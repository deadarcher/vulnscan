#Requires -Version 5.1
<#
    Get-RffVulnScan.ps1 - what on this Windows machine has a known CVE?

    Reads the installed-software list and the OS patch level, matches them against a published
    vulnerability index, and tells you what is vulnerable. Nothing about your machine is uploaded:
    the index comes DOWN to you and the matching happens locally.

    TWO MODES, picked automatically:
      ONLINE  - can reach the index -> downloads it, matches here, writes an HTML report.
      OFFLINE - cannot (locked-down server, no outbound internet) -> writes a small JSON snapshot
                you carry to https://getrff.com/vulnscan/ and drop in the browser. That page does
                the same matching client-side. This mode exists because the machines where
                vulnerability scanning matters most are usually the ones with no internet.

    Windows PowerShell 5.1 compatible and PURE ASCII on purpose - an em dash or a curly quote makes
    5.1 fail parsing SILENTLY, so the script "runs" and does nothing.

    Read it before you run it. That is the point of shipping a script rather than a binary.

    Usage:
      .\Get-RffVulnScan.ps1                    # auto: online if it can reach the index
      .\Get-RffVulnScan.ps1 -Offline           # force the snapshot-only path
      .\Get-RffVulnScan.ps1 -OutFile C:\x.json # where the snapshot / report goes
      .\Get-RffVulnScan.ps1 -IndexFile C:\cve-index.json   # fully offline, still writes the report
#>
[CmdletBinding()]
param(
    [string] $IndexUrl = 'https://getrff.com/vulnscan/cve-index.json.gz',
    # Use an index already on disk instead of fetching one. This is what makes a fully air-gapped
    # run possible: copy the script and the index onto a machine with no internet and still get the
    # complete HTML report, rather than a snapshot you have to carry somewhere else to read.
    [string] $IndexFile,
    [string] $OutFile,
    [switch] $Offline,
    # Also read OTHER users' installed software. Needs elevation, so it is opt-in: requiring admin
    # for a download-and-run tool costs more than the coverage buys. Unelevated runs report which
    # hives they could not read rather than quietly reporting only yours.
    [switch] $AllUsers,
    [switch] $NoReport
)

$ErrorActionPreference = 'Stop'
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

function Write-Step($msg) { Write-Host $msg -ForegroundColor Cyan }

# ---------------------------------------------------------------------------------------------
# 1. Collect. Registry only - deliberately NOT Win32_Product, which reconfigures every MSI it
#    touches and can take minutes. Three hives: 64-bit, 32-bit-on-64, and per-user.
# ---------------------------------------------------------------------------------------------
function Get-InstalledSoftware {
    $paths = @(
        'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*',
        'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*',
        # 32-bit per-user installs land here and were missed entirely. Zero rows on many machines,
        # which is why it went unnoticed - an empty result reads the same as a path never queried.
        'HKCU:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*'
    )
    $seen = @{}
    foreach ($p in (Get-ItemProperty $paths -ErrorAction SilentlyContinue)) {
        $name = $p.DisplayName
        if ([string]::IsNullOrWhiteSpace($name)) { continue }
        # Updates and hotfix entries are not products; they inflate the list and match nothing.
        if ($p.SystemComponent -eq 1) { continue }
        if ($name -match '^(Update for|Security Update for|Hotfix for|KB\d{6,})') { continue }
        $ver = $p.DisplayVersion
        if ([string]::IsNullOrWhiteSpace($ver)) { continue }
        $key = "$name|$ver"
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true

        # EVIDENCE. The exact key this came from, so a finding can be independently verified rather
        # than believed. This is the difference between "we determined X" and "here is the artifact".
        # It matters because DisplayVersion often is not the product version - "Python 3.10.6
        # (64-bit)" reports 3.10.6150.0, where 6150 is an installer build number.
        $regPath = [string]$p.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
        $regPath = $regPath -replace '^HKEY_LOCAL_MACHINE', 'HKLM' -replace '^HKEY_CURRENT_USER', 'HKCU'
        # HKCU is per-user: it is only visible to the account running this, so a finding sourced from
        # there is scoped to that user and its absence proves nothing about other accounts.
        $scope = if ($regPath -like 'HKCU*') { 'user' } else { 'machine' }

        [pscustomobject]@{
            name      = [string]$name
            version   = [string]$ver
            publisher = [string]$p.Publisher
            evidence  = [pscustomobject]@{
                registryPath   = $regPath
                displayName    = [string]$name
                displayVersion = [string]$ver
                scope          = $scope
                readAt         = (Get-Date).ToUniversalTime().ToString('o')
            }
        }
    }
}

# What the scan could NOT see, reported alongside the findings. A count of what we looked at is
# only meaningful next to a count of what we skipped.
$script:Coverage = [ordered]@{
    MsixCollected      = 0
    UserHivesRead      = 0
    UserHivesSkipped   = 0
    SkippedUsers       = @()
}

function Get-MsixPackagesLocal {
    # MSIX/Store apps live nowhere in the registry uninstall keys, so a registry-only scan reports
    # them as not installed. On a normal desktop that is dozens of applications.
    # Framework and non-removable packages are runtime plumbing every machine has - excluded, or
    # they swamp the list without telling anybody anything.
    $out = @()
    try {
        $pkgs = if ($AllUsers) { Get-AppxPackage -AllUsers -ErrorAction SilentlyContinue }
                else           { Get-AppxPackage -ErrorAction SilentlyContinue }
        $seen = @{}
        foreach ($p in $pkgs) {
            if ($p.IsFramework -or $p.NonRemovable) { continue }
            if ([string]::IsNullOrWhiteSpace($p.Name) -or [string]::IsNullOrWhiteSpace($p.Version)) { continue }
            $key = "$($p.Name)|$($p.Version)"
            if ($seen.ContainsKey($key)) { continue }   # -AllUsers returns one row per user
            $seen[$key] = $true
            # "CN=Foo, O=..., C=US" -> "Foo", so it reads like a registry Publisher.
            $pub = $p.Publisher
            if ($pub -and $pub -match 'CN=([^,]+)') { $pub = $Matches[1].Trim() }
            $out += [pscustomobject]@{
                name      = [string]$p.Name
                version   = [string]$p.Version
                publisher = [string]$pub
                source    = 'msix'
                evidence  = [pscustomobject]@{
                    registryPath   = 'AppX package manifest (not a registry key)'
                    displayName    = [string]$p.Name
                    displayVersion = [string]$p.Version
                    scope          = 'machine'
                    readAt         = (Get-Date).ToUniversalTime().ToString('o')
                }
            }
        }
    } catch { }
    $script:Coverage.MsixCollected = $out.Count
    return $out
}

function Get-OtherUserSoftware {
    # Every OTHER loaded user hive. Only reachable elevated; unelevated we count what we could not
    # open so the report can say so instead of implying the machine has one user.
    $out = @()
    try {
        $me = ([Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
        $sids = @(Get-ChildItem Registry::HKEY_USERS -ErrorAction SilentlyContinue |
                  Where-Object { $_.PSChildName -match '^S-1-5-21-' -and $_.PSChildName -notlike '*_Classes' } |
                  ForEach-Object { $_.PSChildName } | Where-Object { $_ -ne $me })
        foreach ($sid in $sids) {
            $got = $false
            foreach ($rel in @('SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall',
                               'SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall')) {
                $path = "Registry::HKEY_USERS\$sid\$rel\*"
                try {
                    foreach ($p in (Get-ItemProperty $path -ErrorAction Stop)) {
                        if ([string]::IsNullOrWhiteSpace($p.DisplayName)) { continue }
                        if ($p.SystemComponent -eq 1) { continue }
                        if ([string]::IsNullOrWhiteSpace($p.DisplayVersion)) { continue }
                        $got = $true
                        $regPath = [string]$p.PSPath -replace '^Microsoft\.PowerShell\.Core\\Registry::', ''
                        $out += [pscustomobject]@{
                            name      = [string]$p.DisplayName
                            version   = [string]$p.DisplayVersion
                            publisher = [string]$p.Publisher
                            evidence  = [pscustomobject]@{
                                registryPath   = $regPath
                                displayName    = [string]$p.DisplayName
                                displayVersion = [string]$p.DisplayVersion
                                scope          = 'user'
                                readAt         = (Get-Date).ToUniversalTime().ToString('o')
                            }
                        }
                    }
                } catch { }
            }
            if ($got) { $script:Coverage.UserHivesRead++ }
            else {
                $script:Coverage.UserHivesSkipped++
                $script:Coverage.SkippedUsers += $sid
            }
        }
    } catch { }
    return $out
}

function Get-OsFacts {
    $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    # UBR is the Update Build Revision - the authoritative patch level. Get-HotFix is NOT: it took
    # 2.2 seconds and returned 4 rows on a fully patched Windows 11 26200 box, because modern
    # cumulative updates do not reliably register there. One registry read beats it on both
    # correctness and speed.
    [pscustomobject]@{
        caption     = [string]$cv.ProductName
        displayVer  = [string]$cv.DisplayVersion
        build       = [int]$cv.CurrentBuildNumber
        ubr         = [int]$cv.UBR
        fullBuild   = "10.0.$($cv.CurrentBuildNumber).$($cv.UBR)"
        machineName = $env:COMPUTERNAME
    }
}

$swatch = [Diagnostics.Stopwatch]::StartNew()
Write-Step 'Reading installed software...'
$apps = @(Get-InstalledSoftware)
Write-Step 'Reading packaged (Store/MSIX) apps...'
$apps += @(Get-MsixPackagesLocal)
if ($AllUsers) {
    Write-Step 'Reading other users installed software...'
    $apps += @(Get-OtherUserSoftware)
}
Write-Step 'Reading OS patch level...'
$os = Get-OsFacts
$collectMs = $swatch.ElapsedMilliseconds

$snapshot = [pscustomobject]@{
    schema      = 'rff-vulnscan/1'
    generatedAt = (Get-Date).ToUniversalTime().ToString('o')
    machine     = $os
    software    = $apps
    # What was NOT looked at. A count of what we checked is only meaningful beside this.
    coverage    = [pscustomobject]@{
        msixCollected    = $script:Coverage.MsixCollected
        userHivesRead    = $script:Coverage.UserHivesRead
        userHivesSkipped = $script:Coverage.UserHivesSkipped
        allUsers         = [bool]$AllUsers
        elevated         = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
}
Write-Host ("  {0} applications, OS {1} ({2} ms)" -f $apps.Count, $os.fullBuild, $collectMs)
if ($script:Coverage.MsixCollected -gt 0) {
    Write-Host ("  ...including {0} packaged (Store/MSIX) apps" -f $script:Coverage.MsixCollected)
}
# Never let a partial read look like a complete one.
if ($script:Coverage.UserHivesSkipped -gt 0) {
    Write-Host ("  {0} other user profile(s) could NOT be read - re-run elevated with -AllUsers to include them." -f $script:Coverage.UserHivesSkipped) -ForegroundColor Yellow
} elseif (-not $AllUsers) {
    Write-Host "  Only this user's per-user apps were read. -AllUsers (elevated) includes other profiles."
}

# ---------------------------------------------------------------------------------------------
# 2. Try to fetch the index. Failure here is NORMAL, not an error - it is the offline path.
# ---------------------------------------------------------------------------------------------
$index = $null

# A local index wins over the network. Checked FIRST so an air-gapped run never waits on a timeout
# it is guaranteed to lose.
if ($IndexFile) {
    if (-not (Test-Path $IndexFile)) {
        Write-Host "  index file not found: $IndexFile" -ForegroundColor Red
        Write-Host "  Download it once from $IndexUrl and pass the path with -IndexFile."
        return
    }
    Write-Step 'Reading the local vulnerability index...'
    try {
        $index = Get-Content -Path $IndexFile -Raw -Encoding UTF8 | ConvertFrom-Json
        $prodCount = 0
        if ($index -and $index.productsV2) { $prodCount = ($index.productsV2.PSObject.Properties.Name).Count }
        elseif ($index -and $index.products) { $prodCount = ($index.products.PSObject.Properties.Name).Count }
        # Same rule as the network path: a file that parses but carries no products is not an index
        # and reporting zero findings from it would be a false all-clear.
        if ($prodCount -lt 1) {
            Write-Host "  that file parsed but contains no products - it is not a usable index." -ForegroundColor Red
            return
        }
        Write-Host ("  index: {0} products, generated {1}" -f $prodCount, $index.generated)
    } catch {
        Write-Host "  that file is not a usable index ($($_.Exception.Message.Split([Environment]::NewLine)[0]))" -ForegroundColor Red
        return
    }
}

if (-not $index -and -not $Offline) {
    Write-Step 'Fetching the vulnerability index...'
    try {
        $prev = $ProgressPreference; $ProgressPreference = 'SilentlyContinue'   # 5.1 is very slow with the bar
        $resp = Invoke-WebRequest -Uri $IndexUrl -UseBasicParsing -TimeoutSec 60
        $ProgressPreference = $prev
        # $resp.Content is a STRING when the server sends a text content-type, but a byte[] when it
        # does not - which is what a GitHub Release asset (the redirect target) returns. Decode the
        # bytes ourselves so the parse never depends on the server guessing right.
        $raw = $resp.Content
        if ($raw -isnot [byte[]]) { $raw = [Text.Encoding]::UTF8.GetBytes([string]$raw) }
        # Detect gzip by MAGIC BYTES rather than by URL, so this works whether the index is served
        # compressed or plain and needs no change if the hosting moves. The asset host sends no
        # Content-Encoding even when asked, so the browser cannot inflate it for us and the plain
        # file is 21 MB against 1.5 MB compressed.
        if ($raw.Length -gt 2 -and $raw[0] -eq 0x1F -and $raw[1] -eq 0x8B) {
            $inStream  = New-Object System.IO.MemoryStream(,$raw)
            $gzip      = New-Object System.IO.Compression.GzipStream($inStream, [System.IO.Compression.CompressionMode]::Decompress)
            $outStream = New-Object System.IO.MemoryStream
            $gzip.CopyTo($outStream)
            $gzip.Dispose(); $inStream.Dispose()
            $raw = $outStream.ToArray(); $outStream.Dispose()
        }
        $body = [Text.Encoding]::UTF8.GetString($raw)
        $index = $body | ConvertFrom-Json

        # A PARSE THAT SUCCEEDS IS NOT A VALID INDEX. A proxy, SSL-inspection appliance or captive
        # portal can return something that parses to an object with no products - and accepting it
        # reports ZERO CVEs, which reads as "your machine is clean" when the truth is "we never
        # checked". That is the worst output a vulnerability scanner can produce. Seen on a corporate
        # network 2026-08-31: 'index: 0 products' followed by '0 distinct CVEs'.
        $prodCount = 0
        if ($index -and $index.productsV2) { $prodCount = ($index.productsV2.PSObject.Properties.Name).Count }
        elseif ($index -and $index.products) { $prodCount = ($index.products.PSObject.Properties.Name).Count }
        # Products alone do not make an index usable. Without the alias table nothing can be
        # IDENTIFIED, so every application resolves to nothing and the run reports a confident zero.
        # That shipped undetected for the tool's whole life because this check only looked at
        # products. Treat a missing alias table exactly like an empty index.
        $aliasCount = 0
        if ($index -and $index.aliases) { $aliasCount = ($index.aliases.PSObject.Properties.Name).Count }
        if ($aliasCount -lt 1) { $prodCount = 0 }
        if ($prodCount -lt 1) {
            Write-Host "  the index came back empty or unreadable - NOT a clean result." -ForegroundColor Yellow
            Write-Host "  Something between this machine and the index (a proxy or SSL inspection) likely"
            Write-Host "  altered the response. Falling back to the offline snapshot."
            $index = $null
        } else {
            Write-Host ("  index: {0} products, generated {1}" -f $prodCount, $index.generated)
        }
    } catch {
        Write-Host "  could not reach the index ($($_.Exception.Message.Split([Environment]::NewLine)[0]))" -ForegroundColor Yellow
        Write-Host "  falling back to the offline snapshot path." -ForegroundColor Yellow
        $index = $null
    }
}

# ---------------------------------------------------------------------------------------------
# 3a. OFFLINE - write the snapshot and stop.
# ---------------------------------------------------------------------------------------------
if (-not $index) {
    if (-not $OutFile) {
        $OutFile = Join-Path ([Environment]::GetFolderPath('Desktop')) ("vulnscan-$($os.machineName).json")
    }
    $snapshot | ConvertTo-Json -Depth 6 -Compress | Set-Content -Path $OutFile -Encoding UTF8
    Write-Host ""
    Write-Host "Wrote $OutFile" -ForegroundColor Green
    Write-Host ""
    Write-Host "This machine could not reach the vulnerability index, so nothing was matched yet."
    Write-Host "Two ways to read it:"
    Write-Host "  1. Drop the file at $($IndexUrl -replace '/cve-index\.json(\.gz)?$','/')"
    Write-Host "  2. Run this on a machine WITH internet, or fetch the index once and use:"
    Write-Host "       .\Get-RffVulnScan.ps1 -IndexFile <path-to-cve-index.json>"
    Write-Host "     which does the whole job locally and writes an HTML report - no network needed."
    Write-Host ""
    Write-Host "Nothing was uploaded by this script."
    # Open the folder with the file selected. Telling somebody with no internet to visit a website is
    # a dead end; at minimum, hand them the file.
    if (-not $NoReport -and $env:RFF_NO_OPEN -ne '1') {
        # Concatenated, not an escaped-quote string: this file is embedded in a TS template
        # literal, so a backtick anywhere in it breaks the page build.
        try { Start-Process explorer.exe -ArgumentList ('/select,"' + $OutFile + '"') } catch { }
    }
    return
}

# ---------------------------------------------------------------------------------------------
# 3b. ONLINE - match locally.
# ---------------------------------------------------------------------------------------------

# Compare two version strings numerically, segment by segment. Non-numeric segments compare as 0,
# which is the honest behaviour for things like "8.1-dev": we would rather under-report than invent
# a match on a version we cannot parse.
# THE single definition of "is this installed version inside this range". Both the v2 and v1 paths
# call it, and it mirrors the browser's compareVersions logic exactly. Two copies of this test is how
# the collector and the page came to disagree by 3x, so there is deliberately only one.
function Test-VersionInRange([string]$installed, $vs, $si, $ve, $ei) {
    # No bound at all names the product with no version constraint, which would flag the application
    # whatever version is installed - a fully patched machine would get the same list as one years
    # behind. Skipped rather than guessed.
    if (-not $vs -and -not $ve) { return $false }
    if ($vs) {
        $c = Compare-Version $installed $vs
        if ($c -eq $null) { return $false }
        if ($si -eq 1) { if ($c -lt 0) { return $false } } else { if ($c -le 0) { return $false } }
    }
    if ($ve) {
        $c = Compare-Version $installed $ve
        if ($c -eq $null) { return $false }
        if ($ei -eq 1) { if ($c -gt 0) { return $false } } else { if ($c -ge 0) { return $false } }
    }
    return $true
}

function Compare-Version([string]$a, [string]$b) {
    if ([string]::IsNullOrWhiteSpace($a) -or [string]::IsNullOrWhiteSpace($b)) { return $null }
    $ax = @(); foreach ($sg in ($a -split '[._\-+]')) { $n = 0; [void][int]::TryParse($sg, [ref]$n); $ax += $n }
    $bx = @(); foreach ($sg in ($b -split '[._\-+]')) { $n = 0; [void][int]::TryParse($sg, [ref]$n); $bx += $n }
    $len = [Math]::Max($ax.Count, $bx.Count)
    for ($i = 0; $i -lt $len; $i++) {
        $av = if ($i -lt $ax.Count) { $ax[$i] } else { 0 }
        $bv = if ($i -lt $bx.Count) { $bx[$i] } else { 0 }
        if ($av -ne $bv) { return $(if ($av -gt $bv) { 1 } else { -1 }) }
    }
    return 0
}

# Identity: bind an installed app to a CPE product. The index ships the alias table so this stays
# in ONE place - a wrong binding here turns a real finding into a silent false negative, which is
# the failure mode that matters for a security tool.
#
# WORD-SUBSET, not substring. Every word of the needle must appear in the name, in any order.
# Substring matching looks equivalent and is not: it requires the words to be CONTIGUOUS, and real
# display names put the version in the middle ("ImageMagick 7.1.2-21 Q16-HDRI (64-bit)"). That
# silently lost 70 real findings before this was fixed.
function Split-Words([string]$s) {
    return @(($s.ToLowerInvariant() -split '[^a-z0-9+]+') | Where-Object { $_ })
}
# Flatten the alias table ONCE into (key, needle-words), sorted longest needle first.
#
# The previous version called Split-Words on every needle for every application: 186 apps x 878
# needles is 163,000 regex splits, each running a Where-Object pipeline, which is one of the slowest
# things you can do repeatedly in PowerShell 5.1. The needles never change, so this is pure waste.
#
# Sorting longest-first also lets the search STOP at its first full match. Matching is most-words-
# wins, so once the list is descending by word count the first needle that matches is by definition
# the best one, and everything after it is shorter.
function Build-AliasTable($aliases) {
    $table = New-Object System.Collections.ArrayList
    $ordinal = 0
    foreach ($prop in $aliases.PSObject.Properties) {
        foreach ($needle in $prop.Value) {
            $parts = Split-Words ([string]$needle)
            if ($parts.Count -gt 0) {
                [void]$table.Add([pscustomobject]@{
                    Key = $prop.Name; Parts = $parts; Count = $parts.Count; Ordinal = $ordinal
                })
                $ordinal++
            }
        }
    }
    # STABLE sort: longest needle first, and original order within equal lengths. Sort-Object is not
    # stable on its own, and that matters - the original code accepted a needle only when it was
    # strictly longer than the best so far, so among equally long matches the FIRST one in table
    # order won. Sorting by count alone reshuffled those ties and changed one binding on a real
    # machine (484 findings became 483). A speed change that quietly alters results is a bad trade,
    # so the ordinal pins the tie-break to exactly what it was.
    return @($table | Sort-Object -Property @{Expression='Count';Descending=$true}, @{Expression='Ordinal';Descending=$false})
}

function Resolve-ProductKey($words, $aliasTable) {
    foreach ($entry in $aliasTable) {
        $all = $true
        foreach ($p in $entry.Parts) { if (-not $words.Contains($p)) { $all = $false; break } }
        # First match wins: the table is sorted longest-needle-first, so nothing later can beat it.
        if ($all) { return $entry.Key }
    }
    return $null
}

Write-Step 'Matching...'
$mwatch = [Diagnostics.Stopwatch]::StartNew()
$findings = New-Object Collections.ArrayList
$aliases = $index.aliases
$aliasTable = Build-AliasTable $aliases
$excludeNames = @()
if ($index.excludeNames) { $excludeNames = @($index.excludeNames) }
$incomparable = $null
if ($index.incomparable) { $incomparable = $index.incomparable }
$versionFromName = $null
if ($index.versionFromName) { $versionFromName = $index.versionFromName }
$notCompared = New-Object System.Collections.ArrayList
foreach ($app in $apps) {
    $appWords = New-Object 'System.Collections.Generic.HashSet[string]'
    foreach ($w in (Split-Words $app.name)) { [void]$appWords.Add($w) }
    # Components of a product are not the product. An add-in, a virtual printer or a launcher
    # carries its OWN version, so comparing it against the parent product's CVE ranges is
    # meaningless in both directions - it invents findings on a patched machine and hides them on an
    # unpatched one. The index ships the list because word-subset matching cannot express "not
    # this". Measured: the Teams Meeting Add-in collected 10 Teams CVEs off its own version number.
    $skip = $false
    foreach ($ex in $excludeNames) {
        $all = $true
        foreach ($p in (Split-Words $ex)) { if (-not $appWords.Contains($p)) { $all = $false; break } }
        if ($all) { $skip = $true; break }
    }
    if ($skip) { continue }
    $key = Resolve-ProductKey $appWords $aliasTable
    if (-not $key) { continue }
    # Where the registry version is in a different scheme from the index, derive a comparable one
    # from the DISPLAY NAME. Oracle ships Java 8 as "Java 8 Update 481" with registry version
    # 8.0.4810.10, while NVD states it as 1.8.0 + update481. The name carries the update number
    # plainly, so it is read from there instead of decoding 4810, which would be guesswork.
    $version = $app.version
    if ($versionFromName -and $versionFromName.PSObject.Properties.Name -contains $key) {
        foreach ($rule in @($versionFromName.$key)) {
            $rm = [regex]::Match($app.name, $rule.pattern, [Text.RegularExpressions.RegexOptions]::IgnoreCase)
            if ($rm.Success) {
                $rv = $rule.template
                for ($gi = 1; $gi -lt $rm.Groups.Count; $gi++) {
                    $rv = $rv.Replace(('$' + $gi), $rm.Groups[$gi].Value)
                }
                $version = $rv
                break
            }
        }
    }

    # Known scheme mismatch and no rule fired: the comparison would SUCCEED and return the wrong
    # answer, so refuse and say so. Java 8u481 used to report CLEAN this way.
    if ($incomparable -and $incomparable.PSObject.Properties.Name -contains $key -and $version -eq $app.version) {
        [void]$notCompared.Add([pscustomobject]@{
            software = $app.name; version = $app.version; product = $key
            reason = $incomparable.$key
        })
        continue
    }
    $groups = $null
    if ($index.productsV2) { $groups = $index.productsV2.$key }
    if ($groups) {
        # v2: CVEs are grouped by version bound, so each DISTINCT bound is compared ONCE and the
        # whole CVE list is attributed to it. The bounds repeat enormously - 249 Firefox CVEs all
        # share "< 152.0.0" - so comparing per CVE repeated the same arithmetic thousands of times.
        foreach ($g in $groups) {
            if (-not (Test-VersionInRange $version $g[0] $g[1] $g[2] $g[3])) { continue }
            foreach ($c in $g[4]) {
                [void]$findings.Add([pscustomobject]@{
                    cve = $c[0]; severity = $c[1]; kev = $c[2]
                    software = $app.name; version = $app.version; product = $key
                })
            }
        }
    } else {
        # v1: one row per CVE. Kept so a saved -IndexFile from before the format change still works.
        $rows = $index.products.$key
        if (-not $rows) { continue }
        foreach ($r in $rows) {
            if (-not (Test-VersionInRange $version $r[3] $r[4] $r[5] $r[6])) { continue }
            [void]$findings.Add([pscustomobject]@{
                cve = $r[0]; severity = $r[1]; kev = $r[2]
                software = $app.name; version = $app.version; product = $key
            })
        }
    }
}
$matchMs = $mwatch.ElapsedMilliseconds

$unique = $findings | Group-Object cve | ForEach-Object { $_.Group[0] }
$sevName = @{ 4 = 'Critical'; 3 = 'High'; 2 = 'Medium'; 1 = 'Low'; 0 = 'Unrated' }
$crit = @($unique | Where-Object { $_.severity -eq 4 }).Count
$high = @($unique | Where-Object { $_.severity -eq 3 }).Count
$kev  = @($unique | Where-Object { $_.kev -eq 1 }).Count

Write-Host ""
$appCount = @($findings | Group-Object software).Count
Write-Host ("{0} distinct CVEs across {1} applications  ({2} ms to match)" -f @($unique).Count, $appCount, $matchMs) -ForegroundColor Yellow
if ($notCompared.Count -gt 0) {
    # Printed with the headline, not buried below it: these applications were RECOGNISED, so without
    # this line they would sit silently inside the "checked" count with nothing actually compared.
    Write-Host ("  {0} application(s) could NOT be checked - the installed version and the published" -f $notCompared.Count) -ForegroundColor Yellow
    Write-Host "  CVE versions use different numbering schemes. This is NOT a clean result for them:" -ForegroundColor Yellow
    foreach ($nc in $notCompared) { Write-Host ("    {0} ({1})" -f $nc.software, $nc.version) -ForegroundColor Yellow }
}
Write-Host ("  {0} critical, {1} high, {2} on CISA KEV" -f $crit, $high, $kev)
Write-Host ("  OS {0} - patch level checked separately, see the report" -f $os.fullBuild)

if ($NoReport) { return }

if (-not $OutFile) {
    $OutFile = Join-Path ([Environment]::GetFolderPath('Desktop')) ("vulnscan-$($os.machineName).html")
}
$rowsHtml = ($unique | Sort-Object @{e={$_.severity};Descending=$true}, cve | ForEach-Object {
    $s = $sevName[[int]$_.severity]
    $k = if ($_.kev -eq 1) { ' <span class="kev">KEV</span>' } else { '' }
    "<tr><td>$($_.cve)$k</td><td class='s$($_.severity)'>$s</td><td>$([Net.WebUtility]::HtmlEncode($_.software))</td><td>$([Net.WebUtility]::HtmlEncode($_.version))</td></tr>"
}) -join ([Environment]::NewLine)

$html = @"
<!doctype html><html><head><meta charset="utf-8"><title>Vulnerability scan - $($os.machineName)</title>
<style>
body{font:14px/1.5 system-ui,Segoe UI,sans-serif;margin:2rem auto;max-width:1000px;color:#1a1a2e}
h1{font-size:20px;margin:0 0 4px} .sub{color:#666;margin:0 0 20px}
table{border-collapse:collapse;width:100%} th,td{text-align:left;padding:6px 10px;border-bottom:1px solid #eee}
th{color:#666;font-weight:600;font-size:12px;text-transform:uppercase}
.s4{color:#b00020;font-weight:600}.s3{color:#d35400;font-weight:600}.s2{color:#8a6d3b}.s1,.s0{color:#888}
.kev{background:#b00020;color:#fff;font-size:10px;padding:1px 5px;border-radius:3px;margin-left:6px}
.box{background:#f7f7fb;border:1px solid #e3e3ee;border-radius:8px;padding:12px 16px;margin-bottom:20px}
</style></head><body>
<h1>$($os.machineName)</h1>
<p class="sub">$($os.caption) $($os.displayVer) - build $($os.fullBuild) - scanned $((Get-Date).ToString('u'))</p>
<div class="box">
<strong>$(@($unique).Count) distinct CVEs</strong> across $(@($findings | Group-Object software).Count) applications.
$crit critical, $high high, $kev on the CISA Known Exploited list.<br>
<small>Matched locally against an index of $((($index.products.PSObject.Properties.Name)).Count) products. Nothing about this machine was uploaded.</small>
</div>
<table><thead><tr><th>CVE</th><th>Severity</th><th>Software</th><th>Installed version</th></tr></thead>
<tbody>
$rowsHtml
</tbody></table>
<p class="sub" style="margin-top:24px">Findings only. This tool does not change anything on the machine.</p>
</body></html>
"@
Set-Content -Path $OutFile -Value $html -Encoding UTF8
Write-Host ""
Write-Host "Report: $OutFile" -ForegroundColor Green
if (-not $NoReport -and $env:RFF_NO_OPEN -ne '1') { Start-Process $OutFile }

# SIG # Begin signature block
# MIIs4AYJKoZIhvcNAQcCoIIs0TCCLM0CAQExDzANBglghkgBZQMEAgEFADB5Bgor
# BgEEAYI3AgEEoGswaTA0BgorBgEEAYI3AgEeMCYCAwEAAAQQH8w7YFlLCE63JNLG
# KX7zUQIBAAIBAAIBAAIBAAIBADAxMA0GCWCGSAFlAwQCAQUABCD0BMzyk8sVvTfg
# OiqaHex+uKyH3nx9widpwAvWgOd616CCJfQwggVvMIIEV6ADAgECAhBI/JO0YFWU
# jTanyYqJ1pQWMA0GCSqGSIb3DQEBDAUAMHsxCzAJBgNVBAYTAkdCMRswGQYDVQQI
# DBJHcmVhdGVyIE1hbmNoZXN0ZXIxEDAOBgNVBAcMB1NhbGZvcmQxGjAYBgNVBAoM
# EUNvbW9kbyBDQSBMaW1pdGVkMSEwHwYDVQQDDBhBQUEgQ2VydGlmaWNhdGUgU2Vy
# dmljZXMwHhcNMjEwNTI1MDAwMDAwWhcNMjgxMjMxMjM1OTU5WjBWMQswCQYDVQQG
# EwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVkMS0wKwYDVQQDEyRTZWN0aWdv
# IFB1YmxpYyBDb2RlIFNpZ25pbmcgUm9vdCBSNDYwggIiMA0GCSqGSIb3DQEBAQUA
# A4ICDwAwggIKAoICAQCN55QSIgQkdC7/FiMCkoq2rjaFrEfUI5ErPtx94jGgUW+s
# hJHjUoq14pbe0IdjJImK/+8Skzt9u7aKvb0Ffyeba2XTpQxpsbxJOZrxbW6q5KCD
# J9qaDStQ6Utbs7hkNqR+Sj2pcaths3OzPAsM79szV+W+NDfjlxtd/R8SPYIDdub7
# P2bSlDFp+m2zNKzBenjcklDyZMeqLQSrw2rq4C+np9xu1+j/2iGrQL+57g2extme
# me/G3h+pDHazJyCh1rr9gOcB0u/rgimVcI3/uxXP/tEPNqIuTzKQdEZrRzUTdwUz
# T2MuuC3hv2WnBGsY2HH6zAjybYmZELGt2z4s5KoYsMYHAXVn3m3pY2MeNn9pib6q
# RT5uWl+PoVvLnTCGMOgDs0DGDQ84zWeoU4j6uDBl+m/H5x2xg3RpPqzEaDux5mcz
# mrYI4IAFSEDu9oJkRqj1c7AGlfJsZZ+/VVscnFcax3hGfHCqlBuCF6yH6bbJDoEc
# QNYWFyn8XJwYK+pF9e+91WdPKF4F7pBMeufG9ND8+s0+MkYTIDaKBOq3qgdGnA2T
# OglmmVhcKaO5DKYwODzQRjY1fJy67sPV+Qp2+n4FG0DKkjXp1XrRtX8ArqmQqsV/
# AZwQsRb8zG4Y3G9i/qZQp7h7uJ0VP/4gDHXIIloTlRmQAOka1cKG8eOO7F/05QID
# AQABo4IBEjCCAQ4wHwYDVR0jBBgwFoAUoBEKIz6W8Qfs4q8p74Klf9AwpLQwHQYD
# VR0OBBYEFDLrkpr/NZZILyhAQnAgNpFcF4XmMA4GA1UdDwEB/wQEAwIBhjAPBgNV
# HRMBAf8EBTADAQH/MBMGA1UdJQQMMAoGCCsGAQUFBwMDMBsGA1UdIAQUMBIwBgYE
# VR0gADAIBgZngQwBBAEwQwYDVR0fBDwwOjA4oDagNIYyaHR0cDovL2NybC5jb21v
# ZG9jYS5jb20vQUFBQ2VydGlmaWNhdGVTZXJ2aWNlcy5jcmwwNAYIKwYBBQUHAQEE
# KDAmMCQGCCsGAQUFBzABhhhodHRwOi8vb2NzcC5jb21vZG9jYS5jb20wDQYJKoZI
# hvcNAQEMBQADggEBABK/oe+LdJqYRLhpRrWrJAoMpIpnuDqBv0WKfVIHqI0fTiGF
# OaNrXi0ghr8QuK55O1PNtPvYRL4G2VxjZ9RAFodEhnIq1jIV9RKDwvnhXRFAZ/ZC
# J3LFI+ICOBpMIOLbAffNRk8monxmwFE2tokCVMf8WPtsAO7+mKYulaEMUykfb9gZ
# pk+e96wJ6l2CxouvgKe9gUhShDHaMuwV5KZMPWw5c9QLhTkg4IUaaOGnSDip0TYl
# d8GNGRbFiExmfS9jzpjoad+sPKhdnckcW67Y8y90z7h+9teDnRGWYpquRRPaf9xH
# +9/DUp/mBlXpnYzyOmJRvOwkDynUWICE5EV7WtgwggYaMIIEAqADAgECAhBiHW0M
# UgGeO5B5FSCJIRwKMA0GCSqGSIb3DQEBDAUAMFYxCzAJBgNVBAYTAkdCMRgwFgYD
# VQQKEw9TZWN0aWdvIExpbWl0ZWQxLTArBgNVBAMTJFNlY3RpZ28gUHVibGljIENv
# ZGUgU2lnbmluZyBSb290IFI0NjAeFw0yMTAzMjIwMDAwMDBaFw0zNjAzMjEyMzU5
# NTlaMFQxCzAJBgNVBAYTAkdCMRgwFgYDVQQKEw9TZWN0aWdvIExpbWl0ZWQxKzAp
# BgNVBAMTIlNlY3RpZ28gUHVibGljIENvZGUgU2lnbmluZyBDQSBSMzYwggGiMA0G
# CSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQCbK51T+jU/jmAGQ2rAz/V/9shTUxjI
# ztNsfvxYB5UXeWUzCxEeAEZGbEN4QMgCsJLZUKhWThj/yPqy0iSZhXkZ6Pg2A2NV
# DgFigOMYzB2OKhdqfWGVoYW3haT29PSTahYkwmMv0b/83nbeECbiMXhSOtbam+/3
# 6F09fy1tsB8je/RV0mIk8XL/tfCK6cPuYHE215wzrK0h1SWHTxPbPuYkRdkP05Zw
# mRmTnAO5/arnY83jeNzhP06ShdnRqtZlV59+8yv+KIhE5ILMqgOZYAENHNX9SJDm
# +qxp4VqpB3MV/h53yl41aHU5pledi9lCBbH9JeIkNFICiVHNkRmq4TpxtwfvjsUe
# dyz8rNyfQJy/aOs5b4s+ac7IH60B+Ja7TVM+EKv1WuTGwcLmoU3FpOFMbmPj8pz4
# 4MPZ1f9+YEQIQty/NQd/2yGgW+ufflcZ/ZE9o1M7a5Jnqf2i2/uMSWymR8r2oQBM
# dlyh2n5HirY4jKnFH/9gRvd+QOfdRrJZb1sCAwEAAaOCAWQwggFgMB8GA1UdIwQY
# MBaAFDLrkpr/NZZILyhAQnAgNpFcF4XmMB0GA1UdDgQWBBQPKssghyi47G9IritU
# pimqF6TNDDAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBADATBgNV
# HSUEDDAKBggrBgEFBQcDAzAbBgNVHSAEFDASMAYGBFUdIAAwCAYGZ4EMAQQBMEsG
# A1UdHwREMEIwQKA+oDyGOmh0dHA6Ly9jcmwuc2VjdGlnby5jb20vU2VjdGlnb1B1
# YmxpY0NvZGVTaWduaW5nUm9vdFI0Ni5jcmwwewYIKwYBBQUHAQEEbzBtMEYGCCsG
# AQUFBzAChjpodHRwOi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNDb2Rl
# U2lnbmluZ1Jvb3RSNDYucDdjMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0
# aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAgEABv+C4XdjNm57oRUgmxP/BP6YdURh
# w1aVcdGRP4Wh60BAscjW4HL9hcpkOTz5jUug2oeunbYAowbFC2AKK+cMcXIBD0Zd
# OaWTsyNyBBsMLHqafvIhrCymlaS98+QpoBCyKppP0OcxYEdU0hpsaqBBIZOtBajj
# cw5+w/KeFvPYfLF/ldYpmlG+vd0xqlqd099iChnyIMvY5HexjO2AmtsbpVn0OhNc
# WbWDRF/3sBp6fWXhz7DcML4iTAWS+MVXeNLj1lJziVKEoroGs9Mlizg0bUMbOalO
# hOfCipnx8CaLZeVme5yELg09Jlo8BMe80jO37PU8ejfkP9/uPak7VLwELKxAMcJs
# zkyeiaerlphwoKx1uHRzNyE6bxuSKcutisqmKL5OTunAvtONEoteSiabkPVSZ2z7
# 6mKnzAfZxCl/3dq3dUNw4rg3sTCggkHSRqTqlLMS7gjrhTqBmzu1L90Y1KWN/Y5J
# KdGvspbOrTfOXyXvmPL6E52z1NZJ6ctuMFBQZH3pwWvqURR8AgQdULUvrxjUYbHH
# j95Ejza63zdrEcxWLDX6xWls/GDnVNueKjWUH3fTv1Y8Wdho698YADR7TNx8X8z2
# Bev6SivBBOHY+uqiirZtg0y9ShQoPzmCcn63Syatatvx157YK9hlcPmVoa1oDE5/
# L9Uo2bC5a4CH2RwwggZIMIIEsKADAgECAhEA5SHpfAJbIErG15QH7BB+KDANBgkq
# hkiG9w0BAQwFADBUMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1p
# dGVkMSswKQYDVQQDEyJTZWN0aWdvIFB1YmxpYyBDb2RlIFNpZ25pbmcgQ0EgUjM2
# MB4XDTI2MDUxOTAwMDAwMFoXDTI3MDUxOTIzNTk1OVowXjELMAkGA1UEBhMCVVMx
# EzARBgNVBAgMCkNhbGlmb3JuaWExHDAaBgNVBAoME1ZpdGtvIFNvZnR3YXJlLCBM
# TEMxHDAaBgNVBAMME1ZpdGtvIFNvZnR3YXJlLCBMTEMwggIiMA0GCSqGSIb3DQEB
# AQUAA4ICDwAwggIKAoICAQDWKBYoiUr8LiKKwN5XL3M5Kj76CNnsggqUVMHBtNUu
# qu8g3mGYst5OOsA2zpMeX6nt3JtyMTUVO5uNX7ljTNw6G8AK3/FaWv8nN5MYIQn5
# 8VqrbHM1okfJohJ12JyaHR3Czcq/ukpiLd1AIuA4ACPzNgpS5Ac6r1rlQnbWfqsj
# e3zMRa1T8lpocwEdZkTjve2S7ihqil81ALryz/+A6cXXP2fVMetbVnJmEENmm+E0
# fdZQptp6VTVxGeK/pCI6ozbKH3NaH9fZAcvtD8heCMkLS/tgCl5vsAKoZ9JcbfV6
# Kjzz7H1KVMuqyhRs6+6dkGNKaxmTiasQFIMJH4TkUMdhcyun57LWSQ2xViXrmCe0
# d68C5vzdKbpU42btTw7o4mKEAGkKRQNjnEErORPAcPKekeyn5vKk9EtxdF3f+th3
# Rt1and8Z+1tW7p3U5HvgksJR1StxSem3FeWYYv//REvChMOdgpMqk7bCtbT/2DBl
# 1maX7SgblwQHVyXDfkz41enLAc6jEwc8BLhtQh4Kzs2rV5f3P2PjPmOgc2pVVa4R
# zk6UbF819dYND7i8HYISbXIAvLN8c+kYaxxTTCPCRN/w2VdWeKZVAMv5jNsyUgpP
# Y4t7EyQQ8kcp1mO/3mSdLJFsJvWDnyBjTuEBGGwW8sR2AlzjlvLnmTgB4IiNFRVI
# TwIDAQABo4IBiTCCAYUwHwYDVR0jBBgwFoAUDyrLIIcouOxvSK4rVKYpqhekzQww
# HQYDVR0OBBYEFHn6Qx0kNzcRnUxN9st73DlJY0GUMA4GA1UdDwEB/wQEAwIHgDAM
# BgNVHRMBAf8EAjAAMBMGA1UdJQQMMAoGCCsGAQUFBwMDMEoGA1UdIARDMEEwNQYM
# KwYBBAGyMQECAQMCMCUwIwYIKwYBBQUHAgEWF2h0dHBzOi8vc2VjdGlnby5jb20v
# Q1BTMAgGBmeBDAEEATBJBgNVHR8EQjBAMD6gPKA6hjhodHRwOi8vY3JsLnNlY3Rp
# Z28uY29tL1NlY3RpZ29QdWJsaWNDb2RlU2lnbmluZ0NBUjM2LmNybDB5BggrBgEF
# BQcBAQRtMGswRAYIKwYBBQUHMAKGOGh0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2Vj
# dGlnb1B1YmxpY0NvZGVTaWduaW5nQ0FSMzYuY3J0MCMGCCsGAQUFBzABhhdodHRw
# Oi8vb2NzcC5zZWN0aWdvLmNvbTANBgkqhkiG9w0BAQwFAAOCAYEAUVdCTQkRJxrW
# BRSrtrKvOaGKpq695JnmMjwQbV8VdXOKAsUb1MVIshMxEozaaRVhhA3F4feMx0fk
# ZBjyxE6iMG5j5uwhu1OfL2wr4yQCGe/0X1MD8hliYyMghpkHDNB8HyHCFfO3FJr+
# kJBxx5tObAXvAwuLNdsnNtQWhmTR9zDlPjiv+RV/jqH6J2be0IRJnckt8ryAMZ+x
# 7eSNjjgeBnPFFHGqVN3z6d0Xe9sNdC7upO7i0Zl6x1nGl6QHni5YkxfYUVssekKD
# 3UuWiVVk+6Vo0TuWqrWSMZjjLmgvnRbdrZKZQuZOi44XWrjD6IE7hQZhkNa9g0jg
# sWPJs/3c0r05IDwPpcKeULviHqspYW5Kdoth7GUfkLzYk6qoHg6iUVhPIcpat6KX
# JxTxzzdbepbPjp2b8bVvC1sgz4vf3BhlHNVqC+D1EvxY+ffLozt3hhnYxBRnuuRk
# /bSwfEi2kxDAWX4FZ+Kd8gzU6Aq94dH+j4YvkS7IeRvyE19ML16mMIIGgjCCBGqg
# AwIBAgIQNsKwvXwbOuejs902y8l1aDANBgkqhkiG9w0BAQwFADCBiDELMAkGA1UE
# BhMCVVMxEzARBgNVBAgTCk5ldyBKZXJzZXkxFDASBgNVBAcTC0plcnNleSBDaXR5
# MR4wHAYDVQQKExVUaGUgVVNFUlRSVVNUIE5ldHdvcmsxLjAsBgNVBAMTJVVTRVJU
# cnVzdCBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMjEwMzIyMDAwMDAw
# WhcNMzgwMTE4MjM1OTU5WjBXMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGln
# byBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5n
# IFJvb3QgUjQ2MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAiJ3YuUVn
# nR3d6LkmgZpUVMB8SQWbzFoVD9mUEES0QUCBdxSZqdTkdizICFNeINCSJS+lV1ip
# nW5ihkQyC0cRLWXUJzodqpnMRs46npiJPHrfLBOifjfhpdXJ2aHHsPHggGsCi7uE
# 0awqKggE/LkYw3sqaBia67h/3awoqNvGqiFRJ+OTWYmUCO2GAXsePHi+/JUNAax3
# kpqstbl3vcTdOGhtKShvZIvjwulRH87rbukNyHGWX5tNK/WABKf+Gnoi4cmisS7o
# SimgHUI0Wn/4elNd40BFdSZ1EwpuddZ+Wr7+Dfo0lcHflm/FDDrOJ3rWqauUP8hs
# okDoI7D/yUVI9DAE/WK3Jl3C4LKwIpn1mNzMyptRwsXKrop06m7NUNHdlTDEMovX
# AIDGAvYynPt5lutv8lZeI5w3MOlCybAZDpK3Dy1MKo+6aEtE9vtiTMzz/o2dYfdP
# 0KWZwZIXbYsTIlg1YIetCpi5s14qiXOpRsKqFKqav9R1R5vj3NgevsAsvxsAnI8O
# a5s2oy25qhsoBIGo/zi6GpxFj+mOdh35Xn91y72J4RGOJEoqzEIbW3q0b2iPuWLA
# 911cRxgY5SJYubvjay3nSMbBPPFsyl6mY4/WYucmyS9lo3l7jk27MAe145GWxK4O
# 3m3gEFEIkv7kRmefDR7Oe2T1HxAnICQvr9sCAwEAAaOCARYwggESMB8GA1UdIwQY
# MBaAFFN5v1qqK0rPVIDh2JvAnfKyA2bLMB0GA1UdDgQWBBT2d2rdP/0BE/8WoWyC
# Ai/QCj0UJTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zATBgNVHSUE
# DDAKBggrBgEFBQcDCDARBgNVHSAECjAIMAYGBFUdIAAwUAYDVR0fBEkwRzBFoEOg
# QYY/aHR0cDovL2NybC51c2VydHJ1c3QuY29tL1VTRVJUcnVzdFJTQUNlcnRpZmlj
# YXRpb25BdXRob3JpdHkuY3JsMDUGCCsGAQUFBwEBBCkwJzAlBggrBgEFBQcwAYYZ
# aHR0cDovL29jc3AudXNlcnRydXN0LmNvbTANBgkqhkiG9w0BAQwFAAOCAgEADr5l
# Qe1oRLjlocXUEYfktzsljOt+2sgXke3Y8UPEooU5y39rAARaAdAxUeiX1ktLJ3+l
# gxtoLQhn5cFb3GF2SSZRX8ptQ6IvuD3wz/LNHKpQ5nX8hjsDLRhsyeIiJsms9yAW
# nvdYOdEMq1W61KE9JlBkB20XBee6JaXx4UBErc+YuoSb1SxVf7nkNtUjPfcxuFtr
# QdRMRi/fInV/AobE8Gw/8yBMQKKaHt5eia8ybT8Y/Ffa6HAJyz9gvEOcF1VWXG8O
# MeM7Vy7Bs6mSIkYeYtddU1ux1dQLbEGur18ut97wgGwDiGinCwKPyFO7ApcmVJOt
# lw9FVJxw/mL1TbyBns4zOgkaXFnnfzg4qbSvnrwyj1NiurMp4pmAWjR+Pb/SIduP
# nmFzbSN/G8reZCL4fvGlvPFk4Uab/JVCSmj59+/mB2Gn6G/UYOy8k60mKcmaAZsE
# VkhOFuoj4we8CYyaR9vd9PGZKSinaZIkvVjbH/3nlLb0a7SBIkiRzfPfS9T+Jesy
# lbHa1LtRV9U/7m0q7Ma2CQ/t392ioOssXW7oKLdOmMBl14suVFBmbzrt5V5cQPnw
# td3UOTpS9oCG+ZZheiIvPgkDmA8FzPsnfXW5qHELB43ET7HHFHeRPRYrMBKjkb8/
# IN7Po0d0hQoF4TeMM+zYAJzoKQnVKOLg8pZVPT8wgganMIIEj6ADAgECAhEAkKwI
# ciD9xafEa1zHDfc9BjANBgkqhkiG9w0BAQwFADBXMQswCQYDVQQGEwJHQjEYMBYG
# A1UEChMPU2VjdGlnbyBMaW1pdGVkMS4wLAYDVQQDEyVTZWN0aWdvIFB1YmxpYyBU
# aW1lIFN0YW1waW5nIFJvb3QgUjQ2MB4XDTI2MDMyNTAwMDAwMFoXDTQxMDMyNDIz
# NTk1OVowVTELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGltaXRlZDEs
# MCoGA1UEAxMjU2VjdGlnbyBQdWJsaWMgVGltZSBTdGFtcGluZyBDQSBSNDEwggIi
# MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCu5EqiAa2CHGL5Zi1bmgPM8NUX
# wYZJ+BtQqHps43GLTC+sjVLypsBh+8uv+TLkgtVGD//vSmA0qrzELf9YRCh2MTAA
# /aGaQZKGg0BRCmziR3pbCnvgWjtGXBDUyn3j3K2lZAO8KxgFtlxwOYEAkL+CCqK4
# v9zzTl8ZwzDpPMiDIFa5THk8an1ieF5I09cXNrPQw+1ER1liThaG0z6FrOpqwxZW
# mPRZQBw2E32878UB1bL0Zp91vuWZgsMpNNiPCoBj0/1F+LE8+NRokfqacFI0F2tf
# trRB2W7HQClLR9zjxFbWb5be2rceIfNyHUUfKGIvMI2NzoxSlxXnFqUG887D8W1C
# j8DFok688JKxWvHR/9aQykSbd+9Vutj36ij2sgq/125wTpUZ/AgC0ph50bRs7gFr
# UyaXE9wSsOqMvCCC+sEm7vd/BemSG0TSHNXSmyCba+FCzekeWX03TRIcF3Laqd0R
# w24OH7jpei4zaGhcI7nfdhBA4c8RScxNY6jeHLHHmSMMTk9Wqn7H4dLhUBP5YEwb
# gbN4uv1i9ltTnHli8t1xHV0StX9BFgrnmunTX19kUXY1H5ORJbRZyZDdvm1oZyte
# Dj0SnMozr+YSmdIleDUTXdfoY7b2taz8s2+QbOxLxcahEIYGWzqu6h955tKwcANH
# cZ4gTmAhT3btuOiQsQIDAQABo4IBbjCCAWowHwYDVR0jBBgwFoAU9ndq3T/9ARP/
# FqFsggIv0Ao9FCUwHQYDVR0OBBYEFDp0pQxnxkJQwv21/Me7KTSC9Hq5MA4GA1Ud
# DwEB/wQEAwIBhjASBgNVHRMBAf8ECDAGAQH/AgEAMBMGA1UdJQQMMAoGCCsGAQUF
# BwMIMCMGA1UdIAQcMBowCAYGZ4EMAQQCMA4GDCsGAQQBsjEBAgEDCDBMBgNVHR8E
# RTBDMEGgP6A9hjtodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNU
# aW1lU3RhbXBpbmdSb290UjQ2LmNybDB8BggrBgEFBQcBAQRwMG4wRwYIKwYBBQUH
# MAKGO2h0dHA6Ly9jcnQuc2VjdGlnby5jb20vU2VjdGlnb1B1YmxpY1RpbWVTdGFt
# cGluZ1Jvb3RSNDYucDdjMCMGCCsGAQUFBzABhhdodHRwOi8vb2NzcC5zZWN0aWdv
# LmNvbTANBgkqhkiG9w0BAQwFAAOCAgEAMt5SR2bxngNm+N8oc6Gq76Gx1c235fkX
# 7jw8Ho9MAkJGADerHE7dhsBXttqmzgr/7ZZahZSykGRPhPY1crj028kB8KzO0dKC
# 2qQBAwtfgqMLKkkX/6bYq2uT33eD6ByAp2/XKD0LcmZh0kKecvSBr6ln9ajX6u1d
# nx2fA7xEKy1M3qBhfQSUWLtjs2nFt0ELVLptzTlX9ID0cL+iOPfdboZ3CelT+JXK
# VKR2Sge0d4YiFAtPZkfSo8z1Z1x7y/Z9mwMIlBAnyuWXs4YsNuxdrYIt/QxE31PD
# OJ9DesS4Bc7H9OTORlEV/AvfiF/VepKZpira1MzLYuCw+uoLZn/pkpvd+CvNTS+m
# EHjBJNa6WK1j8qXFu+jIq+sG9QILHiyB6p/xpHrkJu8zkw393+VqF9eKlTY2VjRx
# dycZLrVemZ4Yp3wi33b+W58CllH3HqjmowlZ7SOrgmx8YwYOkgrHsXOQHyBp6O4F
# Rb8In0+FzjT7ElGie9V7CfhL3IlVFZ4zjuKsZtH1iU3fGu4z/JnOGT6sCb0BbTqe
# /uhvpFCQBdH5xPGIA/LrbQUXjU2tWJgHhTIqnN/HvHyOHi5tM4zP3nhgh2rJ6Kqq
# 2xsHBeNYs/R18xQ8DeIg+c90Eoaeh0YlN1KU8AyYol3K9M+qY5ez8syd/7ZlrRno
# VewgH3P1pcswggbiMIIEyqADAgECAhEA507yVbBQT/rbpt/3/IujFTANBgkqhkiG
# 9w0BAQwFADBVMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MSwwKgYDVQQDEyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIENBIFI0MTAe
# Fw0yNjAzMjUwMDAwMDBaFw0zNzA2MjQyMzU5NTlaMHIxCzAJBgNVBAYTAkdCMRcw
# FQYDVQQIEw5HcmVhdGVyIExvbmRvbjEYMBYGA1UEChMPU2VjdGlnbyBMaW1pdGVk
# MTAwLgYDVQQDEydTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIFNpZ25lciBS
# MzcwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCy/8NtS9xQ2UUtBRF3
# 2bj7VK3n4m50Uqjk/zTciSziYV40H1LKah0/oEklYG42E4VCP3DvsBUB6DmpCkDZ
# 0jCnZBPIEevaH15ZJOQwFWP2ZXr5YjlJpb68Nlbs+ElNvKx32/1YHde3qqUSLybj
# ulxPLz6T85+HOIqK7M1Bep8LspyhEP/q6nw5kGxTSrGvufmeH+JF8CnVBcVMFA40
# FlIYh0cDJVFhhfTfdWgLy/vWuLMQoKkf3s/FvByf16r0rtbyHm/iemwxSioJL9zy
# ZDDKUNAbHXl0dhXo2VxUV2NcPXWXuoKsjL+6cfk6Vm2DHnxAlFdFsaBDIF1JOkSn
# C6PeLlBznZn2buF3vIIYJcq6N/zeFRCk4/HXDz7zgRsRRMdUB+rhyk5FoZaBjw0n
# Lq3GZ3fClLUx5es5pUAxzNODMBn7JkFYip2BAGBPER5eV0ROhk6tGTG+fUiMiV+v
# gjg1YnP5FvnYWyEtWeQD/B2hp3vz0RvtdkM0p3igyadzrfpOBq5ppVk/YsuhTQkP
# 99ivneHAGfi5e7lmxJ+meoBPrRLuzMmb81rzzbESjJHMsn5RVtc6Ucs7rcMqQC13
# PUIO7BbGBETV2ufCmV6lPTp3P7XJOvmnUCRTPbVvMTpxP/z+SOHg4/OCBhiqs4FA
# 9+4oQvlkk9w32NGASli9GWrm5wIDAQABo4IBjjCCAYowHwYDVR0jBBgwFoAUOnSl
# DGfGQlDC/bX8x7spNIL0erkwHQYDVR0OBBYEFGEQ6XoSr1HEhdTyz6R0D1DNIK/4
# MA4GA1UdDwEB/wQEAwIGwDAMBgNVHRMBAf8EAjAAMBYGA1UdJQEB/wQMMAoGCCsG
# AQUFBwMIMEoGA1UdIARDMEEwCAYGZ4EMAQQCMDUGDCsGAQQBsjEBAgEDCDAlMCMG
# CCsGAQUFBwIBFhdodHRwczovL3NlY3RpZ28uY29tL0NQUzBKBgNVHR8EQzBBMD+g
# PaA7hjlodHRwOi8vY3JsLnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNUaW1lU3Rh
# bXBpbmdDQVI0MS5jcmwwegYIKwYBBQUHAQEEbjBsMEUGCCsGAQUFBzAChjlodHRw
# Oi8vY3J0LnNlY3RpZ28uY29tL1NlY3RpZ29QdWJsaWNUaW1lU3RhbXBpbmdDQVI0
# MS5jcnQwIwYIKwYBBQUHMAGGF2h0dHA6Ly9vY3NwLnNlY3RpZ28uY29tMA0GCSqG
# SIb3DQEBDAUAA4ICAQAD6j2N0azN+hl6k6bKB5/U6VuSOs93ZBb3Pczy9VtBIKu4
# 947Z5GwL0aFngIxl+GSuLFrJgPruBCRvKJEJsm7kv+LQ1COVCEG9tZ+IRtr4ocUo
# a53lgdFaENlS0N4wgkZkbQEPv+x+1lSjYh+T4JeL9mUznT7Erc6Sp5dWLka5sMP/
# m3GZi6oJPdPcsCKWagH7m2H2xDGIyHJC5PdH9phvi/KmhkktiSVTNNqVeV5bWdX2
# zhRE6UTfz0IcMoCL996lFIydXxOCE4MNDHDM0as4lnTiT/KHMccO6l8c9TnUVgmp
# ci9ar1IABZ2U1XUkYjGGSn9MC3EHDP9V39VuBVvZ33/BEV/EWSRrf07T7jFplKX+
# gQr/UOqPGMlE7ZJ72UaUkNJy7bVl3bcLKzdpjIHzLkf/4MVa1V7w8wqCv5W4gOnR
# GTlud5UMARbRM8BPxR/CXYXoMmIOD8pmTk2axgRL4LG8XtuchISdCHRmtacAmLGq
# 5XSYSVTHTXADlO48iDKh3HM2r98LSF6f0sG12d8V9Jn7C3wDUieOxuKj4MdWrW+h
# iJU2kF87v6eH00HgCFFc2V0+CvfOCMn7juzS41jLaINcBlKWQ/fKb/uDLfWOW73z
# 1I2lFY7Xj8tQ1XYtK5eREjWItM8jpl1cbQOc88btR+0XS2TmboE/141+va2PWzGC
# BkIwggY+AgEBMGkwVDELMAkGA1UEBhMCR0IxGDAWBgNVBAoTD1NlY3RpZ28gTGlt
# aXRlZDErMCkGA1UEAxMiU2VjdGlnbyBQdWJsaWMgQ29kZSBTaWduaW5nIENBIFIz
# NgIRAOUh6XwCWyBKxteUB+wQfigwDQYJYIZIAWUDBAIBBQCggYQwGAYKKwYBBAGC
# NwIBDDEKMAigAoAAoQKAADAZBgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgor
# BgEEAYI3AgELMQ4wDAYKKwYBBAGCNwIBFTAvBgkqhkiG9w0BCQQxIgQgyg3odBpj
# N7uJxLHdfg++VdG7F0unY6AiuO/A3g8E77AwDQYJKoZIhvcNAQEBBQAEggIAU/pG
# zcEFAAlQ8cEhpsntfJ0iM34UIfdi+ymKYV1CtjDnD+79VOeYbXUP/+266Y+LSOqF
# LdUu/sAIp5hSFqhnn2nhIDbE0RKWWjv4jBovp8GEJX0h2WaclkUjb4Kpj4dddNqa
# Zau8TC2mks1+K0U3kWhVgLUGgfbFfCKca/LnuesrHocX4l3cOW/7kMttYG8VxMIv
# moJSp0ydBJ/3ExxprkozW31e4rdDT/SCAJ92ESnLyzPCgktIa1K1d7u/lf7McucS
# Gr1smvnoIesbaHJPMVT0JwNrqaoewVSfWl8L6VCOC5+6u/ndIgS9DwFxZRLegNZP
# 9in1l+k4LOHTaEBOWYjcEdwOWe4OlA39zrBspsipajQbx+zsk6s4OVMcv/0RypPW
# mApq4jGrU6J6Kh6Rb8M4iNvifyU/41Pf8D6uWbNAykDLQoTNwVsmS9j4bgizRaXw
# cWY53nQn7V+FTlXQMU2xLujrJoIoTyegdZhNjDrUNiiMSWM3O4Gqy7ZTpKM8iO0n
# H9nTOCJm7w2L4DT3kq+ZOvzhLPkaaw2JoloOq0S4CbkaSTeFSXRknp8G21WwdXaS
# Rg0/5/q6KVU8ZPQsyWQfNVYJIr3iL/3HDkFAFkZ3d4zo1d2dFZ0bGlHi078yQ/TB
# T645g2iKNYF+TeBETqryK5oo8rMQZ30N2JtC396hggMjMIIDHwYJKoZIhvcNAQkG
# MYIDEDCCAwwCAQEwajBVMQswCQYDVQQGEwJHQjEYMBYGA1UEChMPU2VjdGlnbyBM
# aW1pdGVkMSwwKgYDVQQDEyNTZWN0aWdvIFB1YmxpYyBUaW1lIFN0YW1waW5nIENB
# IFI0MQIRAOdO8lWwUE/626bf9/yLoxUwDQYJYIZIAWUDBAICBQCgeTAYBgkqhkiG
# 9w0BCQMxCwYJKoZIhvcNAQcBMBwGCSqGSIb3DQEJBTEPFw0yNjA5MDEwMDA5MzRa
# MD8GCSqGSIb3DQEJBDEyBDD1AcMrfh4KXQdfA2LdRa2NzGBcRwmlOZRFpjOxliD9
# 7otu8qa66KZncQmUukopBswwDQYJKoZIhvcNAQEBBQAEggIAhDplPXy+jAjWCZ/G
# EHk/4EBRlRuTl35OIt/WNuvywljdU8g4SMlxhchS+LjjSb3OYuSrFcT+xqyv4R8l
# idMHy08mJS56oYwyzTe1h4gosgzdZ2+1ZipM0WkE8qytaP/emHZ44i9ZZBoE2yc3
# Ow6lGPTqdJ/LjZ207RBWNHrEfIbeZZcKCBNsVCiPVjjm2O/qxohFJAX3v+ommnIO
# G68ChS9yDAmNWpwcbSyV8Clmdi1eyXLCfUbt3UyZKXDfXNmTT0nW8dpvhTwEjxbW
# RunjepUZTHs6YU3ksuNMKX+hCgD3yq/9eWzpWXhg4V9xpUbRMJBubr5hRu0tklH+
# LWZduV7l24iwn5h5LmDZR3vg4WqiB+71WIrOA82//FfQr1JzzqXfUbDr13BGsy8G
# 8XTceD7firSDSiLy0TCUei9WlOzzMIBdlFzYAkaKch1wRJosmK8+6OTcO82oeF8E
# kHrrPLWVdLZNhi0YmG2oU8cfe7CIw5iHJR/tL0BjHDUgzmEHIc9GMWpbnMpW2upl
# YwLPTKmTgBH6Rj4rxLfvggQ6c5l7o8WP0+qClRqcqZJyJA2skKL2ul/KRbcmKL5+
# UOLmnNzMHl8x70seIOHVtnpkeCTKvXlxm45O4aRGnzPv9sNrMKIwwkVmjXxSDzpY
# 9byD4HfOL30jIqwkX1uZrlchJW0=
# SIG # End signature block
