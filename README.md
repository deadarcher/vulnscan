# VulnScan

**What on this Windows machine is actually vulnerable, and how do you know?**

Run one PowerShell script, drop the file it writes into your browser, and get every published CVE
affecting the software you have installed and the version of Windows you are running, along with the
registry key each finding was read from.

Runs **entirely in your browser**. The vulnerability index is downloaded to you and the matching
happens on your machine, so your software inventory is never uploaded. A list of every application
and version you run is a genuine disclosure, which is why nothing is sent anywhere. You can verify
that by watching the network tab, or by disconnecting from the network and running it anyway. It
still works.

Live at **https://getrff.com/vulnscan/**

## What it does

- **Applications.** Matches what you have installed against NVD's published version ranges. It reads
  the registry uninstall keys and packaged (MSIX/Store) apps, which most inventory tools miss
  entirely.
- **Windows itself.** Compares your Update Build Revision against the revision Microsoft published
  the fix in, per servicing stream. UBR is the authoritative patch level. `Get-HotFix` is not: it
  returned four rows on a fully patched Windows 11 26200 machine, because modern cumulative updates
  do not reliably register there.
- **Proof, not just a verdict.** Every finding shows the registry key it was read from, the raw
  `DisplayVersion`, the product binary's own file version, and whether the install is machine-wide or
  per-user. You can paste the path into regedit and check it yourself.
- **Says what it did NOT check.** Applications collected but absent from the index, packaged apps
  with no CVE mapping, and user profiles it could not read are each reported separately. "We looked
  and found nothing" and "we never looked" are different facts and the report keeps them apart.

## Why the proof matters

`DisplayVersion` is frequently not the product version, and the version comparison is what decides
whether you are vulnerable. On one ordinary Windows 11 machine, 43 installed applications state a
version in their name and **nine contradict their own DisplayVersion**:

| DisplayName | DisplayVersion |
| --- | --- |
| Microsoft .NET SDK 8.0.130 (x64) | `8.1.3026.37309` |
| NVIDIA Nsight Compute 2026.1.0 | `26.1.0.0` |
| Python 3.10.6 (64-bit) | `3.10.6150.0` |

The .NET one is the dangerous shape. A CVE range of "below 8.0.200 is affected" reads `8.1.3026` as
newer and silently misses it. Without the raw key in front of you there is no way to tell a sound
match from a broken one, which is why every finding carries its source.

## Usage

```powershell
# Scan this machine. Writes an HTML report and opens it.
.\Get-RffVulnScan.ps1

# Collect only, then drop the JSON at https://getrff.com/vulnscan/
.\Get-RffVulnScan.ps1 -Offline

# Fully offline: fetch the index once, then run anywhere with no network at all.
.\Get-RffVulnScan.ps1 -IndexFile .\cve-index.json

# Include other users' per-user installs. Needs elevation, so it is opt-in.
.\Get-RffVulnScan.ps1 -AllUsers
```

It does **not** require administrator rights. The machine-wide uninstall keys are readable by any
user. Elevation only adds other users' per-user installs, and when you run without it the report
says how many profiles it could not read rather than quietly reporting only yours.

## The index

Two public sources, no API keys:

- **Applications** come from NVD's CVE feed, pruned to roughly the top 500 Windows applications by
  published CVE count. The product list is committed at `data/fleet-cpes.json`, so you can see
  exactly what is covered, and open a PR to add something. The pruning is a size decision: the
  full catalogue is far too large to hand a browser, and most of it is server, web and appliance
  software that never appears on a Windows endpoint.
- **Windows** comes from Microsoft's MSRC CVRF feed, keyed by build number. Microsoft publishes no
  first-party Windows OVAL, and OS advisories carry MSRC product ids rather than CPEs, so NVD's
  ranges cannot describe "Windows 11 24H2 x64" in a form you can match a build against.
- **Actively-exploited flags** come from CISA's Known Exploited Vulnerabilities catalog.

Both builders are in `scripts/`. You can rebuild the index yourself and diff it against the published
one. That is the point: the data is reproducible, not just the code readable. `-IndexUrl` also takes
any URL, so you never have to fetch it from us.

## Accuracy notes

The Windows check compares build revisions only. It cannot tell whether an advisory needs a
component, feature or CPU your machine does not have, so it errs toward over-reporting. Checked
against a separate engine over 8,100 findings, that is about 0.2% of them. Updating to the revision
the report names clears every entry either way.

Windows fix revisions are only available from around 2021, because Microsoft did not publish them
before then. A machine further behind than that gets a floor rather than a complete answer, and the
report says so on the machine it affects rather than in a footnote.

Application coverage is bounded by the index: roughly the top 500 Windows applications by published
CVE count. An application that is not in it is reported as collected-but-unchecked, never as clean.
If a product you care about is missing, or a match looks wrong,
[open an issue](https://github.com/deadarcher/vulnscan/issues) or add it to `data/fleet-cpes.json`.

## Why it exists

It is the vulnerability report from [RFF](https://getrff.com), run once on one machine instead of
continuously across a fleet. Same matching rules, same proof, same refusal to call something clean
when it simply was not checked. If you want it running against every machine you manage, with
remediation attached, that is the product.

`vulnScan.ts` is the whole matching engine and is kept identical with the hosted copy.

## Licence

MIT. See [LICENSE](LICENSE).
