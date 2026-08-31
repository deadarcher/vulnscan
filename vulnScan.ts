/**
 * Client-side CVE matching for the VulnScan tool.
 *
 * The index comes DOWN to the browser and the match happens here. Nothing about the machine is
 * uploaded, which is the same promise every other tool on this site makes and the one that matters
 * most for a security tool: "send us a list of every application and version you run" is a genuine
 * disclosure, and plenty of organisations will refuse it outright.
 *
 * The index is pruned to the products that actually appear in Windows fleets, which is what keeps
 * it small enough to ship to a browser at all.
 */

export type IndexRow = [
  cve: string,
  severity: number,      // 4 critical, 3 high, 2 medium, 1 low, 0 unrated
  kev: 0 | 1,
  vStart: string | null,
  startInclusive: 0 | 1,
  vEnd: string | null,
  endInclusive: 0 | 1,
];

export interface CveIndex {
  v: number;
  generated?: string;
  /** "vendor:product" -> rows */
  products: Record<string, IndexRow[]>;
  /** "vendor:product" -> lowercase needles matched against the installed DisplayName */
  aliases: Record<string, string[]>;
}

/** Where an installed application was observed. Present on snapshots from collector v1.1+; older
 *  snapshots simply omit it and the report says so rather than inventing a source. */
export interface AppEvidence {
  registryPath: string;
  displayName: string;
  displayVersion: string;
  /** "machine" (HKLM) or "user" (HKCU). A user-scope reading is only true for the account that
   *  ran the collector, so its ABSENCE proves nothing about other accounts on the box. */
  scope: 'machine' | 'user';
  readAt: string;
}

export interface InstalledApp {
  name: string; version: string; publisher?: string; evidence?: AppEvidence;
  /** "msix" for a packaged Store app; absent for a registry uninstall entry. */
  source?: string;
}

/** What the COLLECTOR could not see, as distinct from what the INDEX could not match. Absent on
 *  snapshots from collectors that predate coverage reporting. */
export interface Coverage {
  msixCollected?: number;
  userHivesRead?: number;
  userHivesSkipped?: number;
  allUsers?: boolean;
  elevated?: boolean;
}
export interface MachineFacts {
  machineName: string; caption?: string; displayVer?: string;
  build?: number; ubr?: number; fullBuild?: string;
}
export interface Snapshot { schema?: string; generatedAt?: string; machine: MachineFacts; software: InstalledApp[] }

export class SnapshotParseError extends Error {}

export function parseSnapshot(text: string): Snapshot {
  let raw: any;
  try { raw = JSON.parse(text); }
  catch { throw new SnapshotParseError('That file is not valid JSON. Re-run the collector and drop the file it writes.'); }
  if (!raw || typeof raw !== 'object') throw new SnapshotParseError('That JSON is not a collector snapshot.');
  if (!Array.isArray(raw.software)) {
    throw new SnapshotParseError(
      'That looks like JSON, but not a VulnScan snapshot - it has no "software" list. ' +
      'If you ran a different RFF collector, use the tool that matches it.');
  }
  if (!raw.machine || typeof raw.machine !== 'object') {
    throw new SnapshotParseError('The snapshot has no "machine" section. Re-run the collector.');
  }
  return raw as Snapshot;
}

/**
 * Numeric segment-by-segment version compare.
 *
 * Returns null when either side cannot be read as a version. That is deliberate and the caller
 * treats null as "no match": for a security tool, silently guessing that an unparseable version
 * falls inside a vulnerable range invents findings, and a false positive on a CVE report costs
 * somebody a real afternoon.
 */
export function compareVersions(a: string, b: string): number | null {
  if (!a || !b) return null;
  const split = (s: string) => s.split(/[._\-+]/).map(x => {
    const n = parseInt(x, 10);
    return Number.isNaN(n) ? 0 : n;
  });
  const A = split(a), B = split(b);
  if (!A.length || !B.length) return null;
  for (let i = 0; i < Math.max(A.length, B.length); i++) {
    const d = (A[i] ?? 0) - (B[i] ?? 0);
    if (d !== 0) return d < 0 ? -1 : 1;
  }
  return 0;
}

/** Tokenise a product or display name: lowercase, split on anything that is not alphanumeric.
 *  "Node.js" and "ImageMagick 7.1.2-21 Q16-HDRI (64-bit)" both become clean word lists. */
export function tokenise(s: string): string[] {
  return s.toLowerCase().split(/[^a-z0-9+]+/).filter(Boolean);
}

/**
 * Which CPE product, if any, this installed application is.
 *
 * WORD-SUBSET, not substring: every word of the needle must appear somewhere in the name, in any
 * order. Substring matching looks equivalent and is not - it requires the words to be CONTIGUOUS,
 * and real display names put the version in the middle ("ImageMagick 7.1.2-21 Q16-HDRI"). That
 * silently lost 70 real findings before this was fixed, which is the worst failure mode a security
 * tool has: a confident zero.
 *
 * Most words wins, so "microsoft edge webview2 runtime" binds to the WebView2 entry rather than to
 * plain "microsoft edge", which is also a subset of it.
 */
export function resolveProduct(name: string, aliases: Record<string, string[]>): string | null {
  const words = new Set(tokenise(name));
  let best: string | null = null, bestScore = 0;
  for (const [key, needles] of Object.entries(aliases)) {
    for (const needle of needles) {
      const parts = tokenise(needle);
      if (!parts.length || parts.length <= bestScore) continue;
      if (parts.every(p => words.has(p))) { best = key; bestScore = parts.length; }
    }
  }
  return best;
}

export interface Finding {
  cve: string; severity: number; kev: boolean;
  software: string; version: string; product: string;
  /** THE PROOF. The exact version range from NVD that this installed version fell inside, kept so
   *  the report can show its working instead of asserting a verdict. */
  range: string;
  /** The version this particular CVE is fixed in, when NVD states an exclusive upper bound. */
  fixedIn: string | null;
  /** The registry key the installed version was read from. Undefined on pre-1.1 snapshots. */
  evidence?: AppEvidence;
}

/** One OS-level finding: this Windows build is below the revision Microsoft fixed the CVE in. */
export interface OsFinding {
  cve: string;
  severity: number;
  kev: boolean;
  /** The UBR Microsoft fixed it in, within this build's servicing stream. */
  fixedUbr: number;
  /** What the machine actually reports, carried so the report can show the comparison. */
  observedUbr: number;
  build: number;
}

/** Proof for an OS verdict. One well-known key, and the two numbers the comparison used - a
 *  stronger artifact than the application case, which has to reason about DisplayVersion. */
export interface OsEvidence {
  registryPath: string;
  currentBuildNumber: number;
  ubr: number;
  fullBuild: string;
}

export interface OsScanResult {
  /** False when we could not check at all: no OS data in the index, no build in the snapshot, or
   *  this build is not covered. The report must SAY so rather than showing a clean OS, which would
   *  be a false all-clear on the half people care about most. */
  available: boolean;
  findings: OsFinding[];
  evidence: OsEvidence | null;
  /** Present when we cannot check, explaining which of those it was. */
  note?: string;
  /**
   * True when the machine's revision is BELOW the oldest fix we hold for its build - so it predates
   * our coverage and the findings list is a floor, not a complete answer.
   *
   * This is the subtle failure the rest of the guards miss. An old build IS in the index (it has
   * 2021+ CVEs), so `available` stays true and the report looks authoritative while silently
   * omitting years. Partial coverage is more dangerous than none, because nothing about it looks
   * wrong. MSRC did not publish FixedBuild before ~2021, so this is a hard limit of the data.
   */
  partialCoverage: boolean;
  /** The oldest fix we hold for this build, for the warning to quote. */
  coverageFloor?: number;
}

/**
 * Match the machine's Windows build/UBR against the index's OS section.
 *
 * Deliberately tolerant of an index that has no `os` key at all: the tool ships before the OS index
 * does, and every already-downloaded copy must light up when the hosted index gains the section,
 * without anybody re-downloading the script or the page.
 */
export function scanOs(snapshot: Snapshot, index: CveIndex): OsScanResult {
  const m = snapshot.machine;
  const evidence: OsEvidence | null = m?.build && m?.ubr != null ? {
    // Verified against the agent + the collector: both read exactly this key.
    registryPath: 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion',
    currentBuildNumber: m.build,
    ubr: m.ubr,
    fullBuild: m.fullBuild ?? `10.0.${m.build}.${m.ubr}`,
  } : null;

  const idx = index as {
    os?: Record<string, [string, number, number, number][]>;
    builds?: Record<string, number>;
  };
  const osIndex = idx.os;
  if (!osIndex || Object.keys(osIndex).length === 0) {
    return { available: false, findings: [], evidence, partialCoverage: false,
      note: 'The hosted index does not carry Windows OS data yet, so the operating system was NOT checked. This is an application-level result only.' };
  }
  if (!evidence) {
    return { available: false, findings: [], evidence: null, partialCoverage: false,
      note: 'This snapshot has no Windows build number, so the operating system could not be checked.' };
  }

  const buildKey = String(evidence.currentBuildNumber);
  // A build we hold NO data for is not a clean build. Saying "up to date" here would be a false
  // all-clear for Insider builds, unusual SKUs, and anything newer than the index.
  const covered = idx.builds ? buildKey in idx.builds : buildKey in osIndex;
  if (!covered) {
    return { available: false, findings: [], evidence, partialCoverage: false,
      note: `There is no OS CVE data for Windows build ${evidence.currentBuildNumber} in the index, so the operating system was NOT checked. This can mean a very new build that nothing has been published against yet, or one outside the index's coverage.` };
  }

  const rows = osIndex[buildKey] ?? [];
  const findings: OsFinding[] = [];
  for (const [cve, severity, kev, fixedUbr] of rows) {
    // Affected when this machine's revision is BELOW the one that carries the fix. Equal or above
    // is patched - an off-by-one here would report every fully-patched machine as vulnerable.
    if (evidence.ubr < fixedUbr) {
      findings.push({ cve, severity, kev: kev === 1, fixedUbr, observedUbr: evidence.ubr, build: evidence.currentBuildNumber });
    }
  }
  findings.sort((a, b) => (b.kev ? 1 : 0) - (a.kev ? 1 : 0) || b.severity - a.severity || a.cve.localeCompare(b.cve));

  const floor = idx.builds?.[buildKey];
  return {
    available: true,
    findings,
    evidence,
    // Below the oldest fix we hold means the machine predates our data for this build.
    partialCoverage: floor !== undefined && evidence.ubr < floor,
    coverageFloor: floor,
  };
}

export interface VulnerableApp {
  name: string; version: string; count: number; worst: number; kev: number;
  evidence?: AppEvidence;
  /** Upgrade target that clears the most CVEs for this app: the highest "fixed in" across its
   *  findings. Null when NVD only gave inclusive upper bounds, in which case we say so rather
   *  than inventing a number. */
  upgradeTo: string | null;
  clearedByUpgrade: number;
  examples: Finding[];
}

export interface ScanReport {
  machine: string; os: string;
  findings: Finding[];
  distinctCves: number;
  critical: number; high: number; medium: number; low: number; kev: number;
  appsScanned: number;
  appsMatchedToProduct: number;
  appsUnrecognised: number;
  vulnerableApps: VulnerableApp[];
  indexProducts: number;
  indexGenerated?: string;
  matchMs: number;
}

export function scan(snapshot: Snapshot, index: CveIndex): ScanReport {
  const t0 = performance.now();
  const findings: Finding[] = [];
  let matchedApps = 0;

  for (const app of snapshot.software ?? []) {
    if (!app?.name || !app?.version) continue;
    const key = resolveProduct(app.name, index.aliases);
    if (!key) continue;
    matchedApps++;
    const rows = index.products[key];
    if (!rows) continue;

    for (const r of rows) {
      const [cve, sev, kev, vStart, startIncl, vEnd, endIncl] = r;
      let ok = true;
      if (vStart) {
        const c = compareVersions(app.version, vStart);
        if (c === null) ok = false;
        else if (startIncl === 1 ? c < 0 : c <= 0) ok = false;
      }
      if (ok && vEnd) {
        const c = compareVersions(app.version, vEnd);
        if (c === null) ok = false;
        else if (endIncl === 1 ? c > 0 : c >= 0) ok = false;
      }
      // A row with neither bound names the product with no version constraint. Treating that as a
      // hit would flag every version ever shipped, so it is skipped rather than guessed.
      if (!vStart && !vEnd) ok = false;
      if (!ok) continue;
      const lo = vStart ? `${startIncl === 1 ? '>=' : '>'} ${vStart}` : null;
      const hi = vEnd ? `${endIncl === 1 ? '<=' : '<'} ${vEnd}` : null;
      findings.push({
        cve, severity: sev, kev: kev === 1, software: app.name, version: app.version, product: key,
        range: [lo, hi].filter(Boolean).join(' and ') || 'any version',
        evidence: app.evidence,
        // Only an EXCLUSIVE upper bound means "fixed in". An inclusive one ("<= 3.2") says the last
        // affected version, not the fixed one, and treating them the same would tell people to
        // install a build that is still vulnerable.
        fixedIn: vEnd && endIncl === 0 ? vEnd : null,
      });
    }
  }

  // One row per CVE per machine. The same CVE reached through two version ranges is one problem.
  const byCve = new Map<string, Finding>();
  for (const f of findings) if (!byCve.has(f.cve)) byCve.set(f.cve, f);
  const unique = [...byCve.values()];

  const perApp = new Map<string, VulnerableApp>();
  for (const f of unique) {
    const k = `${f.software}|${f.version}`;
    const e = perApp.get(k) ?? {
      name: f.software, version: f.version, count: 0, worst: 0, kev: 0,
      upgradeTo: null, clearedByUpgrade: 0, examples: [], evidence: f.evidence,
    };
    e.count++; e.worst = Math.max(e.worst, f.severity);
    if (f.kev) e.kev++;
    // Highest "fixed in" wins: upgrading to it clears every CVE fixed at or below it.
    if (f.fixedIn && (!e.upgradeTo || (compareVersions(f.fixedIn, e.upgradeTo) ?? 0) > 0)) e.upgradeTo = f.fixedIn;
    if (e.examples.length < 3) e.examples.push(f);
    perApp.set(k, e);
  }
  for (const e of perApp.values()) {
    e.examples.sort((a, b) => b.severity - a.severity);
    e.clearedByUpgrade = e.upgradeTo
      ? unique.filter(f => f.software === e.name && f.fixedIn &&
          (compareVersions(f.fixedIn, e.upgradeTo!) ?? 1) <= 0).length
      : 0;
  }

  const total = (snapshot.software ?? []).length;
  return {
    machine: snapshot.machine?.machineName ?? 'this machine',
    os: snapshot.machine?.fullBuild
      ? `${snapshot.machine.caption ?? 'Windows'} ${snapshot.machine.displayVer ?? ''} (build ${snapshot.machine.fullBuild})`.replace(/\s+/g, ' ')
      : '',
    findings: unique.sort((a, b) => b.severity - a.severity || a.cve.localeCompare(b.cve)),
    distinctCves: unique.length,
    critical: unique.filter(f => f.severity === 4).length,
    high: unique.filter(f => f.severity === 3).length,
    medium: unique.filter(f => f.severity === 2).length,
    low: unique.filter(f => f.severity <= 1).length,
    kev: unique.filter(f => f.kev).length,
    appsScanned: total,
    appsMatchedToProduct: matchedApps,
    appsUnrecognised: total - matchedApps,
    vulnerableApps: [...perApp.values()].sort((a, b) => b.worst - a.worst || b.count - a.count),
    indexProducts: Object.keys(index.products).length,
    indexGenerated: index.generated,
    matchMs: Math.round(performance.now() - t0),
  };
}

/**
 * The headline. Deliberately reports what was NOT recognised alongside what was: an inventory
 * where most applications are unknown to the index has not been "scanned clean", and a tool that
 * prints a reassuring zero without saying how much it could actually see is the same dishonesty
 * the Hardened baseline refuses to commit.
 */
export function headline(r: ScanReport): string {
  if (r.distinctCves === 0) {
    return r.appsMatchedToProduct === 0
      ? `None of the ${r.appsScanned} applications on ${r.machine} are covered by this index, so nothing could be checked.`
      : `No known CVEs matched the ${r.appsMatchedToProduct} recognised applications on ${r.machine}.`;
  }
  const worst = r.kev > 0
    ? `${r.kev} of them are on CISA's Known Exploited Vulnerabilities list, which is where to start.`
    : r.critical > 0
      ? `${r.critical} are rated critical.`
      : `${r.high} are rated high.`;
  return `${r.distinctCves} known CVEs affect ${r.vulnerableApps.length} applications on ${r.machine}. ${worst}`;
}
