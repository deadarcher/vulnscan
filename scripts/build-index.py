"""Build the full VulnScan index: applications (NVD) + Windows OS (MSRC), merged into one file.

This is what the nightly job runs. It orchestrates the two builders and merges their output into the
single cve-index.json the tool downloads.

Resilience is the point. The OS half (MSRC) is the reason to run nightly - a new Patch Tuesday lands
every month - and it is reliable and public. The app half (NVD) is slower and NVD occasionally
throttles or blocks CI ranges, so a failed app build must NOT produce an empty or app-less index:
the merge keeps the last good app section (the committed seed) if this run could not refresh it.

Env:
  MSRC_CACHE     dir for cached MSRC months        (Actions cache persists it between runs)
  APP_SEED       last good merged index, reused if the app rebuild fails or is skipped
  NVD_API_KEY    optional; raises NVD's rate limit 5 -> 50 per 30s
  OUT            where to write the merged cve-index.json
  SKIP_APP=1     skip the app rebuild entirely and reuse APP_SEED (fast OS-only nightly)

Usage:
  python build-index.py            # full: app + OS, merge
  python build-index.py --full     # also force a full MSRC re-fetch (weekly; MSRC revises old months)
"""
import gzip, json, os, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("OUT", os.path.join(HERE, "..", "cve-index.json"))
SEED = os.environ.get("APP_SEED", OUT)   # default: refresh in place
FULL = "--full" in sys.argv

# Bump whenever the MEANING of a fetched row changes, as opposed to the file's shape. The per-product
# seed cache makes a seeded run fetch nothing, so without this a semantics change silently applies
# only to products that happen to be refetched later - which is exactly how the CPE update level
# would have been captured for new products and never for Java. A changed epoch discards the seed and
# refetches everything once.
#   1 = original
#   2 = CPE update level folded into the version (1.5.0 + update23 -> 1.5.0_23)
APP_EPOCH = 2


def run(script, env_extra):
    env = dict(os.environ)
    env.update(env_extra)
    args = [sys.executable, os.path.join(HERE, script)]
    if FULL and script == "build-oscve-index.py":
        args.append("--full")
    print(f"\n=== {script} {'(full)' if '--full' in args else ''} ===", flush=True)
    return subprocess.run(args, env=env).returncode


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def ungroup(grouped):
    """v2 grouped shape back to flat rows: [vStart, si, vEnd, ei, [[cve,sev,kev],...]] -> one row per CVE."""
    flat = {}
    for key, groups in (grouped or {}).items():
        rows = []
        for g in groups:
            vs, si, ve, ei, cves = g[0], g[1], g[2], g[3], g[4]
            for c in cves:
                rows.append([c[0], c[1], c[2], vs, si, ve, ei])
        flat[key] = rows
    return flat


def group(flat):
    """Flat rows to the v2 grouped shape, deduplicating as it goes.

    This is the whole speed fix. A client currently walks every row and runs up to two version
    comparisons on each; grouping by the version bound means it compares each DISTINCT bound once
    and then attributes the whole CVE list to it. Measured across the index: 488,282 rows collapse
    to 43,783 distinct bounds, an 11x cut in comparisons. mozilla:firefox alone goes from 37,833
    rows to 850 bounds, and mozilla:seamonkey is 121x.

    It also shrinks the file, because each bound is stored once instead of once per CVE.
    """
    out = {}
    for key, rows in (flat or {}).items():
        buckets = {}
        for r in rows:
            cve, sev, kev, vs, si, ve, ei = r[0], r[1], r[2], r[3], r[4], r[5], r[6]
            # A bound-less row names the product with no version constraint, so it would flag every
            # version ever shipped. Both consumers already skip these; dropping them at build time
            # means they stop costing download size too.
            if vs is None and ve is None:
                continue
            buckets.setdefault((vs, si, ve, ei), {})[cve] = [cve, sev, kev]
        out[key] = [[b[0], b[1], b[2], b[3], list(cves.values())]
                    for b, cves in buckets.items()]
    return out


def main():
    tmp = tempfile.mkdtemp(prefix="vulnscan-idx-")
    os_out = os.path.join(tmp, "oscve.json")
    app_out = os.path.join(tmp, "app.json")

    # ── OS index (MSRC). Always. If this fails there is no point continuing - it is the whole
    #    reason the job runs nightly.
    rc = run("build-oscve-index.py", {"OSCVE_OUT": os_out})
    os_index = load(os_out)
    if rc != 0 or not os_index or not os_index.get("os"):
        sys.exit("OS index build failed or empty - refusing to publish a run with no OS data.")

    # ── App index (NVD). Best-effort. Seed from the last good merged index so a keyless or throttled
    #    run resumes instead of starting cold, and a total failure keeps the previous app section.
    seed = load(SEED) or {}
    # The fetch/cache path works in FLAT rows and is deliberately left alone, so a v2 seed is
    # ungrouped on the way in and regrouped on the way out. Keeping the format change purely a
    # write-time concern means the resumable per-product cache stays valid across the switch.
    app_products = seed.get("products") or ungroup(seed.get("productsV2", {}))
    seed_epoch = seed.get("appEpoch", 1)
    if app_products and seed_epoch != APP_EPOCH:
        print(f"seed was built at app epoch {seed_epoch}, this build is epoch {APP_EPOCH} - "
              f"discarding it and refetching every product so the change applies uniformly.")
        app_products = {}
    if os.environ.get("SKIP_APP") == "1":
        print("\nSKIP_APP=1 - reusing the seed app section, not touching NVD.")
    else:
        # Prime the app builder's resumable output with the seed's products so it only fetches what
        # is missing or new, then let it refresh.
        with open(app_out, "w", encoding="utf-8") as f:
            json.dump({"v": 1, "products": app_products, "generated": seed.get("generated", "")}, f)
        rc = run("build-cve-index.py", {"APP_INDEX_OUT": app_out})
        fresh = load(app_out)
        if rc == 0 and fresh and fresh.get("products"):
            app_products = fresh["products"]
        else:
            print("\napp index build did not complete cleanly - keeping the previous app section.")

    # ── Merge. App products + OS builds/os into the one file the tool downloads.
    # Aliases are derived HERE, from the products actually being published, not carried over from
    # the app builder. Both consumers refuse to scan without this table, and deriving it at the point
    # of write is what stops it drifting from the product list it describes.
    sys.path.insert(0, HERE)
    from aliases import build_table, exclude_list, incomparable_map, version_from_name_map
    merged_aliases = build_table(app_products)
    merged_exclude = exclude_list()
    merged_incomparable = incomparable_map()
    merged_vfn = version_from_name_map()

    grouped = group(app_products)
    flat_rows = sum(len(v) for v in app_products.values())
    grouped_rows = sum(len(v) for v in grouped.values())
    print(f"  grouped {flat_rows} rows into {grouped_rows} distinct version bounds "
          f"({flat_rows // max(1, grouped_rows)}x fewer comparisons for the client)")

    merged = {
        # v2. The products key is RENAMED, not just reshaped, and that is deliberate: an older
        # already-downloaded collector reading v2 rows as v1 would treat a version string as a CVE
        # id and emit nonsense findings. With the key renamed it sees no products at all, its
        # empty-index guard fires, and it refuses to report a clean result. Fail closed, not wrong.
        "v": 2,
        "appEpoch": APP_EPOCH,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "productsV2": grouped,
        "aliases": merged_aliases,
        "excludeNames": merged_exclude,
        "incomparable": merged_incomparable,
        "versionFromName": merged_vfn,
        "builds": os_index["builds"],
        "os": os_index["os"],
        "osGenerated": os_index["generated"],
    }
    raw = json.dumps(merged, separators=(",", ":")).encode()
    with open(OUT, "wb") as f:
        f.write(raw)
    with gzip.open(OUT + ".gz", "wb", compresslevel=9) as g:
        g.write(raw)

    os_rows = sum(len(v) for v in merged["os"].values())
    app_rows = sum(len(v) for v in merged["productsV2"].values())
    print(f"\nMERGED -> {OUT}")
    print(f"  {len(merged['aliases'])} alias entries")
    print(f"  {len(merged['productsV2'])} app products ({app_rows} bound-groups), "
          f"{len(merged['os'])} OS builds ({os_rows} rows)")
    print(f"  raw {len(raw)/1024/1024:.1f} MB, gzipped {os.path.getsize(OUT + '.gz')/1024:.0f} KB")


if __name__ == "__main__":
    main()
