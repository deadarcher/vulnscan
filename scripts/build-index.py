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
    app_products = seed.get("products", {})
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
    # Drop exact duplicate rows. One CVE often names the same version range through several CPE
    # entries (editions, architectures, update levels) and each produced an identical row; 21 percent
    # of the index was these, and every one cost the client an iteration and a version comparison for
    # no extra finding. sun:jdk was 78 percent duplicates.
    #
    # This runs HERE, at the point of write, and not in the app builder's fetch loop. That is where
    # it was first put, and it silently did nothing: the builder skips any product already present
    # from the seed, so on a seeded run it fetches nothing and the dedupe never executed. Same shape
    # as the alias table going missing. Anything derived from the final product set belongs next to
    # the write, not in the path that populates it.
    before = sum(len(v) for v in app_products.values())
    for key, rows in app_products.items():
        seen, keep = set(), []
        for r in rows:
            sig = (r[0], r[3], r[4], r[5], r[6])
            if sig in seen: continue
            seen.add(sig); keep.append(r)
        app_products[key] = keep
    after = sum(len(v) for v in app_products.values())
    if before:
        print(f"  deduped {before - after} identical rows ({100 * (before - after) // before}%)")

    sys.path.insert(0, HERE)
    from aliases import build_table, exclude_list
    merged_aliases = build_table(app_products)
    merged_exclude = exclude_list()

    merged = {
        "v": 1,
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "products": app_products,
        "aliases": merged_aliases,
        "excludeNames": merged_exclude,
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
    app_rows = sum(len(v) for v in merged["products"].values())
    print(f"\nMERGED -> {OUT}")
    print(f"  {len(merged['aliases'])} alias entries")
    print(f"  {len(merged['products'])} app products ({app_rows} rows), "
          f"{len(merged['os'])} OS builds ({os_rows} rows)")
    print(f"  raw {len(raw)/1024/1024:.1f} MB, gzipped {os.path.getsize(OUT + '.gz')/1024:.0f} KB")


if __name__ == "__main__":
    main()
