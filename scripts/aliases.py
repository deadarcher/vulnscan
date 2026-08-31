"""Alias generation: CPE key -> the display-name needles that should bind to it.

Its own module because BOTH the app builder and the merger need it, and the merger is what actually
writes the shipped file. That split is how the table went missing in the first place: build-cve-index
generated it, and build-index rebuilt the output dict from an explicit list of keys that did not
include it, so it was computed and then discarded. Deriving it in one place, from the product list
that is actually being published, means the two can never disagree.
"""
import json
import os
import re


# ── Alias table ───────────────────────────────────────────────────────────────────────────────────
# Maps a CPE key ("mozilla:firefox") to the display-name needles that should bind to it. BOTH
# consumers - the browser page and the collector - look this up as index["aliases"], and until
# 2026-08-31 nothing produced it, so every application resolved to nothing and the tool reported
# "0 distinct CVEs" on every machine it ever ran on. The app half of the tool had never worked.
#
# Matching is WORD-SUBSET with most-words-wins (see resolveProduct in vulnScan.ts), so a two-word
# needle beats a one-word needle on the same name. That is what makes it safe to emit both
# "mozilla firefox" and "firefox": "Mozilla Firefox (x64 en-US)" binds on the specific one.
#
# The asymmetry that drives the rules below: a MISSING needle costs a false negative (we miss a real
# CVE), an OVER-BROAD needle costs a false positive (we report CVEs for software you do not have).
# On a security tool the second is worse, because one bogus critical finding teaches somebody to
# distrust the whole report. So bare single-word needles are only emitted when the word is
# distinctive enough to stand alone.

# Single tokens that are ordinary English or otherwise turn up inside unrelated product names. A
# bare needle of one of these matches far too much: "air" hits "Air Explorer", "office" hits every
# Office component, "commerce" hits any e-commerce tool. These require the vendor word as well.
GENERIC_TOKENS = {
    "air", "office", "commerce", "rails", "wire", "tor", "core", "studio", "server", "client",
    "player", "reader", "manager", "browser", "desktop", "mobile", "cloud", "connect", "access",
    "one", "go", "now", "up", "on", "for", "and", "the", "pro", "plus", "lite", "free", "open",
    "central", "express", "basic", "home", "team", "teams", "meeting", "meetings", "chat", "mail",
    "notes", "drive", "box", "space", "link", "hub", "flow", "sync", "share", "vault", "guard",
    "shield", "defender", "security", "antivirus", "backup", "recovery", "monitor", "insight",
    "engine", "runtime", "framework", "platform", "suite", "tools", "toolkit", "builder", "creator",
    "editor", "viewer", "designer", "writer", "master", "expert", "ultimate", "premium", "advanced",
    # Added after reviewing real bindings: each of these appeared in a WRONG match as the only
    # thing the needle had to go on.
    "graphics", "driver", "visual", "studio", "net", "sdk", "edition", "service", "update",
    "windows", "microsoft", "app", "apps", "package", "component", "library", "system", "media",
}

def cpe_unescape(s):
    r"""CPE 2.3 backslash-escapes punctuation (notepad\+\+, joomla\!). The tokeniser
    keeps '+' as a word character, so stripping the backslashes is all that is needed."""
    return re.sub(r"\\(.)", r"\1", s)

def tokenise(s):
    """Byte-for-byte the same rule as tokenise() in vulnScan.ts and Get-RffVulnScan.ps1. If these
    three ever disagree, needles silently stop binding, which is invisible until somebody notices
    the tool finds nothing."""
    return [t for t in re.split(r"[^a-z0-9+]+", s.lower()) if t]

def needles_for(vendor, product):
    v = cpe_unescape(vendor).replace("_", " ")
    p = cpe_unescape(product).replace("_", " ")
    out = []
    # Vendor + product first: matches "Mozilla Firefox", "Oracle VM VirtualBox", "Google Chrome".
    if v and v != p:
        out.append(f"{v} {p}")
    # Product alone: many display names omit the vendor entirely ("VLC media player", "Python 3.12",
    # "7-Zip 24.08"), so without this we miss real software. But it is also the ONLY source of false
    # positives measured on real machines, and every one had the same shape - a product name made
    # entirely of descriptive words, which then matches another vendor's product built from the same
    # words. Measured on deadarcher 2026-08-31, before this rule:
    #     intel:graphics_driver        <- "NVIDIA Graphics Driver 595.95"
    #     microsoft:visual_studio_2026 <- "NVIDIA Nsight Visual Studio Edition"
    #     microsoft:.net_framework     <- "Microsoft ASP.NET Core - Shared Framework"
    # So: emit the bare product ONLY if it carries at least one distinctive word. "vlc media player"
    # keeps it (vlc), "graphics driver" and "visual studio 2026" do not. This deliberately trades
    # recall for precision - a missed CVE is a gap, a fabricated one teaches the user to distrust
    # every finding in the report.
    ptok = tokenise(p)
    distinctive = [t for t in ptok if t not in GENERIC_TOKENS and not t.isdigit() and len(t) >= 3]
    if distinctive:
        out.append(p)
    # Deduplicate while keeping order, and drop anything that tokenises to nothing.
    seen, final = set(), []
    for n in out:
        if not tokenise(n) or n in seen: continue
        seen.add(n); final.append(n)
    return final


# ── Curated corrections ───────────────────────────────────────────────────────────────────────────
# Derivation handles the common shape and cannot settle ambiguity. data/name-overrides.json records
# the human decisions, with a reason for each, and is applied on top.
_OVERRIDES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "data", "name-overrides.json")


def build_table(product_keys):
    """The alias table for a set of CPE keys: derived needles, then curated add/drop applied."""
    table = {k: needles_for(*k.split(":", 1)) for k in product_keys}
    try:
        with open(_OVERRIDES, encoding="utf-8") as fh:
            ov = json.load(fh)
    except FileNotFoundError:
        print("  no name-overrides.json - using derived aliases only")
        return table

    added = dropped = 0
    for key, extra in ov.get("add", {}).items():
        if key not in table:
            # Loud, because a typo here silently does nothing and the wrong binding stays.
            print(f"  WARNING: override adds needles to '{key}', which is not in the index")
            continue
        for n in extra:
            if n not in table[key]:
                table[key].append(n); added += 1
    for key, gone in ov.get("drop", {}).items():
        if key not in table:
            print(f"  WARNING: override drops needles from '{key}', which is not in the index")
            continue
        before = len(table[key])
        table[key] = [n for n in table[key] if n not in gone]
        dropped += before - len(table[key])
    print(f"  overrides: +{added} needles, -{dropped} needles")
    return table


def exclude_list():
    """Display-name needles that must bind to nothing. Shipped in the index so both consumers apply
    the same rule; neither can express it through the alias table."""
    try:
        with open(_OVERRIDES, encoding="utf-8") as fh:
            return json.load(fh).get("exclude", [])
    except FileNotFoundError:
        return []


def incomparable_map():
    """Products whose installed-version scheme does not line up with the index's. Apps binding to
    these must be reported as "could not compare", never as clean: the comparison silently succeeds
    and returns the wrong answer, which is the one outcome a vulnerability scanner must not produce.
    Shipped in the index so both consumers apply the same list."""
    try:
        with open(_OVERRIDES, encoding="utf-8") as fh:
            return json.load(fh).get("incomparable", {})
    except FileNotFoundError:
        return {}


def version_from_name_map():
    """Per-product rules that derive a comparable version from the display name. Shipped in the
    index so both consumers apply the same rewrite; if none matches, the incomparable entry still
    applies and the app is reported as unchecked rather than silently clean."""
    try:
        with open(_OVERRIDES, encoding="utf-8") as fh:
            return json.load(fh).get("versionFromName", {})
    except FileNotFoundError:
        return {}
