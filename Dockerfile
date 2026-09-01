# Build the vulnerability index yourself, from the original sources, with your own NVD API key.
#
# Nothing in here talks to getrff.com. Applications come from NVD's own API and Windows OS CVEs from
# Microsoft's MSRC feed, which is the point: the index this produces is verifiable without trusting
# our copy of it. Diff the output against the published one if you like.
#
#   docker build -t vulnscan-index .
#   docker run --rm -e NVD_API_KEY=your-key -v "${PWD}/out:/out" vulnscan-index
#
# Then point the collector at the result:
#   .\Get-RffVulnScan.ps1 -IndexFile .\out\cve-index.json
#
# Without NVD_API_KEY it still works, at NVD's keyless rate limit: roughly 70 minutes instead of 12.
# Keys are free from https://nvd.nist.gov/developers/request-an-api-key
FROM python:3.12-slim

# The builders use only the standard library on purpose. No pip install, so there is no third-party
# dependency to audit in a tool whose whole argument is that you can check what it does.
WORKDIR /app
COPY scripts/ /app/scripts/
COPY data/ /app/data/

# The scripts default to the author's Windows paths; every one is env-overridable.
ENV OUT=/out/cve-index.json \
    APP_INDEX_OUT=/tmp/app-index.json \
    OSCVE_OUT=/tmp/oscve-index.json \
    FLEET_CPES=/app/data/fleet-cpes.json \
    MSRC_CACHE=/out/.msrc-cache \
    APP_SEED=/out/cve-index.json \
    PYTHONUNBUFFERED=1

VOLUME /out

# --full forces a complete MSRC re-fetch. MSRC revises already-published months, so a from-scratch
# build should not trust an incremental path it has no history for.
ENTRYPOINT ["python", "/app/scripts/build-index.py"]
CMD ["--full"]
