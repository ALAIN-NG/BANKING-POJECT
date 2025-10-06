#!/usr/bin/env bash
set -e
TARGET=${1:-http://127.0.0.1:8000/banking/pages/login/}
OUTDIR=evidence/zap
mkdir -p "$OUTDIR"
TS=$(date -u +"%Y%m%dT%H%M%SZ")
OUTFILE=zap_report_${TS}.html

echo "Running ZAP baseline against $TARGET"
# adjust image name if needed (ghcr.io/zaproxy/zaproxy:stable)
docker run --rm --network host -v "$(pwd)/$OUTDIR":/zap/wrk/ ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t "$TARGET" -r "$OUTFILE" -I -z "-config api.disablekey=true" \
  2>&1 | tee "$OUTDIR/zap_run_${TS}.log"
cp "$OUTDIR/$OUTFILE" "$OUTDIR/zap_report.html"
echo "Report saved to $OUTDIR/$OUTFILE"
