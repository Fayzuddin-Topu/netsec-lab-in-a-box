#!/usr/bin/env bash
set -euo pipefail

FILE=${1:-dashboards/saved_objects/lab_seed.ndjson}
OSD_URL=${OSD_URL:-http://localhost:5601}

echo "Waiting for OpenSearch Dashboards at ${OSD_URL} ..."
# Wait until the status endpoint returns HTTP 200
until curl -fsS "${OSD_URL}/api/status" >/dev/null 2>&1; do
  sleep 2
done

echo "Dashboards is up. Importing ${FILE} ..."
curl -sS -X POST "${OSD_URL}/api/saved_objects/_import?overwrite=true" \
  -H "osd-xsrf: true" \
  -F file=@${FILE}
echo
echo "Import done."
