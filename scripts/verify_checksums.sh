#!/usr/bin/env bash
set -euo pipefail
if [[ -f "pcaps/checksums.sha256" ]]; then
  sha256sum -c pcaps/checksums.sha256
else
  echo "No checksums yet (expected before datasets)."
fi

