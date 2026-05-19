#!/usr/bin/env bash
# VVIP R2 — CLEANUP + CONSOLIDATE
# Run as-is. Takes ~1 min depending on connection.

REMOTE="r2"
BUCKET="vvip-media"

echo "── 1. Deleting junk files from ACCESS/ ──"
rclone deletefile "${REMOTE}:${BUCKET}/ACCESS/25.01.08.130(1).mp3"
rclone deletefile "${REMOTE}:${BUCKET}/ACCESS/v2.mp3"
rclone deletefile "${REMOTE}:${BUCKET}/ACCESS/v3.mp3"

echo "── 2. Deleting macOS ._* resource forks from videos/ ──"
rclone delete "${REMOTE}:${BUCKET}/videos/" --include "._*"

echo "── 3. Merging videos/ → VIDEOS/ ──"
rclone copy "${REMOTE}:${BUCKET}/videos/" "${REMOTE}:${BUCKET}/VIDEOS/"

echo "── 4. Deleting videos/ ──"
rclone delete "${REMOTE}:${BUCKET}/videos/"

echo "── 5. Deleting CRUFT/ ──"
rclone delete "${REMOTE}:${BUCKET}/CRUFT/"

echo "── 6. Auditing old vvipmedia bucket ──"
echo "Contents:"
rclone ls "${REMOTE}:vvipmedia"
echo ""
read -p "Delete entire vvipmedia bucket? (y/N) " confirm
if [[ "$confirm" == "y" || "$confirm" == "Y" ]]; then
  rclone delete "${REMOTE}:vvipmedia"
  echo "✓ vvipmedia bucket emptied."
else
  echo "Skipped."
fi

echo ""
echo "── Verification ──"
rclone lsf "${REMOTE}:${BUCKET}/videos/" 2>/dev/null \
  && echo "⚠ videos/ still has files" \
  || echo "✓ videos/ gone"
rclone lsf "${REMOTE}:${BUCKET}/VIDEOS/" | wc -l | xargs echo "✓ VIDEOS/ file count:"
rclone lsf "${REMOTE}:${BUCKET}/CRUFT/"  2>/dev/null \
  && echo "⚠ CRUFT/ still has files" \
  || echo "✓ CRUFT/ gone"
