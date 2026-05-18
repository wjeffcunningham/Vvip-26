#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════
#  VVIP R2 — UPLOAD VVIPclips/ → MEDIA/pool/
#  Source: local ~/Documents/GitHub/VVIP25/VVIPclips/
#  Dest:   r2:vvip-media/MEDIA/pool/
# ══════════════════════════════════════════════════════════════

REMOTE="r2"
BUCKET="vvip-media"
SRC="$HOME/Documents/GitHub/VVIP25/VVIPclips/"
DEST="${REMOTE}:${BUCKET}/MEDIA/pool/"

echo "── Dry run ──"
rclone copy --dry-run \
  --include "*.jpg" --include "*.jpeg" --include "*.png" --include "*.webp" \
  "${SRC}" "${DEST}"

echo ""
read -p "Proceed? (y/N) " confirm
[[ "$confirm" != "y" && "$confirm" != "Y" ]] && echo "Aborted." && exit 0

echo "── Uploading… ──"
rclone copy \
  --include "*.jpg" --include "*.jpeg" --include "*.png" --include "*.webp" \
  --progress \
  "${SRC}" "${DEST}"

echo ""
rclone lsf "${DEST}" | wc -l | xargs echo "✓ Files in MEDIA/pool/:"
