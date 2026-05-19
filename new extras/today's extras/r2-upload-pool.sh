#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════
#  VVIP R2 — BATCH UPLOAD IMAGES TO MEDIA/pool/
#  Run this once to seed the pool from a local folder.
#  After that, use the admin panel (Image Pool tab) for new uploads.
# ══════════════════════════════════════════════════════════════

REMOTE="r2"
BUCKET="vvip-media"
DEST="${REMOTE}:${BUCKET}/MEDIA/pool/"

# ── Set this to the folder containing your images ────────────
LOCAL_IMAGES="$HOME/path/to/your/thumbnails"   # ← change this

# ── Dry run first ─────────────────────────────────────────────
echo "── Dry run: what would be uploaded ──"
rclone copy --dry-run \
  --include "*.jpg" --include "*.jpeg" --include "*.png" --include "*.webp" \
  "${LOCAL_IMAGES}/" \
  "${DEST}"

echo ""
read -p "Proceed with real upload? (y/N) " confirm
if [[ "$confirm" != "y" && "$confirm" != "Y" ]]; then
  echo "Aborted."
  exit 0
fi

# ── Real upload ───────────────────────────────────────────────
echo "── Uploading images to MEDIA/pool/ ──"
rclone copy \
  --include "*.jpg" --include "*.jpeg" --include "*.png" --include "*.webp" \
  --progress \
  "${LOCAL_IMAGES}/" \
  "${DEST}"

echo ""
echo "── Done. Verify: ──"
rclone lsf "${DEST}" | wc -l | xargs echo "Files in MEDIA/pool/:"

# ── NOTE on naming ────────────────────────────────────────────
# Files land in MEDIA/pool/ with their original filename.
# The admin panel pool browser shows them all as thumbnails.
# If you want them sortable by date, rename them before uploading:
#   YYYY-MM-DD_original-name.jpg
# e.g.: 2025-08-07_kits-session.jpg
