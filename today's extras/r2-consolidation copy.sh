#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════
#  VVIP-MEDIA R2 — CONSOLIDATION + MISSING FILE AUDIT
#  Run each section independently. Always dry-run first.
# ══════════════════════════════════════════════════════════════
#
#  SETUP (one-time):
#  1. brew install rclone
#  2. rclone config
#     - New remote → name: r2
#     - Type: s3  →  Provider: Cloudflare
#     - access_key_id + secret_access_key: R2 dashboard → Manage API tokens
#     - endpoint: https://<ACCOUNT_ID>.r2.cloudflarestorage.com
#     - Leave region blank
# ══════════════════════════════════════════════════════════════

REMOTE="r2"
BUCKET="vvip-media"
LOCAL_MP3="$HOME/Music/Music/Media.localized/Music/Unknown Artist/Unknown Album"
# Set LOCAL_WAV to wherever you keep your wav exports:
LOCAL_WAV="$HOME/path/to/wavs"

# ── 1. CONSOLIDATE videos/ → VIDEOS/ ─────────────────────────
# Dry run first:
rclone copy --dry-run \
  "${REMOTE}:${BUCKET}/videos/" \
  "${REMOTE}:${BUCKET}/VIDEOS/"
# Then for real (uncomment):
# rclone copy "${REMOTE}:${BUCKET}/videos/" "${REMOTE}:${BUCKET}/VIDEOS/"
# rclone delete "${REMOTE}:${BUCKET}/videos/"

# ── 2. GET FULL BUCKET LISTING ────────────────────────────────
rclone ls "${REMOTE}:${BUCKET}" > /tmp/r2-all-files.txt
echo "Total objects: $(wc -l < /tmp/r2-all-files.txt)"

# Extract filenames only (strip size column and folder prefix)
grep -i 'ACCESS/.*\.mp3$' /tmp/r2-all-files.txt \
  | awk '{print $NF}' | sed 's|ACCESS/||I' | sort > /tmp/r2-mp3s-actual.txt

grep -i 'WAV/.*\.wav$' /tmp/r2-all-files.txt \
  | awk '{print $NF}' | sed 's|WAV/||I' | sort > /tmp/r2-wavs-actual.txt

echo "ACCESS/ mp3s on R2:  $(wc -l < /tmp/r2-mp3s-actual.txt)"
echo "WAV/ wavs on R2:     $(wc -l < /tmp/r2-wavs-actual.txt)"

# ── 3. DIFF AGAINST MANIFEST EXPECTED LISTS ──────────────────
# (expected-mp3s.txt and expected-wavs.txt ship alongside this script)
sort expected-mp3s.txt > /tmp/expected-mp3s-sorted.txt
sort expected-wavs.txt > /tmp/expected-wavs-sorted.txt

comm -23 /tmp/expected-mp3s-sorted.txt /tmp/r2-mp3s-actual.txt > /tmp/missing-mp3s.txt
comm -23 /tmp/expected-wavs-sorted.txt /tmp/r2-wavs-actual.txt > /tmp/missing-wavs.txt

echo ""
echo "MISSING MP3s ($(wc -l < /tmp/missing-mp3s.txt)):"
cat /tmp/missing-mp3s.txt

echo ""
echo "MISSING WAVs ($(wc -l < /tmp/missing-wavs.txt)):"
cat /tmp/missing-wavs.txt

echo ""
echo "EXTRA on R2 not in manifest:"
comm -13 /tmp/expected-mp3s-sorted.txt /tmp/r2-mp3s-actual.txt

# ── 4. UPLOAD MISSING FILES ───────────────────────────────────
# Upload all missing mp3s:
# while IFS= read -r f; do
#   echo "Uploading $f..."
#   rclone copyto "${LOCAL_MP3}/${f}" "${REMOTE}:${BUCKET}/ACCESS/${f}"
# done < /tmp/missing-mp3s.txt

# Upload all missing wavs:
# while IFS= read -r f; do
#   echo "Uploading $f..."
#   rclone copyto "${LOCAL_WAV}/${f}" "${REMOTE}:${BUCKET}/WAV/${f}"
# done < /tmp/missing-wavs.txt

# ── 5. CLEAN UP ───────────────────────────────────────────────
# Audit old dupe bucket first, then delete if confirmed unused:
# rclone ls "${REMOTE}:vvipmedia"
# rclone delete "${REMOTE}:vvipmedia"
# rclone ls "${REMOTE}:${BUCKET}/CRUFT/"
# rclone delete "${REMOTE}:${BUCKET}/CRUFT/"
