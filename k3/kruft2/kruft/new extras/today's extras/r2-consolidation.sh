#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════
#  VVIP-MEDIA R2 BUCKET — CONSOLIDATION SCRIPT
#  Target structure (everything under vvip-media):
#
#  vvip-media/
#  ├── ACCESS/          ← mp3s (keep as-is, this is the main audio)
#  ├── WAV/             ← wavs (keep as-is)
#  ├── MEDIA/
#  │   ├── thumbs/      ← track thumbnails
#  │   ├── extras/      ← extra images (keep as-is)
#  │   └── shoppe/      ← store images (if any)
#  ├── VIDEOS/          ← canonical HQ videos (.mov / .mp4)
#  └── [DELETE or archive: CRUFT/, FOOTAGE/, videos/]
#
#  What needs moving:
#  - vvip-media/videos/* → vvip-media/VIDEOS/  (lowercase dupe folder)
#  - vvip-media/FOOTAGE/ → not public-facing; leave or delete manually
#  - vvip-media/CRUFT/   → delete manually via dashboard
#
#  The "vvipmedia" bucket (22 objects, 398 MB) appears to be
#  an old/dupe bucket — audit then delete after confirming
#  nothing live points to it.
# ══════════════════════════════════════════════════════════════

# PREREQUISITES:
# 1. Install rclone: https://rclone.org/install/
# 2. Configure R2 remote — run: rclone config
#    Name it "r2", use Cloudflare R2 S3-compatible endpoint:
#    endpoint = https://<ACCOUNT_ID>.r2.cloudflarestorage.com
#    access_key_id = <R2 Access Key>
#    secret_access_key = <R2 Secret Key>
# 3. Dry-run first with --dry-run before any destructive ops!

BUCKET="vvip-media"
REMOTE="r2"   # your rclone remote name

# ── STEP 1: List full contents of each folder to verify ──────
echo "=== Listing videos/ (lowercase, dupe) ==="
rclone ls ${REMOTE}:${BUCKET}/videos/

echo ""
echo "=== Listing VIDEOS/ (canonical) ==="
rclone ls ${REMOTE}:${BUCKET}/VIDEOS/

echo ""
echo "=== Listing CRUFT/ ==="
rclone ls ${REMOTE}:${BUCKET}/CRUFT/

echo ""
echo "=== Listing FOOTAGE/ ==="
rclone ls ${REMOTE}:${BUCKET}/FOOTAGE/

# ── STEP 2: Merge lowercase videos/ into VIDEOS/ ─────────────
# DRY RUN first (shows what would happen, no changes):
echo ""
echo "=== DRY RUN: merge videos/ → VIDEOS/ ==="
rclone copy --dry-run \
  ${REMOTE}:${BUCKET}/videos/ \
  ${REMOTE}:${BUCKET}/VIDEOS/

# When ready, remove --dry-run:
# rclone copy \
#   ${REMOTE}:${BUCKET}/videos/ \
#   ${REMOTE}:${BUCKET}/VIDEOS/

# Then delete the lowercase folder:
# rclone delete ${REMOTE}:${BUCKET}/videos/
# rclone rmdir  ${REMOTE}:${BUCKET}/videos/

# ── STEP 3: Full listing to a file (for auditing) ────────────
echo ""
echo "=== Full bucket listing → bucket-contents.txt ==="
rclone ls ${REMOTE}:${BUCKET} > bucket-contents.txt
echo "Written to bucket-contents.txt"
wc -l bucket-contents.txt

# ── STEP 4: MP3s in ACCESS/ vs manifest cross-check ─────────
# Run this after step 3:
# grep '\.mp3$' bucket-contents.txt | awk '{print $NF}' | \
#   sed 's|ACCESS/||' | sort > r2-mp3s.txt
# diff r2-mp3s.txt manifest-names.txt   # see what's missing each way

# ── STEP 5: WAV bucket — confirm structure ───────────────────
# WAVs are already at vvip-media/WAV/ — filenames match mp3s
# (24.03.15.105.wav etc). No move needed, just confirm the
# WAV download URL pattern: https://cdn.vvipmedia.net/WAV/<name>.wav
# replacing .mp3 with .wav in the filename.

# ── STEP 6: Old "vvipmedia" bucket audit ─────────────────────
echo ""
echo "=== Old vvipmedia bucket contents ==="
rclone ls ${REMOTE}:vvipmedia

# Once confirmed nothing live uses it, delete:
# rclone delete ${REMOTE}:vvipmedia
# (or just disable public access in the R2 dashboard)

# ── CANONICAL CDN URL PATTERNS (for the player/site code) ────
# MP3:       https://cdn.vvipmedia.net/ACCESS/<filename>.mp3
# WAV:       https://cdn.vvipmedia.net/WAV/<filename>.wav
# Thumbnail: https://cdn.vvipmedia.net/MEDIA/thumbs/<filename>thumb.jpg
# HQ Video:  https://cdn.vvipmedia.net/VIDEOS/<video>.mp4
# Extras:    https://cdn.vvipmedia.net/MEDIA/extras/<img>
