#!/usr/bin/env bash
# Reproduce results.tsv from the exact sources pinned in sources.tsv.

set -u

KEY="838d364d8ed3bd085e150211ea6b3715"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
MANIFEST=${MANIFEST:-"$SCRIPT_DIR/sources.tsv"}
OUTPUT_TSV=${OUTPUT_TSV:-"$SCRIPT_DIR/results.generated.tsv"}
LOG_FILE=${LOG_FILE:-"${OUTPUT_TSV%.tsv}.log"}
REFERENCE_TSV=${REFERENCE_TSV:-"$SCRIPT_DIR/results.tsv"}
ONLY_CODES=${ONLY_CODES:-}
RUN_ID=$$

if [ -n "${WORK_DIR:-}" ]; then
  WORK=$WORK_DIR
  mkdir -p "$WORK"
  CLEAN_WORK=0
else
  WORK=$(mktemp -d "${TMPDIR:-/tmp}/cabmeshd-sweep.XXXXXX")
  CLEAN_WORK=1
fi
BINS="$WORK/cab_meshd"
mkdir -p "$BINS"

cleanup() {
  if [ "$CLEAN_WORK" = 1 ]; then
    rm -rf -- "$WORK"
  fi
}
trap cleanup EXIT

: > "$LOG_FILE"
printf "code\tproduct\tfw\tarch\tkey\tsha\tsize\tsrc\turl\n" > "$OUTPUT_TSV"

want_code() {
  local code=$1 candidate
  [ -z "$ONLY_CODES" ] && return 0
  for candidate in $ONLY_CODES; do
    [ "$candidate" = "$code" ] && return 0
  done
  return 1
}

need_command() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "missing required command: $1" >&2
    return 1
  }
}

extract_meshd() { # image, output directory; prints the extracted binary path
  local image=$1 out=$2 offset volume
  mkdir -p "$out"

  offset=$(binwalk "$image" 2>/dev/null \
    | awk 'tolower($0) ~ /squashfs filesystem/ {print $1; exit}')
  if [ -n "$offset" ]; then
    tail -c +$((offset + 1)) "$image" > "$out/root.sqfs"
    if unsquashfs -q -f -d "$out/rootfs" "$out/root.sqfs" \
      "usr/sbin/cab_meshd" >/dev/null 2>&1; then
      if [ -f "$out/rootfs/usr/sbin/cab_meshd" ]; then
        printf '%s\n' "$out/rootfs/usr/sbin/cab_meshd"
        return 0
      fi
    fi
  fi

  if binwalk "$image" 2>/dev/null | grep -qi "UBI erase count header"; then
    need_command ubireader_extract_images || return 1
    ubireader_extract_images -o "$out/ubi" "$image" >/dev/null 2>&1 || return 1
    while IFS= read -r volume; do
      offset=$(binwalk "$volume" 2>/dev/null \
        | awk 'tolower($0) ~ /squashfs filesystem/ {print $1; exit}')
      [ -z "$offset" ] && continue
      tail -c +$((offset + 1)) "$volume" > "$out/root.sqfs"
      rm -rf -- "$out/rootfs"
      if unsquashfs -q -f -d "$out/rootfs" "$out/root.sqfs" \
        "usr/sbin/cab_meshd" >/dev/null 2>&1; then
        if [ -f "$out/rootfs/usr/sbin/cab_meshd" ]; then
          printf '%s\n' "$out/rootfs/usr/sbin/cab_meshd"
          return 0
        fi
      fi
    done < <(find "$out/ubi" -type f -print 2>/dev/null)
  fi
  return 1
}

normalise_arch() {
  local description
  description=$(file -b "$1")
  case "$description" in
    *aarch64*) printf '%s\n' "ARM64 (aarch64)" ;;
    *ARM*EABI5*) printf '%s\n' "ARM32 (EABI5)" ;;
    *MIPS*) printf '%s\n' "MIPS32el" ;;
    *) printf '%s\n' "$description" ;;
  esac
}

emit_failure() {
  local code=$1 product=$2 fw=$3 status=$4 src=$5 url=$6
  printf "%s\t%s\t%s\t%s\t%s\t-\t-\t%s\t%s\n" \
    "$code" "$product" "$fw" "$status" "$status" "$src" "$url" \
    >> "$OUTPUT_TSV"
}

for tool in file sha256sum stat grep awk cp; do
  need_command "$tool" || exit 2
done

while IFS=$'\t' read -r code product fw src kind url ref member; do
  [ "$code" = code ] && continue
  want_code "$code" || continue
  echo "=== $code ($product) ===" >> "$LOG_FILE"

  if [ "$kind" = unavailable ]; then
    printf "%s\t%s\t-\t-\tNO PUBLIC IMAGE\t-\t-\t-\t-\n" \
      "$code" "$product" >> "$OUTPUT_TSV"
    continue
  fi

  meshd=
  case "$kind" in
    firmware)
      for tool in curl binwalk unsquashfs; do
        need_command "$tool" || exit 2
      done
      image="$WORK/${code}_${RUN_ID}.bin"
      if ! curl -fL --max-time 900 "$url" -o "$image"; then
        emit_failure "$code" "$product" "$fw" DOWNLOAD_FAILED "$src" "$url"
        continue
      fi
      meshd=$(extract_meshd "$image" "$WORK/extract_${code}_${RUN_ID}") || true
      ;;
    git)
      need_command git || exit 2
      repo="$WORK/git_${code}_${RUN_ID}"
      git init -q "$repo"
      git -C "$repo" remote add origin "$url"
      if ! git -C "$repo" fetch -q --depth 1 origin "$ref" \
        || ! git -C "$repo" checkout -q --detach FETCH_HEAD; then
        emit_failure "$code" "$product" "$fw" FETCH_FAILED "$src" "$url"
        continue
      fi
      meshd="$repo/$member"
      ;;
    *)
      emit_failure "$code" "$product" "$fw" UNKNOWN_SOURCE "$src" "$url"
      continue
      ;;
  esac

  if [ -z "$meshd" ] || [ ! -f "$meshd" ]; then
    emit_failure "$code" "$product" "$fw" EXTRACT_FAILED "$src" "$url"
    continue
  fi

  cp "$meshd" "$BINS/${code}_${fw}.cab_meshd"
  sha=$(sha256sum "$meshd" | awk '{print $1}')
  size=$(stat -c%s "$meshd")
  arch=$(normalise_arch "$meshd")
  if grep -aq "$KEY" "$meshd"; then key=YES; else key=no; fi
  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$code" "$product" "$fw" "$arch" "$key" "$sha" "$size" "$src" "$url" \
    >> "$OUTPUT_TSV"
  echo "  key=$key arch=$arch sha=$sha" >> "$LOG_FILE"
done < "$MANIFEST"

echo "SWEEP COMPLETE" >> "$LOG_FILE"
echo "wrote $OUTPUT_TSV"
if [ -z "$ONLY_CODES" ] && [ -f "$REFERENCE_TSV" ]; then
  if cmp -s "$REFERENCE_TSV" "$OUTPUT_TSV"; then
    echo "matches $REFERENCE_TSV"
  else
    echo "differs from $REFERENCE_TSV; inspect with:" >&2
    echo "  diff -u '$REFERENCE_TSV' '$OUTPUT_TSV'" >&2
    exit 1
  fi
fi
