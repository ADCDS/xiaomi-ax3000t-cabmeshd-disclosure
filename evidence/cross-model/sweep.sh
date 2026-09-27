#!/bin/bash
# cab_meshd cross-model key sweep.
# For each Xiaomi router model code: fetch the newest stock firmware from Xiaomi's
# CDN (via the mirom index), extract /usr/sbin/cab_meshd, and test for the
# firmware-global HMAC key.  Emits a TSV of verifiable artefacts.

KEY="838d364d8ed3bd085e150211ea6b3715"
WORK="/tmp/claude-1000/-home-agiu-xiaomi-ax3000t-cabmeshd-disclosure/4fd136d8-c377-4c53-aab1-4c58f7a5c5b7/scratchpad/sweep"
BINS="$WORK/cab_meshd"
TSV="$WORK/results.tsv"
LOG="$WORK/sweep.log"
mkdir -p "$WORK" "$BINS"

declare -A PRODUCT=(
  [RD03]="Xiaomi AX3000T (CN)"          [RD23]="Xiaomi AX3000T (International)"
  [RD15]="Xiaomi BE3600 2.5G"           [RD16]="Xiaomi BE3600"
  [RD18]="Xiaomi BE5000"                [RD08]="Xiaomi BE6500 Pro"
  [RC06]="Xiaomi BE7000"                [RC01]="Xiaomi Router BE10000"
  [RN02]="Xiaomi BE6500"                [RD05]="Mi Router 4A Gigabit Ed."
  [RD13]="Xiaomi Mesh System AC1200"    [RD01]="Xiaomi (RD01)"
  [RD02]="Xiaomi (RD02)"                [RB01]="Xiaomi AX3200"
  [RB03]="Redmi AX6S"                   [RB04]="Xiaomi (RB04)"
  [RB06]="Redmi AX6000"                 [RB08]="Xiaomi (RB08)"
  [RA67]="Redmi AX5"                    [RA69]="Redmi AX6"
  [RA70]="Xiaomi AX9000"                [RA71]="Redmi AX1800"
  [RA72]="Xiaomi AX6000"                [RA74]="Redmi AX5400"
  [RA80]="Xiaomi AX3000"                [RA81]="Redmi AX3000"
  [RA82]="Xiaomi Mesh System AX3000"    [RM1800]="Redmi AX1800 (RM1800)"
  [R3600]="Xiaomi AIoT Router AX3600"
)

CODES="RD03 RD23 RD15 RD16 RD18 RD08 RC06 RC01 RN02 RD05 RD13 RD01 RD02 RB01 RB03 RB04 RB06 RB08 RA67 RA69 RA70 RA71 RA72 RA74 RA80 RA81 RA82 RM1800 R3600"

printf "model_code\tproduct\tfw_version\tarch\tkey_present\tcab_meshd_sha256\tcab_meshd_size\timage_sha256\tfirmware_url\n" > "$TSV"

extract_meshd() {  # $1 = image, $2 = outdir ; echoes path to cab_meshd or nothing
  local img="$1" out="$2" off sq vol
  rm -rf "$out"; mkdir -p "$out"

  # Case A: squashfs directly inside the image
  off=$(binwalk "$img" 2>/dev/null | grep -i "squashfs filesystem" | head -1 | awk '{print $1}')
  if [ -n "$off" ]; then
    tail -c +$((off+1)) "$img" > "$out/root.sqfs" 2>/dev/null
    if unsquashfs -q -f -d "$out/rootfs" "$out/root.sqfs" "usr/sbin/cab_meshd" >/dev/null 2>&1; then
      [ -f "$out/rootfs/usr/sbin/cab_meshd" ] && { echo "$out/rootfs/usr/sbin/cab_meshd"; return; }
    fi
  fi

  # Case B: UBI container -> volume -> squashfs
  if binwalk "$img" 2>/dev/null | grep -qi "UBI erase count header"; then
    ubireader_extract_images -o "$out/ubi" "$img" >/dev/null 2>&1
    for vol in $(find "$out/ubi" -type f 2>/dev/null); do
      off=$(binwalk "$vol" 2>/dev/null | grep -i "squashfs filesystem" | head -1 | awk '{print $1}')
      [ -z "$off" ] && continue
      tail -c +$((off+1)) "$vol" > "$out/root.sqfs" 2>/dev/null
      if unsquashfs -q -f -d "$out/rootfs" "$out/root.sqfs" "usr/sbin/cab_meshd" >/dev/null 2>&1; then
        [ -f "$out/rootfs/usr/sbin/cab_meshd" ] && { echo "$out/rootfs/usr/sbin/cab_meshd"; return; }
      fi
    done
  fi
}

for CODE in $CODES; do
  lc=$(echo "$CODE" | tr 'A-Z' 'a-z')
  prod="${PRODUCT[$CODE]:-(unmapped)}"
  echo "=== $CODE ($prod) ===" >> "$LOG"

  idx="$WORK/idx_$CODE.html"
  if ! curl -sfL --max-time 40 "https://mirom.ezbox.idv.tw/en/miwifi/$CODE/roms-stable/" -o "$idx"; then
    echo "  no index page" >> "$LOG"
    printf "%s\t%s\tNO_PUBLIC_IMAGE\t-\t-\t-\t-\t-\t-\n" "$CODE" "$prod" >> "$TSV"
    continue
  fi

  url=$(grep -oE "https?://[^\"']*miwifi_${lc}_[^\"']*\.bin" "$idx" \
        | sort -u \
        | sed -E 's/.*_([0-9]+\.[0-9]+\.[0-9]+)\.bin$/\1\t&/' \
        | sort -V | tail -1 | cut -f2)
  if [ -z "$url" ]; then
    echo "  no .bin in index" >> "$LOG"
    printf "%s\t%s\tNO_PUBLIC_IMAGE\t-\t-\t-\t-\t-\t-\n" "$CODE" "$prod" >> "$TSV"
    continue
  fi
  ver=$(echo "$url" | sed -E 's/.*_([0-9]+\.[0-9]+\.[0-9]+)\.bin$/\1/')
  echo "  $ver  $url" >> "$LOG"

  img="$WORK/$CODE.bin"
  if ! curl -sfL --max-time 900 "$url" -o "$img"; then
    echo "  DOWNLOAD FAILED" >> "$LOG"
    printf "%s\t%s\t%s\tDOWNLOAD_FAILED\t-\t-\t-\t-\t%s\n" "$CODE" "$prod" "$ver" "$url" >> "$TSV"
    continue
  fi
  isha=$(sha256sum "$img" | awk '{print $1}')

  meshd=$(extract_meshd "$img" "$WORK/x_$CODE")
  if [ -z "$meshd" ]; then
    echo "  EXTRACT FAILED" >> "$LOG"
    printf "%s\t%s\t%s\tEXTRACT_FAILED\t-\t-\t-\t%s\t%s\n" "$CODE" "$prod" "$ver" "$isha" "$url" >> "$TSV"
    rm -f "$img"; rm -rf "$WORK/x_$CODE"; continue
  fi

  cp "$meshd" "$BINS/${CODE}_${ver}.cab_meshd"
  msha=$(sha256sum "$meshd" | awk '{print $1}')
  msz=$(stat -c%s "$meshd")
  arch=$(file -b "$meshd" | grep -oE "ELF (32|64)-bit [A-Z]+ (pie )?(executable|shared object|LSB [a-z ]*)?[^,]*" | head -1)
  [ -z "$arch" ] && arch=$(file -b "$meshd" | cut -c1-45)
  if grep -aq "$KEY" "$meshd"; then kp="YES"; else kp="no"; fi
  echo "  key=$kp arch=$arch sha=$msha" >> "$LOG"

  printf "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n" \
    "$CODE" "$prod" "$ver" "$arch" "$kp" "$msha" "$msz" "$isha" "$url" >> "$TSV"

  rm -f "$img"; rm -rf "$WORK/x_$CODE"
done

echo "SWEEP COMPLETE" >> "$LOG"
