#!/usr/bin/env bash
# Build the "deploy on a Linux VM" ad: narrated 1080x1350 MP4 plus the static ad images.
#
#   ./build.sh                      full build into ./out
#   VOICE=en-GB-RyanNeural ./build.sh
#
# Needs: ffmpeg, python3 with edge-tts (pip install edge-tts), and Chrome or Edge for rendering the slides.
# Everything runs locally; the only network call is the text-to-speech request.
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"
OUT=${OUT:-out}
VOICE=${VOICE:-en-US-GuyNeural}
RATE=${RATE:--4%}
TTS=${TTS:-$HOME/tts-venv/bin/edge-tts}
CHROME=${CHROME:-}
mkdir -p "$OUT/slides" "$OUT/audio"

# One narration line per slide - what is spoken while that slide is on screen.
LINES=(
"Your FortiGate logged everything today. Nobody read a line of it."
"Vigil turns that syslog into a dashboard, and it installs on one Linux V M in about a minute."
"You need any Linux machine that runs Docker. Two virtual C P Us, two gigabytes of memory. Nothing is installed on the firewall itself."
"Clone the repository and run the installer. It checks Docker and the Compose plugin first."
"Then it checks port five fourteen. If rsyslog already receives your firewall there, Vigil reads that file read only, and nothing on the FortiGate changes."
"It saves the settings, pulls the image, starts the container, and tells you how much log history it has to read and how long that will take."
"Open port eight thousand and eighty, create the admin account, and the install is finished."
"Now you can watch every inbound request live. Each particle is one real log line, and you can click it to read the record."
"Upload a configuration backup and every internet facing rule is graded: who can reach it, what it exposes, and the known exploited vulnerabilities that apply."
"Ask in plain English why something was blocked, and follow it hop by hop across thirty days."
"It is free and open source, self hosted, with no cloud and no telemetry. It reads syslog and never touches your firewall."
"Try it on a spare V M. Link is in the comments."
)

# ---- 1. voice ------------------------------------------------------------------------------------------------
command -v "$TTS" >/dev/null 2>&1 || { echo "edge-tts not found at $TTS - pip install edge-tts"; exit 1; }
DURS=(); FRAMES=()
for i in "${!LINES[@]}"; do
  n=$((i + 1))
  f="$OUT/audio/$n.mp3"
  [ -s "$f" ] || "$TTS" --voice "$VOICE" --rate="$RATE" --text "${LINES[$i]}" --write-media "$f" >/dev/null
  raw=$(ffprobe -v error -show_entries format=duration -of csv=p=0 "$f")
  # Lock every slide to a whole number of frames and pad its narration to exactly that length. Without this the
  # frame-quantised video segments drift away from the audio and captions end up over the wrong slide.
  frames=$(python3 -c "print(max(30, round(($raw + 0.5) * 30)))")
  d=$(python3 -c "print(f'{$frames / 30:.4f}')")
  FRAMES+=("$frames")
  DURS+=("$d")
  pad="$OUT/audio/$n.wav"
  [ -s "$pad" ] || ffmpeg -v error -i "$f" -af "adelay=180|180,apad" -t "$d" -ar 48000 -ac 2 -y "$pad"
  printf 'slide %2d  %5.2fs (%s frames)  %s\n' "$n" "$d" "$frames" "${LINES[$i]:0:52}..."
done

# ---- 2. slides -----------------------------------------------------------------------------------------------
if [ -z "$CHROME" ]; then
  for c in "/mnt/c/Program Files/Google/Chrome/Application/chrome.exe" \
           "/mnt/c/Program Files (x86)/Microsoft/Edge/Application/msedge.exe" \
           "$(command -v google-chrome || true)" "$(command -v chromium || true)"; do
    [ -x "$c" ] && { CHROME=$c; break; }
  done
fi
[ -n "$CHROME" ] || { echo "no Chrome/Edge found - set CHROME=/path/to/chrome"; exit 1; }
HTML=$(readlink -f slides.html)
case "$CHROME" in /mnt/c/*) URLBASE="file:///$(wslpath -w "$HTML" | sed 's#\\#/#g')" ;; *) URLBASE="file://$HTML" ;; esac
for n in $(seq 1 ${#LINES[@]}); do
  png="$OUT/slides/$n.png"
  [ -s "$png" ] && continue
  tmp=$(mktemp -d)
  "$CHROME" --headless=new --disable-gpu --hide-scrollbars --window-size=1080,1350 \
            --screenshot="$(case "$CHROME" in /mnt/c/*) wslpath -w "$tmp/s.png";; *) echo "$tmp/s.png";; esac)" \
            "$URLBASE?s=$n" >/dev/null 2>&1 || true
  [ -s "$tmp/s.png" ] || { echo "slide $n did not render"; exit 1; }
  mv "$tmp/s.png" "$png"; rm -rf "$tmp"
done
echo "slides rendered: $(ls "$OUT/slides" | wc -l)"

# ---- 3. captions (LinkedIn autoplays muted - they carry the message) ------------------------------------------
subs="$OUT/captions.ass"
{
  printf '[Script Info]\nScriptType: v4.00+\nPlayResX: 1080\nPlayResY: 1350\nWrapStyle: 0\n\n[V4+ Styles]\n'
  printf 'Format: Name, Fontname, Fontsize, PrimaryColour, OutlineColour, BackColour, Bold, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding\n'
  printf 'Style: Cap,Segoe UI,44,&H00FFFFFF,&H00000000,&HB0000000,0,3,0,0,2,80,80,120,1\n\n[Events]\n'
  printf 'Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text\n'
  t=0
  for i in "${!LINES[@]}"; do
    d=${DURS[$i]}
    s=$(printf '%.2f' "$t"); e=$(python3 -c "print(f'{$t + $d:.2f}')")
    fmt() { python3 -c "
h=int($1//3600); m=int(($1%3600)//60); s=$1%60
print(f'{h}:{m:02d}:{s:05.2f}')"; }
    # keep captions short: two lines maximum
    txt=$(python3 - "${LINES[$i]}" <<'PY'
import sys, textwrap
t = sys.argv[1].replace('V M', 'VM').replace('C P Us', 'vCPUs')
w = textwrap.wrap(t, 46)
print('\\N'.join(w[:3]))
PY
)
    printf 'Dialogue: 0,%s,%s,Cap,,0,0,0,,%s\n' "$(fmt "$s")" "$(fmt "$e")" "$txt"
    t=$(python3 -c "print($t + $d)")
  done
} > "$subs"

# ---- 4. video ------------------------------------------------------------------------------------------------
: > "$OUT/concat.txt"
for i in "${!LINES[@]}"; do
  n=$((i + 1)); d=${DURS[$i]}
  seg="$OUT/seg$n.mp4"
  # slow push-in keeps a static slide alive; fade at both ends hides the cut
  ffmpeg -v error -loop 1 -i "$OUT/slides/$n.png" \
    -vf "scale=2160:2700,zoompan=z='min(1.06,1.001+0.0008*on)':d=1:x='iw/2-(iw/zoom/2)':y='ih/2-(ih/zoom/2)':s=1080x1350:fps=30,\
fade=t=in:st=0:d=0.35,fade=t=out:st=$(python3 -c "print(max(0,$d-0.35))"):d=0.35,format=yuv420p" \
    -frames:v ${FRAMES[$i]} -c:v libx264 -preset medium -crf 20 -r 30 -y "$seg"
  echo "file 'seg$n.mp4'" >> "$OUT/concat.txt"
done
ffmpeg -v error -f concat -safe 0 -i "$OUT/concat.txt" -c copy -y "$OUT/video-raw.mp4"
: > "$OUT/audio.txt"
for n in $(seq 1 ${#LINES[@]}); do echo "file 'audio/$n.wav'" >> "$OUT/audio.txt"; done   # padded to the slide length
ffmpeg -v error -f concat -safe 0 -i "$OUT/audio.txt" -c:a aac -b:a 192k -y "$OUT/voice.m4a"
ffmpeg -v error -i "$OUT/video-raw.mp4" -i "$OUT/voice.m4a" \
  -vf "subtitles=$subs:fontsdir=/mnt/c/Windows/Fonts" \
  -c:v libx264 -preset slow -crf 20 -pix_fmt yuv420p -c:a aac -b:a 192k -shortest \
  -movflags +faststart -y "$OUT/Vigil-deploy-1080x1350.mp4"

# ---- 5. static ad images -------------------------------------------------------------------------------------
cp "$OUT/slides/2.png" "$OUT/ad-portrait-1080x1350.png"
ffmpeg -v error -i "$OUT/slides/2.png" -vf "crop=1080:1080:0:135" -y "$OUT/ad-square-1080x1080.png"
ffmpeg -v error -i "$OUT/slides/12.png" -vf "crop=1080:565:0:390,scale=1200:627" -y "$OUT/ad-link-1200x627.png"
ffmpeg -v error -ss 1 -i "$OUT/Vigil-deploy-1080x1350.mp4" -frames:v 1 -y "$OUT/video-cover.jpg"

echo
ffprobe -v error -show_entries format=duration,size -of default=nw=1 "$OUT/Vigil-deploy-1080x1350.mp4"
echo "built: $OUT/Vigil-deploy-1080x1350.mp4"
