#!/usr/bin/env bash
# Vigil installer - run from the cloned repository:   ./install.sh
#
# 1. checks Docker Engine and the Compose v2 plugin
# 2. decides how FortiGate logs reach Vigil:
#      * port 514 free                    -> built-in syslog receiver on 514 (VIGIL_INPUT=receiver)
#      * port 514 already used by a syslog server that writes FortiGate logs to a file (rsyslog, syslog-ng, ...)
#                                         -> Vigil reads that file read-only, the existing server keeps working
#                                            (VIGIL_INPUT=file) - nothing on the FortiGate or the syslog server changes
#      * port 514 used by something else  -> built-in receiver on another port (FortiGate needs `set port <n>`)
#    The check uses ss, netstat, /proc/net or a real bind - whatever this machine has. A port that cannot be checked
#    is never treated as free.
# 3. writes the choice to .env and runs `docker compose up -d`; should Docker still report "address already in use",
#    the installer reconfigures itself (existing log file, or another port) and retries once
#
# Options:
#   -y, --yes            do not ask, accept the detected setup
#   --dry-run            only show what would be configured
#   --no-start           write .env but do not start the container
#   --port N             syslog port the FortiGate sends to on this host (default 514)
#   --log-file PATH      use this existing syslog file (skips detection)
#   --receiver           always use the built-in receiver
#   --no-pull            do not refresh the container image before starting
#   --scan-dir DIR       where to look for FortiGate log files (default /var/log)
set -euo pipefail
cd "$(dirname "$(readlink -f "$0")")"

YES=0; DRY=0; START=1; PULL=1; PORT=514; LOG_FILE=""; FORCE_RECEIVER=0; SCAN_DIR=/var/log
while [ $# -gt 0 ]; do
  case "$1" in
    -y|--yes) YES=1 ;;
    --dry-run) DRY=1; START=0 ;;
    --no-start) START=0 ;;
    --port) PORT=$2; shift ;;
    --log-file) LOG_FILE=$2; shift ;;
    --receiver) FORCE_RECEIVER=1 ;;
    --no-pull) PULL=0 ;;
    --scan-dir) SCAN_DIR=$2; shift ;;
    -h|--help) sed -n '2,/^set -euo/p' "$0" | sed '$d' | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown option: $1 (see ./install.sh --help)"; exit 2 ;;
  esac
  shift
done

if [ -t 1 ]; then B=$'\e[1m'; G=$'\e[32m'; Y=$'\e[33m'; R=$'\e[31m'; N=$'\e[0m'; else B=; G=; Y=; R=; N=; fi
say()  { printf '%s\n' "$*"; }
ok()   { printf '%s✓%s %s\n' "$G" "$N" "$*"; }
warn() { printf '%s!%s %s\n' "$Y" "$N" "$*"; }
die()  { printf '%s✗%s %s\n' "$R" "$N" "$*" >&2; exit 1; }
ask()  {   # ask "question" -> 0 = yes
  [ $YES = 1 ] && return 0
  [ -t 0 ] || return 0
  local a; read -r -p "$1 [Y/n] " a; [[ ! "$a" =~ ^[Nn] ]]
}

# sudo is only used to read log files and to see which process owns a port: passwordless sudo, or a single prompt
# in an interactive shell; otherwise everything runs with the current user's rights (members of "adm" can read /var/log)
if [ "$(id -u)" = 0 ] || ! command -v sudo >/dev/null 2>&1; then SUDO=""
elif sudo -n true 2>/dev/null; then SUDO="sudo -n"
elif [ -t 0 ]; then SUDO="sudo"
else SUDO=""; fi
priv() { if [ -n "$SUDO" ]; then $SUDO "$@"; else "$@"; fi; }

say "${B}Vigil installer${N}"

# ---- 1. Docker -------------------------------------------------------------------------------------------------
DOCKER=(docker)
if [ $DRY = 0 ]; then
  command -v docker >/dev/null 2>&1 || die "Docker is not installed. Install it first:
    curl -fsSL https://get.docker.com | sudo sh
  or on Ubuntu:  sudo apt install -y docker.io docker-compose-v2
  Details: docs/INSTALL.md#install-docker"
  if ! docker info >/dev/null 2>&1; then
    if [ -n "$SUDO" ] && $SUDO docker info >/dev/null 2>&1; then
      DOCKER=($SUDO docker)
      warn "your user cannot use Docker directly - using sudo (to avoid it: sudo usermod -aG docker \"\$USER\", then log in again)"
    else
      die "Docker is installed but not running or not reachable: sudo systemctl enable --now docker"
    fi
  fi
  "${DOCKER[@]}" compose version >/dev/null 2>&1 || die "The Docker Compose v2 plugin is missing ('docker compose' does not work).
    Ubuntu packages:  sudo apt install -y docker-compose-v2
    Docker packages:  sudo apt install -y docker-compose-plugin
  Details: docs/INSTALL.md#install-docker"
  ok "Docker $("${DOCKER[@]}" version --format '{{.Server.Version}}' 2>/dev/null || echo '?') with $("${DOCKER[@]}" compose version --short 2>/dev/null | sed 's/^/Compose /')"
fi

# ---- helpers -----------------------------------------------------------------------------------------------------
# Is UDP or TCP port $1 taken? -> 0 = in use, 1 = free, 2 = could not tell.
# Several methods, because none of them works everywhere: ss/netstat can be missing or too old for the filter syntax
# (some builds have no "-H"), /proc/net needs no tool at all, and binding the port is exactly what Docker does.
# A port that cannot be checked is never called free - that assumption is what let the container fail later with
# "failed to bind host port 0.0.0.0:514: address already in use".
PORT_CHECK_METHOD=""
port_listed() {   # 0 = found in a listener table, 1 = tables read but port absent, 2 = no table could be read
  local p=$1 out="" found=1 read_any=1 f line hexport st rows first
  if command -v ss >/dev/null 2>&1 && out=$(ss -lnut 2>/dev/null) && [ -n "$out" ]; then
    PORT_CHECK_METHOD=ss
  elif command -v netstat >/dev/null 2>&1 && out=$(netstat -lnut 2>/dev/null) && [ -n "$out" ]; then
    PORT_CHECK_METHOD=netstat
  else
    out=""
  fi
  # both tools put the local address in column 4 ("0.0.0.0:514", "[::]:514", "*:514")
  [ -n "$out" ] && printf '%s\n' "$out" | awk 'NR > 1 { print $4 }' | grep -qE "[:.]$p\$" && return 0
  # kernel tables: "sl local_address rem_address st ..." with the port in hex; 0A = TCP listening
  for f in /proc/net/tcp /proc/net/tcp6 /proc/net/udp /proc/net/udp6; do
    [ -r "$f" ] || continue
    rows=0; first=1
    while read -r _ line _ st _; do          # read with bash only: no tail/awk needed, so a bare PATH still works
      if [ "$first" = 1 ]; then first=0; continue; fi         # header row
      rows=$((rows + 1))
      hexport=${line##*:}
      [ "$hexport" = "$line" ] && continue
      case $hexport in *[!0-9A-Fa-f]*|"") continue ;; esac
      case "$f" in *tcp*) [ "$st" = 0A ] || continue ;; esac  # 0A = listening; UDP sockets are all "open"
      [ "$((16#$hexport))" = "$p" ] && { found=0; break; }
    done < "$f"
    [ "$rows" -gt 0 ] && read_any=0          # only a table we really read counts as evidence
    [ $found = 0 ] && break
  done
  if [ $found = 0 ]; then
    [ -n "$PORT_CHECK_METHOD" ] || PORT_CHECK_METHOD=/proc/net
    return 0
  fi
  [ -n "$out" ] && return 1
  [ $read_any = 0 ] && { PORT_CHECK_METHOD=/proc/net; return 1; }
  return 2
}
port_bind_test() {   # 0 = in use, 1 = free (or only root may bind it), 2 = cannot test
  command -v python3 >/dev/null 2>&1 || return 2
  python3 - "$1" >/dev/null 2>&1 <<'PY'
import errno, socket, sys
port, busy = int(sys.argv[1]), False
for typ in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
    s = socket.socket(socket.AF_INET, typ)
    try:
        s.bind(('0.0.0.0', port))              # no SO_REUSEADDR: bind exactly like Docker's port proxy
    except OSError as e:
        busy = busy or e.errno == errno.EADDRINUSE     # EACCES only means "not root" - the port itself is free
    finally:
        s.close()
sys.exit(3 if busy else 0)
PY
  case $? in 3) return 0 ;; 0) return 1 ;; *) return 2 ;; esac
}
port_in_use() {
  local p=$1 rc
  port_listed "$p"; rc=$?
  [ $rc = 0 ] && return 0
  port_bind_test "$p"
  case $? in
    0) PORT_CHECK_METHOD=bind; return 0 ;;
    1) [ $rc = 2 ] && PORT_CHECK_METHOD=bind; return 1 ;;
    *) return "$rc" ;;
  esac
}
port_owners() {   # names of the processes on port $1, e.g. "rsyslogd" (needs sudo to see other users' sockets)
  command -v ss >/dev/null 2>&1 || return 0
  { priv ss -H -lnup "sport = :$1"; priv ss -H -lntp "sport = :$1"; } 2>/dev/null |
    grep -oE 'users:\(\("[^"]+"' | cut -d'"' -f2 | sort -u | paste -sd, - || true
}
vigil_owns_port() {   # the running Vigil container itself publishes the port (re-running the installer)
  [ $DRY = 0 ] || return 1
  "${DOCKER[@]}" ps --filter name='^vigil$' --format '{{.Ports}}' 2>/dev/null | grep -qE "[:.]$1->5514"
}
free_port() {
  local p st
  for p in 5514 15514 25514 35514; do
    st=0; port_in_use "$p" || st=$?
    [ "$st" = 1 ] && { echo "$p"; return; }        # only a port proven free
  done
  echo 45514
}
FORTI_RE='CEF: ?0\|Fortinet\|Forti|logid="?[0-9]{10}"? '
find_forti_file() {   # prints "<count> <path>" of the file with most FortiGate lines among recently written files
  local f n best=0 bestf=""
  while IFS= read -r f; do
    n=$(priv tail -c 2000000 "$f" 2>/dev/null | grep -cE "$FORTI_RE" || true)
    if [ "${n:-0}" -gt "$best" ]; then best=$n; bestf=$f; fi
  done < <(priv find "$SCAN_DIR" -maxdepth 3 -type f -size +0 -mmin -30 \
             ! -name '*.gz' ! -name '*.xz' ! -name '*.bz2' ! -name '*.zip' ! -name '*.[0-9]' ! -name '*.journal' \
             ! -name 'wtmp' ! -name 'btmp' ! -name 'lastlog' ! -name 'faillog' ! -path '*/journal/*' 2>/dev/null)
  [ -n "$bestf" ] && echo "$best $bestf"
}
env_set() {   # set KEY=VALUE in .env (replacing an existing or commented-out line)
  local k=$1 v=$2
  if [ $DRY = 1 ]; then say "    $k=$v"; return; fi
  [ -f .env ] || cp .env.example .env
  if grep -qE "^#? ?$k=" .env; then
    awk -v k="$k" -v v="$v" 'BEGIN{d=0} { if (!d && $0 ~ "^#? ?"k"=") { print k"="v; d=1 } else print }' .env > .env.tmp && mv .env.tmp .env
  else
    printf '%s=%s\n' "$k" "$v" >> .env
  fi
}
write_input_env() {   # log-source settings, written the same way on the first attempt and on a retry
  env_set VIGIL_INPUT "$MODE"
  env_set VIGIL_SYSLOG_PORT "$SYSLOG_PORT"
  if [ "$MODE" = file ]; then
    env_set VIGIL_HOST_LOG_DIR "$(dirname "$LOG_FILE")"
    env_set VIGIL_LOG_NAME "$(basename "$LOG_FILE")"
    env_set VIGIL_HOST_LOG_GID "$GID"
    env_set VIGIL_HOST_SYSLOG_PORT "$PORT"
  fi
}

# ---- 2. how do logs reach Vigil? -----------------------------------------------------------------------------------
use_existing_syslog() {   # port $PORT is taken (or unverifiable): prefer reading the file the other server writes
  say "Looking for FortiGate logs that the existing syslog server writes under $SCAN_DIR ..."
  found=$(find_forti_file || true)
  if [ -n "$found" ]; then
    LOG_FILE=${found#* }
    ok "found ${found%% *} FortiGate log lines in the last 2 MB of ${B}$LOG_FILE${N}"
    say "  The FortiGate is already integrated with this machine. Vigil will read this file read-only;"
    say "  the existing syslog server and the FortiGate stay exactly as they are."
    if ask "Use $LOG_FILE?"; then MODE=file; else LOG_FILE=""; fi
  else
    warn "no FortiGate log lines found in files written during the last 30 minutes under $SCAN_DIR"
  fi
  if [ "$MODE" != file ]; then
    SYSLOG_PORT=$(free_port)
    say "  Vigil's own receiver will listen on port ${B}$SYSLOG_PORT${N} instead (on the FortiGate: set port $SYSLOG_PORT)."
    say "  If the FortiGate logs are in a file this script did not find: ./install.sh --log-file /path/to/file"
    ask "Continue with the built-in receiver on port $SYSLOG_PORT?" || die "stopped - nothing was changed"
  fi
}

MODE=receiver; SYSLOG_PORT=$PORT
PORT_STATE=0; port_in_use "$PORT" || PORT_STATE=$?
if [ -n "$LOG_FILE" ]; then
  MODE=file
elif [ $FORCE_RECEIVER = 1 ]; then
  MODE=receiver
elif [ "$PORT_STATE" = 0 ]; then
  if vigil_owns_port "$PORT"; then
    ok "port $PORT is already published by the running Vigil container"
  else
    owners=$(port_owners "$PORT")
    say "Port $PORT is already in use on this machine${owners:+ by ${B}${owners}${N}} (detected via $PORT_CHECK_METHOD)."
    use_existing_syslog
  fi
elif [ "$PORT_STATE" = 2 ]; then
  warn "could not check whether port $PORT is in use (no usable ss, netstat, /proc/net or python3 here)"
  use_existing_syslog
else
  ok "port $PORT is free - Vigil's built-in receiver will listen on it"
fi

GID=4
prepare_file_mode() {   # can the container read the chosen file? sets GID and keeps the receiver off the host's port
  priv test -f "$LOG_FILE" || die "$LOG_FILE does not exist"
  LOG_FILE=$(readlink -f "$LOG_FILE")
  read -r fgid fmode < <(priv stat -c '%g %a' "$LOG_FILE")
  # the container runs as uid 10001 with one extra group: readable if the group or everyone may read the file
  if (( (8#$fmode & 8#040) != 0 )); then
    GID=$fgid
    ok "the container can read it through group $(getent group "$fgid" | cut -d: -f1 || echo "$fgid") (mode $fmode)"
  elif (( (8#$fmode & 8#004) != 0 )); then
    ok "the file is world-readable (mode $fmode)"
  else
    warn "$LOG_FILE is not group- or world-readable (mode $fmode) - Vigil could not read it."
    say  "  Make the syslog server create it group-readable, e.g. for rsyslog in /etc/rsyslog.d/*.conf:"
    say  "      \$FileGroup adm"
    say  "      \$FileCreateMode 0640"
    say  "  then: sudo systemctl restart rsyslog   (see docs/INSTALL.md, \"Existing syslog server\")"
  fi
  # the directory is mounted too (rotated files live next to the live one): it must be listable by that group or everyone
  read -r dgid dmode < <(priv stat -c '%g %a' "$(dirname "$LOG_FILE")")
  if ! { [ "$dgid" = "$GID" ] && (( (8#$dmode & 8#050) == 8#050 )); } && (( (8#$dmode & 8#005) != 8#005 )); then
    warn "$(dirname "$LOG_FILE") (mode $dmode) cannot be listed by the container - rotated files and the live file may be invisible."
    say  "  Fix: sudo chmod o+rx $(dirname "$LOG_FILE")   or put the syslog file in a directory readable by group $GID"
  fi
  SYSLOG_PORT=$(free_port)                       # keep the container's receiver port off the one the host server uses
}
if [ "$MODE" = file ]; then prepare_file_mode; fi

# ---- 3. write .env and start ---------------------------------------------------------------------------------------
[ $DRY = 1 ] && say "Would write to .env:"
write_input_env
[ $DRY = 1 ] && exit 0
ok "settings saved in .env ($MODE input)"
[ $START = 1 ] || { say "Start later with: docker compose up -d"; exit 0; }

# `docker compose up -d` only pulls when no local image exists, so an older image left from a previous install would
# keep running - including versions that predate settings written above. Refresh it first; failure is not fatal
# (offline installs, or a locally built image).
if [ $PULL = 1 ]; then
  say "Fetching the current image ..."
  "${DOCKER[@]}" compose pull -q 2>/dev/null || warn "could not fetch a newer image - using the one already on this machine"
fi

OUT=$(mktemp); trap 'rm -f "$OUT"' EXIT
start_stack() {
  local rc
  set +e
  "${DOCKER[@]}" compose up -d 2>&1 | tee "$OUT"
  rc=${PIPESTATUS[0]}
  set -e
  return "$rc"
}
HTTP_PORT=$(grep -E '^VIGIL_HTTP_PORT=' .env 2>/dev/null | cut -d= -f2); HTTP_PORT=${HTTP_PORT:-8080}
if ! start_stack; then
  # Last safety net: a port looked free but the bind failed anyway (a listener no check could see, another
  # container, or something that started in between) - reconfigure instead of leaving a half-finished install.
  if grep -qiE 'address already in use|port is already allocated' "$OUT"; then
    busy=$(grep -oE '(0\.0\.0\.0|\[::\]|host port [0-9.]*):[0-9]+' "$OUT" | grep -oE '[0-9]+$' | head -1)
    busy=${busy:-$SYSLOG_PORT}
    warn "port $busy is in use after all - reconfiguring and retrying"
    if [ "$busy" = "$HTTP_PORT" ]; then
      for p in 8081 8088 8090 9090 18080; do
        st=0; port_in_use "$p" || st=$?
        [ "$st" = 1 ] && { HTTP_PORT=$p; break; }
      done
      env_set VIGIL_HTTP_PORT "$HTTP_PORT"
      say "  the web port was taken - Vigil's UI will listen on ${B}$HTTP_PORT${N}"
    else
      MODE=receiver; LOG_FILE=""
      use_existing_syslog                       # prefers the existing syslog file, else a free receiver port
      if [ "$MODE" = file ]; then prepare_file_mode; fi
      write_input_env
    fi
    start_stack || die "could not start Vigil - see the output above and docs/TROUBLESHOOTING.md"
  else
    die "could not start Vigil - see the output above and docs/TROUBLESHOOTING.md"
  fi
fi
say "Waiting for Vigil to become healthy ..."
for _ in $(seq 40); do
  st=$("${DOCKER[@]}" inspect -f '{{.State.Health.Status}}' vigil 2>/dev/null || true)
  [ "$st" = healthy ] && break
  sleep 3
done
[ "${st:-}" = healthy ] && ok "Vigil is running" || warn "Vigil did not report healthy yet - check: docker compose logs vigil"
ip=$(hostname -I 2>/dev/null | awk '{print $1}')
http=$(grep -E '^VIGIL_HTTP_PORT=' .env 2>/dev/null | cut -d= -f2); http=${http:-8080}
say ""
say "${B}Open http://${ip:-<this-host>}:$http${N} and create the administrator account."
if [ "$MODE" = file ]; then
  say "Vigil reads $LOG_FILE - no change is needed on the FortiGate."
else
  say "Then point the FortiGate at this machine, port $SYSLOG_PORT (the page shows the exact commands)."
fi
