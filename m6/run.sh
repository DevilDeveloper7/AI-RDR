#!/usr/bin/env bash
# AI-RDR M6 launcher for macOS and Linux.
#   ./run.sh               set up (first run only), start backend + frontend, open the browser
#   ./run.sh --check       only check that Python and Node are installed
#   ./run.sh --setup-only  install dependencies, then exit
#   ./run.sh --no-browser  do not open the browser
#   ./run.sh --stop        stop an M6 that is still running from an earlier start
# Stop everything with Ctrl+C.

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT" || exit 1

VENV="$ROOT/.venv"
LOGS="$ROOT/logs"
PIDFILE="$LOGS/m6.pids"
BACK_PID=""
FRONT_PID=""

if [ -t 1 ]; then B=$'\033[1m'; G=$'\033[32m'; R=$'\033[31m'; Y=$'\033[33m'; N=$'\033[0m'; else B=""; G=""; R=""; Y=""; N=""; fi
say()  { printf '%s\n' "${B}==>${N} $*"; }
ok()   { printf '%s\n' "${G}OK${N}  $*"; }
warn() { printf '%s\n' "${Y}!!${N}  $*"; }
die()  { printf '%s\n' "${R}ERROR${N} $*" >&2; exit 1; }

MODE_CHECK=0; MODE_SETUP=0; MODE_STOP=0; OPEN_BROWSER=1
[ -n "${NO_BROWSER:-}" ] && OPEN_BROWSER=0
for arg in "$@"; do
  case "$arg" in
    --check) MODE_CHECK=1 ;;
    --setup-only) MODE_SETUP=1 ;;
    --stop) MODE_STOP=1 ;;
    --no-browser) OPEN_BROWSER=0 ;;
    -h|--help) sed -n '2,8p' "$0" | sed 's/^# \{0,1\}//; 1s/^/Usage:\n/'; exit 0 ;;
    *) die "Unknown option: $arg (try --help)" ;;
  esac
done

read_env() { # read_env KEY DEFAULT: value from .env (without sourcing it), else DEFAULT
  local v=""
  if [ -f "$ROOT/.env" ]; then
    v=$(grep -E "^[[:space:]]*$1=" "$ROOT/.env" | tail -n1 | sed -E "s/^[[:space:]]*$1=//; s/[[:space:]]+#.*$//; s/^[\"']//; s/[\"']$//")
  fi
  if [ -n "$v" ]; then printf '%s' "$v"; else printf '%s' "$2"; fi
}

hash_file() { if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | cut -d' ' -f1; else sha256sum "$1" | cut -d' ' -f1; fi; }

find_python() {
  local c
  for c in python3.13 python3.12 python3.11 python3; do
    if command -v "$c" >/dev/null 2>&1 && "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
      printf '%s' "$c"; return 0
    fi
  done
  return 1
}

check_prerequisites() {
  PY=$(find_python) || die "Python 3.11 or newer was not found.
       macOS:  brew install python@3.12
       Ubuntu: sudo apt install python3 python3-venv python3-pip"
  ok "Python: $($PY --version 2>&1)"
  command -v node >/dev/null 2>&1 || die "Node.js was not found.
       macOS:  brew install node@20
       Ubuntu: sudo apt install nodejs npm   (Node 18 or newer)"
  command -v npm >/dev/null 2>&1 || die "npm was not found. It normally installs together with Node.js."
  local major; major=$(node -p "process.versions.node.split('.')[0]")
  [ "$major" -ge 18 ] || die "Node.js 18 or newer is required (found $(node -v))."
  ok "Node: $(node -v), npm $(npm -v)"
}

setup_backend() {
  if [ -x "$VENV/bin/python" ] && ! "$VENV/bin/python" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null; then
    die "The existing .venv uses an old Python. Delete it (rm -rf .venv) and run again."
  fi
  if [ ! -x "$VENV/bin/python" ]; then
    say "Setting up Python environment (.venv)..."
    "$PY" -m venv "$VENV" || die "Could not create the virtual environment. On Ubuntu try: sudo apt install python3-venv"
  fi
  local want have
  want=$(hash_file backend/requirements.txt); have=$(cat "$VENV/.m6-requirements" 2>/dev/null || true)
  if [ "$want" != "$have" ]; then
    say "Installing backend dependencies..."
    "$VENV/bin/python" -m pip install -q -r backend/requirements.txt || die "pip install failed. Check your internet connection."
    printf '%s' "$want" > "$VENV/.m6-requirements"
  else
    ok "Backend dependencies already installed"
  fi
}

setup_frontend() {
  local want have lock=frontend/package-lock.json
  [ -f "$lock" ] || lock=frontend/package.json
  want=$(hash_file "$lock"); have=$(cat frontend/node_modules/.m6-deps 2>/dev/null || true)
  if [ ! -d frontend/node_modules ] || [ "$want" != "$have" ]; then
    say "Installing frontend dependencies (this can take a minute)..."
    (cd frontend && npm install --no-audit --no-fund --loglevel=error) || die "npm install failed. Check your internet connection."
    printf '%s' "$want" > frontend/node_modules/.m6-deps
  else
    ok "Frontend dependencies already installed"
  fi
}

stop_previous() { # stop M6 processes left over from an earlier start (for example if the terminal was killed)
  [ -f "$PIDFILE" ] || return 1
  local pid cmd stopped=1
  for pid in $(cat "$PIDFILE"); do
    cmd=$(ps -p "$pid" -o command= 2>/dev/null)
    case "$cmd" in
      *backend/run.py*|*vite*) pkill -P "$pid" 2>/dev/null; kill "$pid" 2>/dev/null; stopped=0 ;;
    esac
  done
  rm -f "$PIDFILE"
  [ "$stopped" = 0 ] && sleep 1
  return $stopped
}

port_owner() { command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:"$1" -sTCP:LISTEN 2>/dev/null | tail -n +2 | head -n 3; }

port_in_use() { "$VENV/bin/python" -c "import socket,sys; s=socket.socket(); s.settimeout(0.5); sys.exit(0 if s.connect_ex(('127.0.0.1', int(sys.argv[1])))==0 else 1)" "$1"; }
http_ok() { "$VENV/bin/python" -c "import sys,urllib.request; urllib.request.urlopen(sys.argv[1], timeout=2)" "$1" >/dev/null 2>&1; }
wait_http() { # wait_http URL PID LABEL
  local i=0
  while [ $i -lt 80 ]; do
    http_ok "$1" && return 0
    kill -0 "$2" 2>/dev/null || return 1
    sleep 0.5; i=$((i + 1))
  done
  return 1
}

cleanup() {
  trap - EXIT INT TERM HUP
  rm -f "$PIDFILE"
  if [ -n "$BACK_PID$FRONT_PID" ]; then
    printf '\n'; say "Stopping M6..."
    local pid
    for pid in $FRONT_PID $BACK_PID; do
      pkill -P "$pid" 2>/dev/null
      kill "$pid" 2>/dev/null
    done
    local i=0
    while [ $i -lt 10 ]; do
      kill -0 "$FRONT_PID" 2>/dev/null || kill -0 "$BACK_PID" 2>/dev/null || break
      sleep 0.3; i=$((i + 1))
    done
    for pid in $FRONT_PID $BACK_PID; do kill -9 "$pid" 2>/dev/null; done
    wait 2>/dev/null
    ok "Backend and frontend stopped."
  fi
}

# ---------------------------------------------------------------- main
printf '%s\n' "${B}AI-RDR  M6 Dashboard and Integration${N}"
check_prerequisites
[ "$MODE_CHECK" = 1 ] && { ok "Prerequisites are fine."; exit 0; }

if [ "$MODE_STOP" = 1 ]; then
  if stop_previous; then ok "Stopped the earlier M6 run."; else ok "No earlier M6 run was found (nothing to stop)."; fi
  exit 0
fi

if [ ! -f "$ROOT/.env" ] && [ -f "$ROOT/.env.example" ]; then
  cp "$ROOT/.env.example" "$ROOT/.env"; ok "Created .env from .env.example"
fi
setup_backend
setup_frontend
[ "$MODE_SETUP" = 1 ] && { ok "Setup complete."; exit 0; }

BACK_PORT=$(read_env PORT 5001); BACK_HOST=$(read_env HOST 127.0.0.1); FRONT_PORT="${M6_FRONTEND_PORT:-5173}"
stop_previous && ok "Stopped an earlier M6 run that was still running."
for p in "$BACK_PORT" "$FRONT_PORT"; do
  if port_in_use "$p"; then
    owner=$(port_owner "$p")
    die "Port $p is already in use${owner:+ by:
$owner}
       If that is an old M6 (or Flask/Vite) process, stop it with:  kill \$(lsof -ti :$p)
       Otherwise change PORT in .env (backend) or set M6_FRONTEND_PORT (frontend)."
  fi
done

mkdir -p "$LOGS"
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

say "Starting M6..."
PORT="$BACK_PORT" HOST="$BACK_HOST" "$VENV/bin/python" backend/run.py >"$LOGS/backend.log" 2>&1 &
BACK_PID=$!
echo "$BACK_PID" > "$PIDFILE"
BACK_URL="http://$BACK_HOST:$BACK_PORT"
if ! wait_http "$BACK_URL/api/v1/health" "$BACK_PID"; then
  warn "The backend did not start. Last log lines:"; tail -n 15 "$LOGS/backend.log"; exit 1
fi
ok "Backend running"

(cd frontend && VITE_DEV_API_TARGET="$BACK_URL" exec ./node_modules/.bin/vite --port "$FRONT_PORT" --strictPort >"$LOGS/frontend.log" 2>&1) &
FRONT_PID=$!
echo "$BACK_PID $FRONT_PID" > "$PIDFILE"
APP_URL="http://localhost:$FRONT_PORT"
if ! wait_http "$APP_URL" "$FRONT_PID"; then
  warn "The frontend did not start. Last log lines:"; tail -n 15 "$LOGS/frontend.log"; exit 1
fi
ok "Frontend running"

printf '\n%s\n' "${B}M6 is running${N}"
printf '  App:       %s\n  Backend:   %s\n  API health: %s/api/v1/health\n  Logs:      %s\n\n' "$APP_URL" "$BACK_URL" "$BACK_URL" "$LOGS"
printf 'Press Ctrl+C to stop both.\n'

if [ "$OPEN_BROWSER" = 1 ]; then
  if command -v open >/dev/null 2>&1; then open "$APP_URL" >/dev/null 2>&1 &
  elif command -v xdg-open >/dev/null 2>&1; then xdg-open "$APP_URL" >/dev/null 2>&1 &
  else warn "Could not open a browser automatically. Open $APP_URL yourself."; fi
fi

while kill -0 "$BACK_PID" 2>/dev/null && kill -0 "$FRONT_PID" 2>/dev/null; do sleep 1; done
kill -0 "$BACK_PID" 2>/dev/null || { warn "The backend stopped unexpectedly. Last log lines:"; tail -n 15 "$LOGS/backend.log"; }
kill -0 "$FRONT_PID" 2>/dev/null || { warn "The frontend stopped unexpectedly. Last log lines:"; tail -n 15 "$LOGS/frontend.log"; }
exit 1
