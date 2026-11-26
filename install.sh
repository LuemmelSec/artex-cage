#!/usr/bin/env bash
#
# One-shot installer for the ARTEX cage.
#
#   sudo ./install.sh              # install the cage, build + start ARTEX, print the setup token
#   sudo ./install.sh --no-up      # install the cage only, do not build/start ARTEX
#   sudo ./install.sh --allow-model HOST:PORT  # allow a private model endpoint and recreate ARTEX
#   sudo ./install.sh --uninstall
#
# Safe to re-run: config, token and .env are only created when missing.

set -Eeuo pipefail

export PATH="/usr/local/sbin:/usr/sbin:/sbin:${PATH:-/usr/bin:/bin}"

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ARTEX_REPO="https://github.com/BaaRai/ARTEX.git"
ARTEX_URL="http://127.0.0.1:8787"
TOKEN_WAIT="${ARTEX_TOKEN_WAIT:-300}"   # seconds to wait for ARTEX to print its setup token

info() { printf '\033[36m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

# Never die silently: say which command failed and where.
trap 'rc=$?; printf "\033[31m[x]\033[0m install.sh failed (exit %s) at line %s: %s\n" "$rc" "$LINENO" "$BASH_COMMAND" >&2' ERR

randstr() { python3 -c 'import secrets,string,sys;a=string.ascii_letters+string.digits;print("".join(secrets.choice(a) for _ in range(int(sys.argv[1]))))' "$1"; }

normalize_model_endpoint() {
  python3 - "$1" <<'PY'
import re
import sys
from urllib.parse import urlsplit

value = sys.argv[1]
try:
    if not value or any(c.isspace() for c in value):
        raise ValueError("enter a hostname or IPv4 address, optionally with a port")
    if "://" not in value:
        value = "http://" + value
    url = urlsplit(value)
    if (url.scheme not in ("http", "https") or not url.hostname or
            url.username is not None or url.password is not None or
            url.query or url.fragment or url.netloc.endswith(":") or
            not re.fullmatch(r"[a-zA-Z0-9.-]+", url.hostname) or
            not re.fullmatch(r"[a-zA-Z0-9._~/-]*", url.path)):
        raise ValueError("use an HTTP(S) URL or hostname:port without credentials, query, or fragment")
    port = url.port if url.port is not None else (443 if url.scheme == "https" else 80)
    if port < 1:
        raise ValueError("port must be between 1 and 65535")
    host = url.hostname.lower()
    authority = host + (":" + str(url.port) if url.port is not None else "")
    path = url.path.rstrip("/") or "/v1"
    print(url.scheme + "://" + authority + path)
    print("%s:%s" % (host, port))
except ValueError as exc:
    print("Invalid model endpoint: %s" % exc, file=sys.stderr)
    sys.exit(1)
PY
}

add_private_model_endpoint() {
  python3 - "$1" "$2" <<'PY'
import os
import re
import sys
import tempfile

path, endpoint = sys.argv[1:]
key = "ARTEX_LLM_PRIVATE_ENDPOINTS"
with open(path, "r", encoding="utf-8", newline="") as fh:
    lines = fh.readlines()
pattern = re.compile(r"^\s*(?:export\s+)?" + key + r"\s*=(.*?)(\r?\n)?$")
matches = [(i, pattern.match(line)) for i, line in enumerate(lines)]
matches = [(i, match) for i, match in matches if match]
if len(matches) > 1:
    sys.exit("Multiple %s entries in .env; resolve them before continuing" % key)
if matches:
    index, match = matches[0]
    value = match.group(1).strip()
    parsed = re.fullmatch(r'''(?:"([^"]*)"|'([^']*)'|([^#]*?))\s*(#.*)?''', value)
    if not parsed:
        sys.exit("Cannot safely update %s in .env; edit it manually" % key)
    entries = [item.strip() for item in (parsed.group(1) or parsed.group(2) or parsed.group(3) or "").split(",") if item.strip()]
    if any(re.search(r"""[\s#'"\\$]""", item) for item in entries):
        sys.exit("Cannot safely update %s in .env; edit it manually" % key)
    if endpoint.lower() in (item.lower() for item in entries):
        sys.exit(0)
    entries.append(endpoint)
    comment = " " + parsed.group(4) if parsed.group(4) else ""
    lines[index] = "%s=%s%s%s" % (key, ",".join(entries), comment, match.group(2) or "\n")
else:
    if lines and not lines[-1].endswith(("\n", "\r")):
        lines[-1] += "\n"
    lines.append("%s=%s\n" % (key, endpoint))
stat = os.stat(path)
fd, tmp = tempfile.mkstemp(prefix=".artex-env-", dir=os.path.dirname(os.path.abspath(path)))
try:
    os.fchmod(fd, stat.st_mode & 0o7777)
    os.fchown(fd, stat.st_uid, stat.st_gid)
    with os.fdopen(fd, "w", encoding="utf-8", newline="") as fh:
        fd = -1
        fh.writelines(lines)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)
finally:
    if fd != -1:
        os.close(fd)
    if os.path.exists(tmp):
        os.unlink(tmp)
PY
}

MODE="up"
case "${1:-}" in
  ""|--up)     MODE="up" ;;
  --no-up)     MODE="no-up" ;;
  --uninstall) MODE="uninstall" ;;
  --allow-model) MODE="allow-model" ;;
  -h|--help)   sed -n '3,10p' "$0"; exit 0 ;;
  *)           die "unknown option: $1 (use --no-up, --allow-model, --uninstall)" ;;
esac

[ "$(uname -s)" = "Linux" ] || die "Linux only (nftables, conntrack, systemd)"
[ "$(id -u)" -eq 0 ] || die "run as root (sudo ./install.sh)"

# --------------------------------------------------------------------- remove
if [ "$MODE" = "uninstall" ]; then
  info "stopping and removing the egress daemon"
  systemctl disable --now artex-egressd.service 2>/dev/null || true
  rm -f /etc/systemd/system/artex-egressd.service
  systemctl daemon-reload
  /usr/bin/python3 /opt/artex-egress/egressd.py --teardown 2>/dev/null || true
  rm -rf /opt/artex-egress /var/lib/artex-egress
  ok "daemon removed. /etc/artex-lab and the lab directory were kept."
  exit 0
fi

if [ "$MODE" = "allow-model" ]; then
  [ "$#" -le 2 ] || die "usage: sudo ./install.sh --allow-model [HOST:PORT or URL]"
  [ -f "$LAB_DIR/.env" ] || die ".env not found; run the installer first"
  command -v python3 >/dev/null || die "python3 not found; run the installer first"
  command -v docker >/dev/null || die "Docker not found"
  docker compose version >/dev/null 2>&1 || die "Docker Compose plugin is unavailable"
  systemctl is-active --quiet artex-egressd.service \
    || die "egress daemon is not running; start it before recreating ARTEX"
  endpoint="${2:-}"
  if [ -z "$endpoint" ]; then
    [ -t 0 ] || die "provide the model endpoint as an argument when running non-interactively"
    read -r -p "Model server hostname:port or URL: " endpoint || die "no model endpoint entered"
  fi
  normalized="$(normalize_model_endpoint "$endpoint")" || die "invalid model endpoint"
  model_hostport="${normalized#*$'\n'}"
  add_private_model_endpoint "$LAB_DIR/.env" "$model_hostport" \
    || die "could not update the private model endpoint list"
  info "authorized $model_hostport for ARTEX model listing; recreating ARTEX"
  ( cd "$LAB_DIR" && docker compose up -d --no-deps artex ) \
    || die "could not recreate ARTEX; the endpoint is saved in .env"
  ok "enter your model URL in ARTEX and approve its destination in the egress console"
  exit 0
fi

# ------------------------------------------------------------------ preflight
command -v systemctl >/dev/null || die "systemd is required"
command -v apt-get >/dev/null || die "apt-get not found — this installer targets Debian/Ubuntu"
[ -d /run/systemd/system ] || die "systemd must be running as the init system"
[ -r /etc/os-release ] || die "cannot identify the operating system (/etc/os-release missing)"
. /etc/os-release
case "${ID:-}" in
  debian|ubuntu) docker_distro="$ID" ;;
  *) die "automatic dependency installation supports Debian and Ubuntu, not ${ID:-unknown}" ;;
esac
docker_codename="${UBUNTU_CODENAME:-${VERSION_CODENAME:-}}"
[ -n "$docker_codename" ] || die "cannot determine the Debian/Ubuntu release codename"

export DEBIAN_FRONTEND=noninteractive
info "checking system packages"
apt-get update -qq || die "apt update failed; check the configured repositories and network"
missing=()
for package in nftables conntrack git curl python3 ca-certificates kmod procps; do
  if [ "$(dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null || true)" != "installed" ]; then
    missing+=("$package")
  fi
done
if [ "${#missing[@]}" -gt 0 ]; then
  info "installing missing packages: ${missing[*]}"
  apt-get install -y --no-remove --no-install-recommends "${missing[@]}" \
    || die "could not install required system packages"
fi
for dependency in nft:nftables conntrack:conntrack git:git curl:curl python3:python3 modprobe:kmod sysctl:procps; do
  executable="${dependency%%:*}"
  package="${dependency#*:}"
  if ! command -v "$executable" >/dev/null; then
    warn "$executable is missing; reinstalling $package"
    apt-get install -y --no-remove --no-install-recommends --reinstall "$package" \
      || die "could not reinstall $package"
    command -v "$executable" >/dev/null \
      || die "$executable is still unavailable after reinstalling $package; check PATH and package installation"
  fi
done

docker_candidate_available() {
  LC_ALL=C apt-cache policy "$1" | awk '$1 == "Candidate:" && $2 != "(none)" { found=1 } END { exit !found }'
}

install_docker_packages() {
  local package key_tmp
  for package in "$@"; do
    if ! docker_candidate_available "$package"; then
      info "configuring Docker's official apt repository"
      install -d -m 0755 /etc/apt/keyrings
      if [ ! -f /etc/apt/keyrings/artex-docker.asc ]; then
        key_tmp="$(mktemp /etc/apt/keyrings/artex-docker.asc.XXXXXX)"
        curl -fsSL "https://download.docker.com/linux/$docker_distro/gpg" \
          -o "$key_tmp" || {
            rm -f "$key_tmp"
            die "could not download Docker's repository signing key"
          }
        chmod 0644 "$key_tmp"
        mv "$key_tmp" /etc/apt/keyrings/artex-docker.asc
      fi
      if [ ! -f /etc/apt/sources.list.d/artex-docker.sources ]; then
        cat >/etc/apt/sources.list.d/artex-docker.sources <<EOF
Types: deb
URIs: https://download.docker.com/linux/$docker_distro
Suites: $docker_codename
Components: stable
Architectures: $(dpkg --print-architecture)
Signed-By: /etc/apt/keyrings/artex-docker.asc
EOF
      fi
      apt-get update -qq || die "could not update Docker's apt repository"
      break
    fi
  done
  info "installing Docker packages: $*"
  apt-get install -y --no-remove --no-install-recommends "$@" \
    || die "could not install Docker packages; resolve any package conflicts and retry"
}

if ! command -v docker >/dev/null || { ! docker info >/dev/null 2>&1 && ! command -v dockerd >/dev/null; }; then
  install_docker_packages docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
fi
command -v docker >/dev/null || die "Docker CLI is still unavailable after installation"
if ! docker info >/dev/null 2>&1; then
  info "starting Docker"
  systemctl start docker || die "could not start Docker; check systemctl status docker"
fi
docker info >/dev/null 2>&1 || die "Docker daemon is not responding"

docker_plugins=()
docker compose version >/dev/null 2>&1 || docker_plugins+=(docker-compose-plugin)
docker buildx version >/dev/null 2>&1 || docker_plugins+=(docker-buildx-plugin)
if [ "${#docker_plugins[@]}" -gt 0 ]; then
  install_docker_packages "${docker_plugins[@]}"
fi
docker compose version >/dev/null 2>&1 || die "Docker Compose plugin is unavailable"
docker buildx version >/dev/null 2>&1 || die "Docker buildx plugin is unavailable"

# gw_priority and DNS isolation require these versions.
engine="$(docker version --format '{{.Server.Version}}')" || die "cannot determine Docker Engine version"
compose="$(docker compose version --short)" || die "cannot determine Docker Compose version"
compose="${compose#v}"
dpkg --compare-versions "$engine" ge 28.0 \
  || die "Docker Engine $engine is too old; upgrade it to 28.0 or later before retrying"
dpkg --compare-versions "$compose" ge 2.33.0 \
  || die "Docker Compose $compose is too old; upgrade it to 2.33.0 or later before retrying"
if ! printf 'add table inet artex_check_%s\nadd chain inet artex_check_%s test { type filter hook forward priority -10 ; }\nadd rule inet artex_check_%s test ct state established accept\nadd table bridge artex_check_%s\nadd chain bridge artex_check_%s test { type filter hook forward priority -10 ; }\nadd rule bridge artex_check_%s test meta ibrname "lo" drop\n' \
    "$$" "$$" "$$" "$$" "$$" "$$" | nft -c -f -; then
  die "kernel nftables/conntrack or bridge support is unavailable, or CAP_NET_ADMIN is missing"
fi
ok "prerequisites installed (Docker $engine, Compose $compose)"

# --------------------------------------------------------------- conntrack io
# Byte/packet accounting is what makes the live view useful. The sysctls only
# exist once nf_conntrack is loaded.
modprobe nf_conntrack 2>/dev/null || true
echo nf_conntrack >/etc/modules-load.d/artex-lab.conf
cat >/etc/sysctl.d/90-artex-lab.conf <<'EOF'
net.netfilter.nf_conntrack_acct=1
net.netfilter.nf_conntrack_timestamp=1
EOF
sysctl --system >/dev/null 2>&1 || warn "could not apply sysctl (conntrack counters may stay at 0)"

# ------------------------------------------------------- docker for your user
# Docker access is root-equivalent; on a dedicated playground VM that is the
# same power you already have via sudo, and it makes `docker compose` usable.
if [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != "root" ]; then
  if ! id -nG "$SUDO_USER" | grep -qw docker; then
    usermod -aG docker "$SUDO_USER"
    warn "added $SUDO_USER to the docker group — log out and back in for it to apply"
  fi
fi

# ------------------------------------------------------------------- ARTEX src
if [ ! -d "$LAB_DIR/ARTEX/.git" ]; then
  info "cloning $ARTEX_REPO"
  git clone --depth 1 "$ARTEX_REPO" "$LAB_DIR/ARTEX"
else
  ok "ARTEX checkout already present"
fi

# --------------------------------------------------------------------- .env
if [ ! -f "$LAB_DIR/.env" ]; then
  cp "$LAB_DIR/.env.example" "$LAB_DIR/.env"
  pw="$(randstr 28)"
  sed -i "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=${pw}|" "$LAB_DIR/.env"
  chmod 600 "$LAB_DIR/.env"
  ok "created .env with a random Postgres password"
  if [ -t 0 ]; then
    while true; do
      read -r -p "Configure an external OpenAI-compatible model server now? [y/N] " answer || answer=""
      case "$answer" in
        y|Y|yes|YES)
          while true; do
            if ! read -r -p "Server hostname:port or URL (e.g. http://192.168.1.10:1234/v1): " endpoint; then
              warn "no endpoint entered; configure the model later in the ARTEX UI"
              break
            fi
            if normalized="$(normalize_model_endpoint "$endpoint")"; then
              model_url="${normalized%%$'\n'*}"
              model_hostport="${normalized#*$'\n'}"
              sed -i \
                -e 's|^ARTEX_LLM_PROVIDER=.*|ARTEX_LLM_PROVIDER=openai|' \
                -e "s|^ARTEX_LLM_BASE_URL=.*|ARTEX_LLM_BASE_URL=$model_url|" \
                -e "s|^ARTEX_LLM_PRIVATE_ENDPOINTS=.*|ARTEX_LLM_PRIVATE_ENDPOINTS=$model_hostport|" \
                "$LAB_DIR/.env"
              ok "configured $model_url; select a model and credentials in the ARTEX UI"
              break
            fi
          done
          break ;;
        ""|n|N|no|NO) info "configure a model later in the ARTEX UI"; break ;;
        *) warn "please answer yes or no" ;;
      esac
    done
  else
    warn "no interactive terminal; configure the model in .env or the ARTEX UI"
  fi
else
  ok ".env already present; model settings were not changed"
fi

mkdir -p "$LAB_DIR/data" "$LAB_DIR/keys"
chmod 700 "$LAB_DIR/keys"

# ------------------------------------------------------------------- daemon
info "installing the egress daemon"
install -d -m 0755 /etc/artex-lab /var/lib/artex-egress /opt/artex-egress /opt/artex-egress/static
install -m 0755 "$LAB_DIR/egress/egressd.py" /opt/artex-egress/egressd.py
rm -f /opt/artex-egress/static/*
install -m 0644 "$LAB_DIR"/egress/static/* /opt/artex-egress/static/

if [ ! -f /etc/artex-lab/egress.json ]; then
  install -m 0640 "$LAB_DIR/egress/config.example.json" /etc/artex-lab/egress.json
  ok "wrote /etc/artex-lab/egress.json"
fi

if [ ! -s /etc/artex-lab/ui-token ]; then
  randstr 32 >/etc/artex-lab/ui-token
fi
chmod 600 /etc/artex-lab/ui-token

# Fail early on a ruleset the kernel will not accept.
if ! /usr/bin/python3 /opt/artex-egress/egressd.py \
      --config /etc/artex-lab/egress.json --print-ruleset >/dev/null; then
  die "could not render the nftables ruleset"
fi

install -m 0644 "$LAB_DIR/egress/artex-egressd.service" /etc/systemd/system/artex-egressd.service
systemctl daemon-reload
systemctl enable artex-egressd.service >/dev/null 2>&1 || warn "could not enable artex-egressd.service at boot"
systemctl restart artex-egressd.service || true

sleep 1
DAEMON_OK=0
if systemctl is-active --quiet artex-egressd.service; then
  DAEMON_OK=1
  ok "egress daemon is running"
else
  warn "egress daemon failed to start:"
  journalctl -u artex-egressd -n 25 --no-pager || true
fi

# ------------------------------------------------------------------- ARTEX up
# ARTEX prints a one-time setup token to stderr on start while no admin
# password exists. A second log line also mentions "setup token" but does not
# contain it, so match the exact line, and wait: it appears only after the
# container has started and reached the database.
SETUP_TOKEN=""
ARTEX_STATE="not started (--no-up)"
INSTALL_FAILED=0

find_setup_token() {
  ( cd "$LAB_DIR" && docker compose logs --no-log-prefix artex 2>/dev/null ) \
    | grep -oE 'Setup token for the /setup page: [0-9a-f]+' | tail -n 1 | awk '{print $NF}' || true
}

if [ "$DAEMON_OK" != 1 ]; then
  INSTALL_FAILED=1
  if [ "$MODE" = "up" ]; then
    ARTEX_STATE="not started: egress daemon is not running"
  fi
elif [ "$MODE" = "up" ]; then
  info "building and starting ARTEX (compiles the frontend and Go binary; the first build takes several minutes)"
  if ( cd "$LAB_DIR" && docker compose up -d --build ); then
    info "waiting up to ${TOKEN_WAIT}s for ARTEX to print its setup token"
    ARTEX_STATE="started, but no setup token seen within ${TOKEN_WAIT}s"
    deadline=$(( $(date +%s) + TOKEN_WAIT ))
    while [ "$(date +%s)" -lt "$deadline" ]; do
      status="$(curl -fsS -m 3 "$ARTEX_URL/api/auth/status" 2>/dev/null || true)"
      case "$status" in
        *'"initialized":true'*)
          ARTEX_STATE="already set up (admin password exists) — log in at $ARTEX_URL"
          break ;;
      esac
      SETUP_TOKEN="$(find_setup_token)"
      if [ -n "$SETUP_TOKEN" ]; then
        ARTEX_STATE="running, waiting for first-run setup"
        break
      fi
      sleep 3
    done
  else
    ARTEX_STATE="docker compose up failed — see the output above"
    INSTALL_FAILED=1
    warn "$ARTEX_STATE"
  fi
fi

# ------------------------------------------------------------------- summary
subnet="$(python3 -c "import json;print(', '.join(json.load(open('/etc/artex-lab/egress.json'))['sources']))" 2>/dev/null || echo 172.30.10.0/24)"

cat <<EOF

  ──────────────────────────────────────────────────────────────────────
  Cage installation summary.

    egress daemon  $([ "$DAEMON_OK" = 1 ] && echo running || echo "NOT running — journalctl -u artex-egressd")
    console        http://127.0.0.1:9099      (from the VM's desktop browser)
    console token  /etc/artex-lab/ui-token    (only needed for non-loopback access)
    ARTEX UI       $ARTEX_URL
    ARTEX state    $ARTEX_STATE
    cage subnet    $subnet
    state          /var/lib/artex-egress/state.json
    audit log      /var/lib/artex-egress/events.jsonl
EOF

if [ -n "$SETUP_TOKEN" ]; then
  cat <<EOF

    ARTEX setup token (one-time, for $ARTEX_URL/setup):

        $SETUP_TOKEN

    It changes every time the container restarts until a password is set.
EOF
elif [ "$MODE" = "up" ] && [ "$INSTALL_FAILED" = 0 ]; then
  cat <<EOF

    Setup token not captured yet. Once ARTEX is up, get it with:
        cd "$LAB_DIR" && docker compose logs artex | grep -o 'Setup token for the /setup page: .*'
EOF
fi

cat <<EOF

  Next:
    1. Open $ARTEX_URL/setup, enter the setup token, choose a password,
       then configure the model and credentials in the ARTEX UI.
    2. Open http://127.0.0.1:9099 and approve the model endpoint when it
       shows up as pending (the cage starts fully closed).
    3. cd "$LAB_DIR" && ./verify-isolation.sh
EOF
if [ "$MODE" = "no-up" ]; then
  cat <<EOF

    ARTEX was not started. Build and start it with:
        cd "$LAB_DIR" && docker compose up -d --build
EOF
fi
echo "  ──────────────────────────────────────────────────────────────────────"
echo
exit "$INSTALL_FAILED"
