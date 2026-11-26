import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


INSTALL = (Path(__file__).resolve().parents[1] / "install.sh").read_text(encoding="utf-8")
BASH = os.environ.get("TEST_BASH", "bash")


def run_bash(script, **env):
    variables = dict(os.environ, TEST_PYTHON=sys.executable, **env)
    if os.name == "nt":
        script = 'TEST_TMP="$(cygpath -u "$TEST_TMP")"\nTEST_PYTHON="$(cygpath -u "$TEST_PYTHON")"\n' + script
    return subprocess.run(
        [BASH, "--noprofile", "--norc", "-s"], input=script, text=True,
        capture_output=True, env=variables, timeout=30,
    )


class EndpointTests(unittest.TestCase):
    def endpoint(self, value):
        function = INSTALL.split("normalize_model_endpoint() {", 1)[1].split("\nMODE=", 1)[0]
        script = 'python3() { "$TEST_PYTHON" "$@"; }\nnormalize_model_endpoint() {' + function
        return run_bash(script + '\nnormalize_model_endpoint "$ENDPOINT"\n', ENDPOINT=value, TEST_TMP=".")

    def test_hostname_and_https_url(self):
        result = self.endpoint("model.example:1234")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            "http://model.example:1234/v1", "model.example:1234",
        ])
        result = self.endpoint("https://model.example/custom/v1/")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            "https://model.example/custom/v1", "model.example:443",
        ])

    def test_rejects_credentials_invalid_ports_and_shell_syntax(self):
        for value in ("http://user:secret@example.com/v1", "example.com:99999",
                      "example.com:0", "http://example.com/v1?x=y", "x:1234/$(id)"):
            with self.subTest(value=value):
                result = self.endpoint(value)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Invalid model endpoint", result.stderr)

    def test_interactive_configuration_and_rerun_preserve_existing_env(self):
        function = INSTALL.split("normalize_model_endpoint() {", 1)[1].split("\nMODE=", 1)[0]
        block = INSTALL.split("# --------------------------------------------------------------------- .env\n", 1)[1]
        block = block.split('mkdir -p "$LAB_DIR/data"', 1)[0]
        block = block.replace("[ -t 0 ]", "true").replace("read -r -p", "read -r -u 3 -p")
        harness = r'''
set -euo pipefail
LAB_DIR="$TEST_TMP"
exec 3<<<"$ANSWERS"
python3() { "$TEST_PYTHON" "$@"; }
randstr() { printf 'randompassword'; }
info() { echo "$*"; }
ok() { echo "$*"; }
warn() { echo "$*" >&2; }
'''
        with tempfile.TemporaryDirectory() as tmp:
            example = Path(__file__).resolve().parents[1] / ".env.example"
            (Path(tmp) / ".env.example").write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
            script = harness + "\nnormalize_model_endpoint() {" + function + "\n" + block
            result = run_bash(script, TEST_TMP=tmp, ANSWERS="y\n192.168.1.10:1234\n")
            self.assertEqual(result.returncode, 0, result.stderr)
            env_file = Path(tmp) / ".env"
            contents = env_file.read_text(encoding="utf-8")
            self.assertIn("ARTEX_LLM_BASE_URL=http://192.168.1.10:1234/v1", contents)
            self.assertIn("ARTEX_LLM_PRIVATE_ENDPOINTS=192.168.1.10:1234", contents)
            result = run_bash(script, TEST_TMP=tmp, ANSWERS="y\nother:4321\n")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(env_file.read_text(encoding="utf-8"), contents)

    def test_declining_leaves_model_unconfigured(self):
        function = INSTALL.split("normalize_model_endpoint() {", 1)[1].split("\nMODE=", 1)[0]
        block = INSTALL.split("# --------------------------------------------------------------------- .env\n", 1)[1]
        block = block.split('mkdir -p "$LAB_DIR/data"', 1)[0]
        block = block.replace("[ -t 0 ]", "true").replace("read -r -p", "read -r -u 3 -p")
        harness = r'''
set -euo pipefail
LAB_DIR="$TEST_TMP"
exec 3<<<"$ANSWERS"
python3() { "$TEST_PYTHON" "$@"; }
randstr() { printf 'randompassword'; }
info() { :; }
ok() { :; }
warn() { :; }
'''
        with tempfile.TemporaryDirectory() as tmp:
            example = Path(__file__).resolve().parents[1] / ".env.example"
            (Path(tmp) / ".env.example").write_text(example.read_text(encoding="utf-8"), encoding="utf-8")
            script = harness + "\nnormalize_model_endpoint() {" + function + "\n" + block
            result = run_bash(script, TEST_TMP=tmp, ANSWERS="n\n")
            self.assertEqual(result.returncode, 0, result.stderr)
            contents = (Path(tmp) / ".env").read_text(encoding="utf-8")
            self.assertIn("ARTEX_LLM_BASE_URL=\n", contents)
            self.assertIn("ARTEX_LLM_PRIVATE_ENDPOINTS=\n", contents)


class PrivateEndpointTests(unittest.TestCase):
    def authorize(self, directory, endpoint):
        function = INSTALL.split("add_private_model_endpoint() {", 1)[1].split("\nMODE=", 1)[0]
        if os.name == "nt":
            function = function.replace("    os.fchmod(fd, stat.st_mode & 0o7777)\n", "")
            function = function.replace("    os.fchown(fd, stat.st_uid, stat.st_gid)\n", "")
        script = 'python3() { "$TEST_PYTHON" "$@"; }\nadd_private_model_endpoint() {' + function
        return run_bash(script + '\nadd_private_model_endpoint "$TEST_TMP/.env" "$ENDPOINT"\n',
                        TEST_TMP=directory, ENDPOINT=endpoint)

    def test_adds_endpoint_without_losing_other_entries_or_settings(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text('ARTEX_LLM_PRIVATE_ENDPOINTS="old.example:80,[::1]:11434" # approved\n'
                            'ARTEX_LLM_BASE_URL=http://other:1234/v1\n', encoding="utf-8")
            result = self.authorize(tmp, "model.example:1234")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(path.read_text(encoding="utf-8"),
                             "ARTEX_LLM_PRIVATE_ENDPOINTS=old.example:80,[::1]:11434,model.example:1234 # approved\n"
                             "ARTEX_LLM_BASE_URL=http://other:1234/v1\n")
            result = self.authorize(tmp, "model.example:1234")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(path.read_text(encoding="utf-8").count("model.example:1234"), 1)

    def test_adds_missing_setting(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            path.write_text("OTHER=value", encoding="utf-8")
            result = self.authorize(tmp, "192.168.1.10:1234")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(path.read_text(encoding="utf-8"),
                             "OTHER=value\nARTEX_LLM_PRIVATE_ENDPOINTS=192.168.1.10:1234\n")

    def test_rejects_ambiguous_settings_without_modifying_file(self):
        for contents in ("ARTEX_LLM_PRIVATE_ENDPOINTS=a:1\nARTEX_LLM_PRIVATE_ENDPOINTS=b:2\n",
                         "ARTEX_LLM_PRIVATE_ENDPOINTS=${MY_ENDPOINT}\n"):
            with self.subTest(contents=contents), tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / ".env"
                path.write_text(contents, encoding="utf-8")
                result = self.authorize(tmp, "model.example:1234")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(path.read_text(encoding="utf-8"), contents)

    def test_command_authorizes_and_recreates_only_artex(self):
        helpers = INSTALL.split("normalize_model_endpoint() {", 1)[1].split("\nMODE=", 1)[0]
        if os.name == "nt":
            helpers = helpers.replace("    os.fchmod(fd, stat.st_mode & 0o7777)\n", "")
            helpers = helpers.replace("    os.fchown(fd, stat.st_uid, stat.st_gid)\n", "")
        block = INSTALL.split('if [ "$MODE" = "allow-model" ]; then', 1)[1]
        block = block.split("# ------------------------------------------------------------------ preflight", 1)[0]
        harness = r'''
set -euo pipefail
LAB_DIR="$TEST_TMP"
MODE=allow-model
set -- --allow-model model.example:1234
python3() { "$TEST_PYTHON" "$@"; }
systemctl() { [ "${DAEMON_ACTIVE:-1}" = 1 ]; }
docker() { echo "docker $*"; }
info() { echo "$*"; }
ok() { echo "$*"; }
die() { echo "$*" >&2; exit 1; }
'''
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / ".env"
            original = "ARTEX_LLM_PRIVATE_ENDPOINTS=\n"
            path.write_text(original, encoding="utf-8")
            script = harness + "\nnormalize_model_endpoint() {" + helpers + '\nif [ "$MODE" = "allow-model" ]; then' + block
            result = run_bash(script, TEST_TMP=tmp, DAEMON_ACTIVE="0")
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(path.read_text(encoding="utf-8"), original)
            result = run_bash(script, TEST_TMP=tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("docker compose up -d --no-deps artex", result.stdout)
            self.assertIn("ARTEX_LLM_PRIVATE_ENDPOINTS=model.example:1234", path.read_text(encoding="utf-8"))


class PreflightTests(unittest.TestCase):
    def test_sbin_executables_are_found_with_restricted_path(self):
        setup = INSTALL.split("set -Eeuo pipefail", 1)[1].split('LAB_DIR=', 1)[0]
        setup = setup.replace("/usr/local/sbin:/usr/sbin:/sbin", "$TEST_TMP/sbin")
        with tempfile.TemporaryDirectory() as tmp:
            script = r'''
mkdir -p "$TEST_TMP/sbin"
printf '#!/bin/sh\nexit 0\n' >"$TEST_TMP/sbin/nft"
chmod +x "$TEST_TMP/sbin/nft"
PATH=/usr/bin:/bin
''' + setup + r'''
command -v nft
'''
            result = run_bash(script, TEST_TMP=tmp)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("/sbin/nft", result.stdout)

    def preflight(self, **env):
        block = INSTALL.split("# ------------------------------------------------------------------ preflight\n", 1)[1]
        block = block.split("# --------------------------------------------------------------- conntrack io", 1)[0]
        block = block.replace("/run/systemd/system", "$TEST_TMP")
        block = block.replace("/etc/os-release", "$TEST_TMP/os-release")
        block = block.replace("/etc/apt", "$TEST_TMP/etc/apt")
        harness = r'''
set -euo pipefail
mkdir -p "$TEST_TMP/etc/apt/sources.list.d"
printf 'ID=debian\nVERSION_CODENAME=bookworm\n' >"$TEST_TMP/os-release"
info() { echo "info: $*"; }
ok() { echo "ok: $*"; }
warn() { echo "warning: $*"; }
die() { echo "error: $*" >&2; exit 1; }
command() {
  if [ "$1" = -v ] && [ "$2" = docker ]; then
    [ "${HAVE_DOCKER:-1}" = 1 ] || [ -f "$TEST_TMP/docker" ]
  elif [ "$1" = -v ] && [ "$2" = dockerd ]; then
    [ "${HAVE_DOCKERD:-1}" = 1 ] || [ -f "$TEST_TMP/docker" ]
  elif [ "$1" = -v ] && [ "$2" = "${MISSING_EXECUTABLE:-}" ]; then
    [ -f "$TEST_TMP/reinstalled-$2" ]
  else
    return 0
  fi
}
apt-get() {
  echo "apt $*"
  if [ "$1" = install ]; then
    for arg in "$@"; do
      case "$arg" in
        docker-ce) touch "$TEST_TMP/docker" "$TEST_TMP/running" ;;
        docker-compose-plugin) touch "$TEST_TMP/compose" ;;
        docker-buildx-plugin) touch "$TEST_TMP/buildx" ;;
        nftables) touch "$TEST_TMP/reinstalled-nft" ;;
      esac
    done
  fi
}
apt-cache() {
  if [ "${NO_CANDIDATE:-0}" = 1 ] && [ ! -f "$TEST_TMP/etc/apt/sources.list.d/artex-docker.sources" ]; then
    echo '  Candidate: (none)'
  else
    echo '  Candidate: 1.0'
  fi
}
dpkg-query() {
  if [ "${MISSING_PACKAGE:-}" = "${*: -1}" ]; then return 1; fi
  printf installed
}
dpkg() {
  if [ "$1" = --print-architecture ]; then echo amd64; return; fi
  if [ "$4" = 28.0 ]; then [ "${ENGINE_VERSION:-28.0.0}" != 27.0.0 ]; else return 0; fi
}
systemctl() { echo "systemctl $*"; touch "$TEST_TMP/running"; }
nft() { cat >/dev/null; [ "${NFT_FAIL:-0}" = 0 ]; }
curl() { while [ "$1" != -o ]; do shift; done; printf key >"$2"; }
docker() {
  case "$1" in
    info)
      [ "${DOCKER_RUNNING:-1}" = 1 ] || [ -f "$TEST_TMP/running" ] ;;
    version) echo "${ENGINE_VERSION:-28.0.0}" ;;
    compose)
      [ "${HAVE_COMPOSE:-1}" = 1 ] || [ -f "$TEST_TMP/compose" ] || return 1
      echo v2.33.0 ;;
    buildx)
      [ "${HAVE_BUILDX:-1}" = 1 ] || [ -f "$TEST_TMP/buildx" ] || return 1
      echo v0.20.0 ;;
  esac
}
'''
        with tempfile.TemporaryDirectory() as tmp:
            return run_bash(harness + block, TEST_TMP=tmp, **env)

    def test_existing_prerequisites_are_not_reinstalled(self):
        result = self.preflight()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("apt install", result.stdout)

    def test_repairs_missing_executable_even_if_package_is_installed(self):
        result = self.preflight(MISSING_EXECUTABLE="nft")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--reinstall nftables", result.stdout)

    def test_installs_missing_packages_and_docker(self):
        result = self.preflight(HAVE_DOCKER="0", HAVE_DOCKERD="0", DOCKER_RUNNING="0",
                                HAVE_COMPOSE="0", HAVE_BUILDX="0", NO_CANDIDATE="1",
                                MISSING_PACKAGE="nftables")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("configuring Docker's official apt repository", result.stdout)
        self.assertIn("--no-remove --no-install-recommends nftables", result.stdout)
        self.assertIn("docker-ce docker-ce-cli containerd.io", result.stdout)

    def test_starts_existing_docker_and_installs_missing_plugin(self):
        result = self.preflight(DOCKER_RUNNING="0", HAVE_COMPOSE="0")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("systemctl start docker", result.stdout)
        self.assertIn("docker-compose-plugin", result.stdout)
        self.assertNotIn("docker-ce ", result.stdout)

    def test_old_engine_is_reported_without_replacement(self):
        result = self.preflight(ENGINE_VERSION="27.0.0")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("too old", result.stderr)
        self.assertNotIn("apt install", result.stdout)

    def test_missing_kernel_support_stops_installation(self):
        result = self.preflight(NFT_FAIL="1")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("kernel nftables/conntrack or bridge support", result.stderr)


if __name__ == "__main__":
    unittest.main()
