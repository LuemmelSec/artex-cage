import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import egressd


class ShutdownTests(unittest.TestCase):
    def test_signals_stop_the_serving_thread(self):
        script = """
import os
import signal
import sys
import threading
from unittest.mock import patch
sys.path.insert(0, os.getcwd())
import egressd

signal_name, config_path = sys.argv[1:]
serve_forever = egressd.ThreadingHTTPServer.serve_forever
def serve_with_signal(server):
    timer = threading.Timer(0.1, signal.raise_signal, args=(getattr(signal, signal_name),))
    timer.daemon = True
    timer.start()
    return serve_forever(server)

with patch.object(egressd.App, "start"), \\
     patch.object(egressd.os, "geteuid", return_value=0, create=True), \\
     patch.object(egressd.ThreadingHTTPServer, "serve_forever", serve_with_signal), \\
     patch.object(sys, "argv", ["egressd.py", "--config", config_path]):
    sys.exit(egressd.main())
"""
        with tempfile.TemporaryDirectory() as tmp:
            config = os.path.join(tmp, "config.json")
            with open(config, "w", encoding="utf-8") as fh:
                json.dump({"port": 0, "state_file": os.path.join(tmp, "state.json"),
                           "token_file": os.path.join(tmp, "token")}, fh)
            for name in ("SIGTERM", "SIGINT"):
                with self.subTest(signal=name):
                    result = subprocess.run(
                        [sys.executable, "-B", "-c", script, name, config],
                        cwd=os.path.dirname(os.path.abspath(__file__)),
                        capture_output=True, text=True, timeout=5,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("shutting down (rules stay in place)", result.stderr)


class KillSwitchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        cfg = dict(egressd.DEFAULTS)
        cfg.update(
            state_file=os.path.join(self.tmp.name, "state.json"),
            events_file=os.path.join(self.tmp.name, "events.jsonl"),
            killswitch_pause=False,
        )
        self.app = egressd.App(cfg)

    def test_kill_drops_before_established_and_covers_bridges(self):
        rules = self.app.nft.render(self.app.cfg, [], True)
        established = next(i for i, line in enumerate(rules)
                           if "out_chain" in line and "ct state established" in line)
        for match in ("ip saddr @srcs", "ip daddr @srcs", "ip saddr @labs", "ip daddr @labs"):
            drop = next(i for i, line in enumerate(rules)
                        if "out_chain %s counter drop" % match in line)
            self.assertLess(drop, established)
        self.assertTrue(any("kill_fwd meta ibrname" in line for line in rules))
        self.assertTrue(any("kill_out oifname @cage_bridges counter drop" in line for line in rules))

    def test_dns_without_explicit_upstream_reports_failure_after_firewall(self):
        container = {
            "Name": "/artex",
            "HostConfig": {"Dns": []},
            "NetworkSettings": {"Networks": {"egress": {"IPAddress": "172.30.10.2"}}},
        }
        responses = [
            subprocess.CompletedProcess([], 0, stdout="28.0.0\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="abc\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=json.dumps([container]), stderr=""),
        ]
        with patch.object(self.app.nft, "apply") as apply, \
             patch.object(egressd, "flush_subnets", return_value=0), \
             patch.object(egressd.subprocess, "run", side_effect=responses):
            with self.assertRaisesRegex(RuntimeError, "DNS may bypass"):
                self.app.set_killswitch(True)
        self.assertTrue(self.app.state.killswitch)
        self.assertTrue(apply.call_args.args[2])
        self.assertEqual(self.app.state.events[-1]["kind"], "killswitch_dns_error")
        self.assertIn("DNS may bypass", self.app.snapshot()["status"]["dns_error"])

    def test_docker_failure_is_not_reported_as_success(self):
        with patch.object(self.app.nft, "apply"), \
             patch.object(egressd, "flush_subnets", return_value=0), \
             patch.object(egressd.subprocess, "run", side_effect=OSError("docker unavailable")):
            with self.assertRaisesRegex(RuntimeError, "cannot verify container DNS"):
                self.app.set_killswitch(True)
        self.assertFalse(self.app.snapshot()["status"]["ok"])
        self.assertTrue(self.app.state.killswitch)

    def test_explicit_dns_and_unrelated_containers(self):
        containers = [
            {"Name": "/artex", "HostConfig": {"Dns": ["1.1.1.1"]},
             "NetworkSettings": {"Networks": {"egress": {"IPAddress": "172.30.10.2"}}}},
            {"Name": "/other", "HostConfig": {"Dns": []},
             "NetworkSettings": {"Networks": {"other": {"IPAddress": "172.17.0.2"}}}},
        ]
        responses = [
            subprocess.CompletedProcess([], 0, stdout="28.0.0\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout="abc def\n", stderr=""),
            subprocess.CompletedProcess([], 0, stdout=json.dumps(containers), stderr=""),
        ]
        with patch.object(egressd.subprocess, "run", side_effect=responses):
            self.app._check_cage_dns()

    def test_release_failure_does_not_unpause_or_clear_kill_state(self):
        self.app.state.killswitch = True
        self.app.state.save()
        with patch.object(self.app.nft, "apply", side_effect=egressd.NftError("rejected")), \
             patch.object(self.app, "_thaw") as thaw:
            with self.assertRaisesRegex(RuntimeError, "rejected"):
                self.app.set_killswitch(False)
        thaw.assert_not_called()
        self.assertTrue(self.app.state.killswitch)
        with open(self.app.state.path, encoding="utf-8") as state_file:
            self.assertTrue(json.load(state_file)["killswitch"])


if __name__ == "__main__":
    unittest.main()
