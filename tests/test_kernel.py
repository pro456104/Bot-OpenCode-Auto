# -*- coding: utf-8 -*-
"""kernel.py tests: conf generation, handshake parsing, readiness (mocked)."""
import time
import unittest
from unittest import mock

from vpnbot import kernel

SERVER = {"name": "t", "private_key": "PRIV", "address": "10.0.0.2/32",
          "public_key": "PUB", "endpoint": "1.2.3.4:51820", "mtu": ""}


class TestKernelConf(unittest.TestCase):
    def test_no_proxy_sections(self):
        text = kernel.make_kernel_conf(SERVER)
        self.assertNotIn("[HTTP]", text)
        self.assertNotIn("[Socks5]", text)
        self.assertIn("DNS = 1.1.1.1", text)
        self.assertIn("AllowedIPs = 0.0.0.0/0, ::/0", text)

    def test_mtu_auto_cloudflare(self):
        s = dict(SERVER, endpoint="188.114.97.1:51820")
        self.assertIn("MTU = 1280", kernel.make_kernel_conf(s))

    def test_mtu_auto_normal(self):
        self.assertIn("MTU = 1380", kernel.make_kernel_conf(SERVER))

    def test_mtu_custom_kept(self):
        s = dict(SERVER, mtu="1400")
        self.assertIn("MTU = 1400", kernel.make_kernel_conf(s))


class TestKernelState(unittest.TestCase):
    def test_interfaces_parsed(self):
        r = mock.MagicMock(stdout="opencode-kernel other0\n")
        with mock.patch.object(kernel.subprocess, "run", return_value=r):
            self.assertEqual(kernel.kernel_interfaces(), ["opencode-kernel", "other0"])

    def test_tunnel_up_ours_only(self):
        with mock.patch.object(kernel, "kernel_interfaces", return_value=["other0"]):
            self.assertFalse(kernel.kernel_tunnel_up())
            self.assertTrue(kernel.any_kernel_up())
        with mock.patch.object(kernel, "kernel_interfaces", return_value=[kernel.KERNEL_TUNNEL]):
            self.assertTrue(kernel.kernel_tunnel_up())

    def test_latest_handshake_age(self):
        ts = int(time.time()) - 30
        r = mock.MagicMock(stdout="PUBKEY\t%d\n" % ts)
        with mock.patch.object(kernel.subprocess, "run", return_value=r):
            age = kernel.kernel_latest_handshake()
        self.assertIsNotNone(age)
        self.assertTrue(25 <= age <= 40)

    def test_latest_handshake_none(self):
        r = mock.MagicMock(stdout="")
        with mock.patch.object(kernel.subprocess, "run", return_value=r):
            self.assertIsNone(kernel.kernel_latest_handshake())

    def test_latest_handshake_garbage(self):
        r = mock.MagicMock(stdout="garbage line\nPUB\tnotanumber\n")
        with mock.patch.object(kernel.subprocess, "run", return_value=r):
            self.assertIsNone(kernel.kernel_latest_handshake())

    def test_wait_ready_success(self):
        with mock.patch.object(kernel, "kernel_latest_handshake", return_value=5), \
             mock.patch.object(kernel, "fetch_direct_ip", return_value="7.7.7.7"):
            self.assertEqual(kernel.wait_for_kernel_ready(timeout_total=1, poll=0.05), "7.7.7.7")

    def test_wait_ready_no_handshake_times_out(self):
        with mock.patch.object(kernel, "kernel_latest_handshake", return_value=None), \
             mock.patch.object(kernel, "fetch_direct_ip") as f:
            self.assertIsNone(kernel.wait_for_kernel_ready(timeout_total=0.2, poll=0.05))
            f.assert_not_called()

    def test_install_missing_exe(self):
        with mock.patch.object(kernel, "WIREGUARD_EXE", r"X:\no\wireguard.exe"):
            ok, msg = kernel.kernel_install("whatever.conf")
        self.assertFalse(ok)
        self.assertIn("not found", msg)


if __name__ == "__main__":
    unittest.main()
