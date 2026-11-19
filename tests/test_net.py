# -*- coding: utf-8 -*-
"""net.py tests: probe semantics, check_server decision tree, IP fetchers (mocked)."""
import socket
import unittest
from unittest import mock

from vpnbot import net


class TestResolveHost(unittest.TestCase):
    def setUp(self):
        net._DNS_CACHE.clear()

    def test_ip_literal_passthrough(self):
        with mock.patch.object(net.socket, "gethostbyname") as g:
            self.assertEqual(net.resolve_host("1.2.3.4"), "1.2.3.4")
            g.assert_not_called()

    def test_resolution_and_cache(self):
        with mock.patch.object(net.socket, "gethostbyname", return_value="5.6.7.8") as g:
            self.assertEqual(net.resolve_host("example.com"), "5.6.7.8")
            self.assertEqual(net.resolve_host("example.com"), "5.6.7.8")
            self.assertEqual(g.call_count, 1)  # second hit from cache

    def test_dns_failure(self):
        with mock.patch.object(net.socket, "gethostbyname", side_effect=socket.gaierror):
            self.assertIsNone(net.resolve_host("bad.example"))


class TestUdpProbe(unittest.TestCase):
    def _sock(self, recv=None, send_exc=None):
        s = mock.MagicMock()
        if send_exc:
            s.sendto.side_effect = send_exc
        elif recv is not None:
            s.recvfrom.return_value = recv
        return s

    def test_open(self):
        with mock.patch.object(net, "resolve_host", return_value="1.2.3.4"), \
             mock.patch.object(net.socket, "socket", return_value=self._sock(recv=(b"x", ("1.2.3.4", 51820)))):
            self.assertEqual(net.udp_probe("h"), "open")

    def test_closed_via_reset(self):
        s = self._sock()
        s.recvfrom.side_effect = ConnectionResetError
        with mock.patch.object(net, "resolve_host", return_value="1.2.3.4"), \
             mock.patch.object(net.socket, "socket", return_value=s):
            self.assertEqual(net.udp_probe("h"), "closed")

    def test_closed_via_winerror_10054(self):
        e = OSError("reset")
        e.winerror = 10054
        s = self._sock()
        s.recvfrom.side_effect = e
        with mock.patch.object(net, "resolve_host", return_value="1.2.3.4"), \
             mock.patch.object(net.socket, "socket", return_value=s):
            self.assertEqual(net.udp_probe("h"), "closed")

    def test_filtered_on_timeout(self):
        s = self._sock()
        s.recvfrom.side_effect = socket.timeout
        with mock.patch.object(net, "resolve_host", return_value="1.2.3.4"), \
             mock.patch.object(net.socket, "socket", return_value=s):
            self.assertEqual(net.udp_probe("h"), "filtered")

    def test_closed_on_send_oserror(self):
        with mock.patch.object(net, "resolve_host", return_value="1.2.3.4"), \
             mock.patch.object(net.socket, "socket", return_value=self._sock(send_exc=OSError("no route"))):
            self.assertEqual(net.udp_probe("h"), "closed")

    def test_dns_fail(self):
        with mock.patch.object(net, "resolve_host", return_value=None):
            self.assertEqual(net.udp_probe("h"), "dns-fail")


class TestCheckServer(unittest.TestCase):
    def _run(self, dns=True, udp="filtered", ping=-1, tcp443=False, tcp80=False):
        with mock.patch.object(net, "resolve_host", return_value="1.2.3.4" if dns else None), \
             mock.patch.object(net, "udp_probe", return_value=udp), \
             mock.patch.object(net, "icmp_ping", return_value=ping), \
             mock.patch.object(net, "tcp_alive", side_effect=lambda h, p, timeout=2: tcp443 if p == 443 else tcp80):
            return net.check_server("h")

    def test_dns_fail_is_down(self):
        self.assertEqual(self._run(dns=False), (False, -1, "DNS fail"))

    def test_udp_closed_is_down(self):
        self.assertEqual(self._run(udp="closed"), (False, -1, "UDP port closed"))

    def test_ping_ok_is_up(self):
        alive, ms, reason = self._run(ping=23.4)
        self.assertTrue(alive)
        self.assertEqual(ms, 23.4)
        self.assertEqual(reason, "Ping OK")

    def test_icmp_blocked_but_tcp_alive_is_up(self):
        self.assertEqual(self._run(tcp443=True), (True, -1, "Host alive (ICMP blocked)"))

    def test_total_silence_is_unknown_not_down(self):
        # WireGuard is silent by design: never false-DOWN, never false-UP
        self.assertEqual(self._run(), (None, -1, "Silent (unverified)"))


class TestIcmpPing(unittest.TestCase):
    def _run(self, out):
        r = mock.MagicMock(stdout=out, stderr="")
        with mock.patch.object(net, "resolve_host", return_value="1.2.3.4"), \
             mock.patch.object(net.subprocess, "run", return_value=r):
            return net.icmp_ping("h")

    def test_english_time(self):
        self.assertEqual(self._run("Reply from 1.2.3.4: bytes=32 time=23ms TTL=54"), 23.0)

    def test_time_lt_1ms(self):
        self.assertEqual(self._run("Reply from 1.2.3.4: bytes=32 time<1ms TTL=64"), 1.0)

    def test_non_english_ttl_only(self):
        self.assertEqual(self._run("Antwort von 1.2.3.4: Bytes=32 Zeit<1ms TTL=64"), 1.0)

    def test_no_reply(self):
        self.assertEqual(self._run("Request timed out."), -1)

    def test_dns_failure(self):
        with mock.patch.object(net, "resolve_host", return_value=None):
            self.assertEqual(net.icmp_ping("h"), -1)


class TestSplitEndpoint(unittest.TestCase):
    def test_ipv4_with_port(self):
        self.assertEqual(net.split_endpoint("1.2.3.4:51820"), ("1.2.3.4", 51820))

    def test_ipv4_bare(self):
        self.assertEqual(net.split_endpoint("1.2.3.4"), ("1.2.3.4", 51820))

    def test_hostname(self):
        self.assertEqual(net.split_endpoint("us16.vpnbook.com:51820"), ("us16.vpnbook.com", 51820))

    def test_ipv6_bracketed(self):
        self.assertEqual(net.split_endpoint("[2400:4700:d1::79ef]:2408"),
                         ("2400:4700:d1::79ef", 2408))

    def test_ipv6_bracketed_no_port(self):
        self.assertEqual(net.split_endpoint("[2400::1]"), ("2400::1", 51820))

    def test_ipv6_bare(self):
        self.assertEqual(net.split_endpoint("2400::1"), ("2400::1", 51820))

    def test_invalid_port_defaults(self):
        self.assertEqual(net.split_endpoint("1.2.3.4:abc"), ("1.2.3.4", 51820))

    def test_empty(self):
        self.assertEqual(net.split_endpoint(""), ("", 51820))
        self.assertEqual(net.split_endpoint(None), ("", 51820))


class TestIpv6Probes(unittest.TestCase):
    def test_resolve_host_v6_passthrough(self):
        with mock.patch.object(net.socket, "gethostbyname") as g:
            self.assertEqual(net.resolve_host("2400::1"), "2400::1")
            g.assert_not_called()

    def test_udp_probe_uses_inet6(self):
        s = mock.MagicMock()
        s.recvfrom.side_effect = socket.timeout
        with mock.patch.object(net.socket, "socket", return_value=s) as mk:
            self.assertEqual(net.udp_probe("2400::1", 2408), "filtered")
        self.assertEqual(mk.call_args.args[0], socket.AF_INET6)

    def test_tcp_alive_uses_inet6(self):
        s = mock.MagicMock()
        s.connect_ex.return_value = 0
        with mock.patch.object(net.socket, "socket", return_value=s) as mk:
            self.assertTrue(net.tcp_alive("2400::1", 443))
        self.assertEqual(mk.call_args.args[0], socket.AF_INET6)

    def test_icmp_ping_v6_flag(self):
        r = mock.MagicMock(stdout="Reply from 2400::1: time=30ms", stderr="")
        with mock.patch.object(net.subprocess, "run", return_value=r) as run:
            self.assertEqual(net.icmp_ping("2400::1"), 30.0)
        cmd = run.call_args.args[0]
        self.assertIn("-6", cmd)

    def test_check_server_v6_endpoint(self):
        host, port = net.split_endpoint("[2400::1]:2408")
        with mock.patch.object(net, "udp_probe", return_value="filtered") as up, \
             mock.patch.object(net, "icmp_ping", return_value=12.0):
            alive, ms, reason = net.check_server(host, port)
        self.assertTrue(alive)
        up.assert_called_once_with("2400::1", 2408, timeout=2)


class TestIpFetch(unittest.TestCase):
    def test_proxy_ready(self):
        s = mock.MagicMock()
        s.connect_ex.return_value = 0
        with mock.patch.object(net.socket, "socket", return_value=s):
            self.assertTrue(net.proxy_ready())
        s.connect_ex.return_value = 10061
        with mock.patch.object(net.socket, "socket", return_value=s):
            self.assertFalse(net.proxy_ready())

    def test_get_ip_fast_fail_when_proxy_down(self):
        with mock.patch.object(net, "proxy_ready", return_value=False), \
             mock.patch.object(net, "_fetch_ip_via_proxy") as f:
            self.assertIsNone(net.get_ip())
            f.assert_not_called()

    def test_get_ip_first_success_wins(self):
        def by_url(url, timeout=3):
            return "9.9.9.9" if "ipify" in url else None
        with mock.patch.object(net, "proxy_ready", return_value=True), \
             mock.patch.object(net, "_fetch_ip_via_proxy", side_effect=by_url):
            self.assertEqual(net.get_ip(timeout=3), "9.9.9.9")

    def test_fetch_direct_ip(self):
        with mock.patch.object(net, "_fetch_direct_ip", return_value="8.8.8.8"):
            self.assertEqual(net.fetch_direct_ip(timeout=3), "8.8.8.8")


if __name__ == "__main__":
    unittest.main()
