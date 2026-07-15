import socket
from types import SimpleNamespace

import psutil
import pytest

import vault_ip


def _snic(family, address):
    """Build a minimal stand-in for psutil's snicaddr namedtuple."""
    return SimpleNamespace(family=family, address=address, netmask=None, broadcast=None, ptp=None)


def _snicstats(isup, mtu):
    return SimpleNamespace(isup=isup, duplex=0, speed=0, mtu=mtu)


# --- is_ipv4_valid / is_ipv6_valid ---

@pytest.mark.parametrize("ip", ["192.168.1.1", "0.0.0.0", "255.255.255.255", "127.0.0.1"])
def test_is_ipv4_valid_accepts_valid_addresses(ip):
    assert vault_ip.is_ipv4_valid(ip) is True


@pytest.mark.parametrize("ip", ["256.1.1.1", "not.an.ip", "::1", "", "1.2.3"])
def test_is_ipv4_valid_rejects_invalid_addresses(ip):
    assert vault_ip.is_ipv4_valid(ip) is False


@pytest.mark.parametrize("ip", ["::1", "2001:db8::1", "fe80::1"])
def test_is_ipv6_valid_accepts_valid_addresses(ip):
    assert vault_ip.is_ipv6_valid(ip) is True


@pytest.mark.parametrize("ip", ["192.168.1.1", "not:an:ip", ""])
def test_is_ipv6_valid_rejects_invalid_addresses(ip):
    assert vault_ip.is_ipv6_valid(ip) is False


# --- get_min_mtu ---

def test_get_min_mtu_returns_fallback_on_psutil_error(monkeypatch):
    def raise_error():
        raise OSError("no interfaces")

    monkeypatch.setattr(psutil, "net_if_stats", raise_error)
    assert vault_ip.get_min_mtu() == vault_ip.DEFAULT_MTU


def test_get_min_mtu_ignores_loopback_and_down_interfaces(monkeypatch):
    stats = {
        "lo": _snicstats(isup=True, mtu=65536),
        "eth0": _snicstats(isup=True, mtu=1500),
        "eth1": _snicstats(isup=False, mtu=9000),
        "eth2": _snicstats(isup=True, mtu=1200),
    }
    monkeypatch.setattr(psutil, "net_if_stats", lambda: stats)
    assert vault_ip.get_min_mtu() == 1200


def test_get_min_mtu_returns_fallback_when_no_active_interfaces(monkeypatch):
    stats = {
        "lo": _snicstats(isup=True, mtu=65536),
        "eth0": _snicstats(isup=False, mtu=1500),
    }
    monkeypatch.setattr(psutil, "net_if_stats", lambda: stats)
    assert vault_ip.get_min_mtu() == vault_ip.DEFAULT_MTU


# --- get_ipv4_addresses ---

def test_get_ipv4_addresses_returns_fallback_on_psutil_error(monkeypatch):
    def raise_error():
        raise OSError("no interfaces")

    monkeypatch.setattr(psutil, "net_if_addrs", raise_error)
    assert vault_ip.get_ipv4_addresses() == [vault_ip.FALLBACK_IPV4]


def test_get_ipv4_addresses_filters_loopback_link_local_and_down_interfaces(monkeypatch):
    addrs = {
        "lo": [_snic(socket.AF_INET, "127.0.0.1")],
        "eth0": [
            _snic(socket.AF_INET, "192.168.1.5"),
            _snic(socket.AF_INET, "169.254.1.2"),
            _snic(socket.AF_INET6, "fe80::1"),
        ],
        "eth1": [_snic(socket.AF_INET, "10.0.0.1")],
    }
    stats = {
        "eth0": _snicstats(isup=True, mtu=1500),
        "eth1": _snicstats(isup=False, mtu=1500),
    }
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: addrs)
    monkeypatch.setattr(psutil, "net_if_stats", lambda: stats)

    result = vault_ip.get_ipv4_addresses()

    assert result == ["192.168.1.5"]


def test_get_ipv4_addresses_returns_fallback_when_nothing_found(monkeypatch):
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: {"lo": [_snic(socket.AF_INET, "127.0.0.1")]})
    monkeypatch.setattr(psutil, "net_if_stats", lambda: {})

    assert vault_ip.get_ipv4_addresses() == [vault_ip.FALLBACK_IPV4]


# --- get_ipv6_addresses ---

def test_get_ipv6_addresses_returns_empty_list_on_gaierror(monkeypatch):
    def raise_gaierror(*args, **kwargs):
        raise socket.gaierror("no ipv6")

    monkeypatch.setattr(socket, "getaddrinfo", raise_gaierror)
    assert vault_ip.get_ipv6_addresses() == []


def test_get_ipv6_addresses_deduplicates(monkeypatch):
    addr_info = [
        (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("2001:db8::1", 0, 0, 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("2001:db8::1", 0, 0, 0)),
        (socket.AF_INET6, socket.SOCK_STREAM, 0, "", ("2001:db8::2", 0, 0, 0)),
    ]
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **k: addr_info)

    result = vault_ip.get_ipv6_addresses()

    assert result == ["2001:db8::1", "2001:db8::2"]


# --- get_ip_addresses ---

def test_get_ip_addresses_combines_ipv4_and_ipv6(monkeypatch):
    monkeypatch.setattr(vault_ip, "get_ipv4_addresses", lambda: ["192.168.1.5"])
    monkeypatch.setattr(vault_ip, "get_ipv6_addresses", lambda: ["2001:db8::1"])

    ipv4, ipv6 = vault_ip.get_ip_addresses()

    assert ipv4 == ["192.168.1.5"]
    assert ipv6 == ["2001:db8::1"]


# --- get_all_interface_addresses ---

def test_get_all_interface_addresses_groups_by_interface(monkeypatch):
    addrs = {
        "eth0": [
            _snic(socket.AF_INET, "192.168.1.5"),
            _snic(socket.AF_INET6, "fe80::1"),
        ],
        "eth1": [_snic(socket.AF_LINK if hasattr(socket, "AF_LINK") else 17, "aa:bb:cc:dd:ee:ff")],
    }
    monkeypatch.setattr(psutil, "net_if_addrs", lambda: addrs)

    result = vault_ip.get_all_interface_addresses()

    assert result == {
        "eth0": {"ipv4": ["192.168.1.5"], "ipv6": ["fe80::1"]},
    }


def test_get_all_interface_addresses_returns_empty_on_error(monkeypatch):
    def raise_error():
        raise OSError("boom")

    monkeypatch.setattr(psutil, "net_if_addrs", raise_error)
    assert vault_ip.get_all_interface_addresses() == {}
