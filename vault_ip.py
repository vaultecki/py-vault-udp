"""
Vault IP Module

Provides network interface utilities for determining MTU and IP addresses.
"""

import logging
import socket
from typing import List, Tuple, Optional

import psutil

logger = logging.getLogger(__name__)

# Constants
DEFAULT_MTU = 1500
FALLBACK_IPV4 = '127.0.0.1'
GOOGLE_DNS_SERVER = '8.8.8.8'
GOOGLE_DNS_PORT = 53


class NetworkError(Exception):
    """Base exception for network operations."""
    pass


class NoActiveInterfaceError(NetworkError):
    """Raised when no active network interfaces are found."""
    pass


class IPDetectionError(NetworkError):
    """Raised when IP address detection fails."""
    pass


def get_min_mtu() -> int:
    """
    Get the minimum MTU across all active network interfaces.

    Returns:
        Minimum MTU in bytes

    Note:
        - Ignores loopback interfaces
        - Returns DEFAULT_MTU (1500) if no active interfaces found
        - Only considers interfaces that are up
    """
    try:
        interface_data = psutil.net_if_stats()
    except Exception as e:
        logger.error("Failed to get network interface stats: %s", e)
        logger.warning("Using fallback MTU: %d", DEFAULT_MTU)
        return DEFAULT_MTU

    mtu_list = []

    for interface_name, stats in interface_data.items():
        # Skip loopback interfaces
        if interface_name.lower().startswith('lo'):
            logger.debug("Skipping loopback interface: %s", interface_name)
            continue

        # Only consider interfaces that are up
        if not stats.isup:
            logger.debug("Skipping interface %s (down)", interface_name)
            continue

        logger.debug(
            "Interface %s: MTU=%d, isup=%s, speed=%s",
            interface_name, stats.mtu, stats.isup, stats.speed
        )
        mtu_list.append(stats.mtu)

    if not mtu_list:
        logger.warning(
            "No active network interfaces found. Using fallback MTU: %d",
            DEFAULT_MTU
        )
        return DEFAULT_MTU

    min_mtu = min(mtu_list)
    logger.info("Minimum MTU across %d active interfaces: %d bytes",
                len(mtu_list), min_mtu)

    return min_mtu


def get_ipv4_address() -> str:
    """
    Get the primary IPv4 address of this machine.

    Returns:
        IPv4 address as string

    Note:
        Uses psutil to get addresses from active network interfaces.
        Prefers non-loopback addresses. Falls back to 127.0.0.1 if 
        no other address is found.
    """
    try:
        if_addrs = psutil.net_if_addrs()
        if_stats = psutil.net_if_stats()
    except Exception as e:
        logger.error("Failed to get network interfaces: %s", e)
        logger.warning("Using fallback IPv4: %s", FALLBACK_IPV4)
        return FALLBACK_IPV4

    # Collect all IPv4 addresses with priority
    addresses = []

    for interface_name, addr_list in if_addrs.items():
        # Skip loopback interfaces
        if interface_name.lower().startswith('lo'):
            continue

        # Check if interface is up
        if interface_name in if_stats and not if_stats[interface_name].isup:
            continue

        # Get IPv4 addresses
        for addr in addr_list:
            if addr.family == socket.AF_INET:
                ip = addr.address
                # Skip link-local addresses (169.254.x.x)
                if not ip.startswith('169.254.'):
                    addresses.append(ip)
                    logger.debug("Found IPv4 address %s on %s", ip, interface_name)

    if addresses:
        # Return the first non-loopback address
        ipv4_address = addresses[0]
        logger.debug("Selected primary IPv4 address: %s", ipv4_address)
        return ipv4_address

    # No non-loopback address found, use fallback
    logger.warning("No active IPv4 address found, using fallback: %s", FALLBACK_IPV4)
    return FALLBACK_IPV4


def get_ipv6_addresses() -> List[str]:
    """
    Get all IPv6 addresses associated with this machine.

    Returns:
        List of IPv6 addresses (may be empty)

    Note:
        Returns unique addresses only (duplicates removed).
        Returns empty list if IPv6 is not available or detection fails.
    """
    try:
        hostname = socket.gethostname()
        logger.debug("Hostname: %s", hostname)

        # Get all IPv6 addresses for this hostname
        addr_info_list = socket.getaddrinfo(
            hostname,
            None,  # Port not needed
            socket.AF_INET6,
            socket.SOCK_STREAM
        )

        # Extract unique IPv6 addresses
        ipv6_addresses = []
        seen = set()

        for addr_info in addr_info_list:
            # addr_info format: (family, type, proto, canonname, sockaddr)
            # sockaddr for IPv6: (address, port, flow info, scope id)
            ipv6_addr = addr_info[4][0]

            if ipv6_addr not in seen:
                ipv6_addresses.append(ipv6_addr)
                seen.add(ipv6_addr)

        logger.debug("Found %d unique IPv6 addresses", len(ipv6_addresses))
        return ipv6_addresses

    except socket.gaierror as e:
        logger.debug("IPv6 address resolution failed: %s", e)
        return []
    except Exception as e:
        logger.warning("Unexpected error getting IPv6 addresses: %s", e)
        return []


def get_ip_addresses() -> Tuple[List[str], List[str]]:
    """
    Get all IP addresses (both IPv4 and IPv6) for this machine.

    Returns:
        Tuple of ([ipv4_addresses], [ipv6_addresses])

    Note:
        - IPv4 list always contains at least one address (may be 127.0.0.1)
        - IPv6 list may be empty if IPv6 is not available
    """
    ipv4 = get_ipv4_address()
    ipv6_list = get_ipv6_addresses()

    logger.info("IP addresses: IPv4=%s, IPv6 count=%d", ipv4, len(ipv6_list))

    return ([ipv4], ipv6_list)


def get_all_interface_addresses() -> dict:
    """
    Get all IP addresses for all network interfaces.

    Returns:
        Dictionary mapping interface names to address lists
        Format: {
            'interface_name': {
                'ipv4': ['address1', ...],
                'ipv6': ['address1', ...]
            }
        }
    """
    interfaces = {}

    try:
        if_addrs = psutil.net_if_addrs()
    except Exception as e:
        logger.error("Failed to get interface addresses: %s", e)
        return interfaces

    for interface_name, addr_list in if_addrs.items():
        ipv4_addrs = []
        ipv6_addrs = []

        for addr in addr_list:
            if addr.family == socket.AF_INET:
                ipv4_addrs.append(addr.address)
            elif addr.family == socket.AF_INET6:
                ipv6_addrs.append(addr.address)

        if ipv4_addrs or ipv6_addrs:
            interfaces[interface_name] = {
                'ipv4': ipv4_addrs,
                'ipv6': ipv6_addrs
            }

    logger.debug("Found addresses for %d interfaces", len(interfaces))
    return interfaces


def is_ipv4_valid(ip: str) -> bool:
    """
    Check if a string is a valid IPv4 address.

    Args:
        ip: IP address string to validate

    Returns:
        True if valid IPv4, False otherwise
    """
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except (socket.error, ValueError, TypeError):
        return False


def is_ipv6_valid(ip: str) -> bool:
    """
    Check if a string is a valid IPv6 address.

    Args:
        ip: IP address string to validate

    Returns:
        True if valid IPv6, False otherwise
    """
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except (socket.error, ValueError, TypeError):
        return False


def get_network_info() -> dict:
    """
    Get comprehensive network information.

    Returns:
        Dictionary with network configuration details
    """
    ipv4_list, ipv6_list = get_ip_addresses()

    return {
        'mtu': get_min_mtu(),
        'primary_ipv4': ipv4_list[0] if ipv4_list else None,
        'all_ipv4': ipv4_list,
        'all_ipv6': ipv6_list,
        'interfaces': get_all_interface_addresses(),
        'hostname': socket.gethostname()
    }


def main():
    """Example usage and testing of network utilities."""
    logging.basicConfig(
        level=logging.DEBUG,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )

    print("=" * 70)
    print("Vault IP - Network Information Utility")
    print("=" * 70)

    # Get hostname
    print(f"\nHostname: {socket.gethostname()}")

    # Get MTU
    print("\n--- MTU Information ---")
    mtu = get_min_mtu()
    print(f"Minimum MTU: {mtu} bytes")

    # Get IPv4
    print("\n--- IPv4 Address ---")
    ipv4 = get_ipv4_address()
    print(f"Primary IPv4: {ipv4}")
    print(f"Valid IPv4: {is_ipv4_valid(ipv4)}")

    # Get IPv6
    print("\n--- IPv6 Addresses ---")
    ipv6_list = get_ipv6_addresses()
    if ipv6_list:
        for i, addr in enumerate(ipv6_list, 1):
            print(f"{i}. {addr}")
            print(f"   Valid: {is_ipv6_valid(addr)}")
    else:
        print("No IPv6 addresses found")

    # Get all IPs
    print("\n--- All IP Addresses ---")
    ipv4_all, ipv6_all = get_ip_addresses()
    print(f"IPv4 addresses: {ipv4_all}")
    print(f"IPv6 addresses: {len(ipv6_all)} found")

    # Get interface details
    print("\n--- Network Interfaces ---")
    interfaces = get_all_interface_addresses()
    for if_name, addrs in interfaces.items():
        print(f"\n{if_name}:")
        if addrs['ipv4']:
            print(f"  IPv4: {', '.join(addrs['ipv4'])}")
        if addrs['ipv6']:
            print(f"  IPv6: {', '.join(addrs['ipv6'][:2])}...")  # Limit display

    # Get comprehensive info
    print("\n--- Complete Network Info ---")
    info = get_network_info()
    print(f"MTU: {info['mtu']}")
    print(f"Primary IPv4: {info['primary_ipv4']}")
    print(f"Total IPv4 addresses: {len(info['all_ipv4'])}")
    print(f"Total IPv6 addresses: {len(info['all_ipv6'])}")
    print(f"Total interfaces: {len(info['interfaces'])}")
    print(f"Hostname: {info['hostname']}")

    # Test validation
    print("\n--- IP Validation Tests ---")
    test_cases = [
        ("192.168.1.1", "IPv4"),
        ("256.1.1.1", "Invalid IPv4"),
        ("::1", "IPv6"),
        ("2001:db8::1", "IPv6"),
        ("invalid", "Invalid"),
    ]

    for test_ip, description in test_cases:
        is_v4 = is_ipv4_valid(test_ip)
        is_v6 = is_ipv6_valid(test_ip)
        result = "IPv4" if is_v4 else ("IPv6" if is_v6 else "Invalid")
        print(f"{test_ip:20s} [{description:15s}] -> {result}")

    print("\n" + "=" * 70)
    print("Network information retrieved successfully! ✓")
    print("=" * 70)


if __name__ == "__main__":
    main()
