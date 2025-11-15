import logging
import psutil
import socket


logger = logging.getLogger(__name__)


def get_min_mtu():
    interface_data = psutil.net_if_stats()
    mtu_list = []
    for interface, stats in interface_data.items():
        # Nur Interfaces berücksichtigen, die "up" sind
        # und nicht loopback ("lo") heißen.
        if stats.isup and not interface.lower().startswith('lo'):
            logger.debug("network interface: {} got following properties: {}".format(interface, stats))
            mtu_list.append(stats.mtu)
        else:
            logger.debug(f"Skipping interface {interface} (isup: {stats.isup})")
    if not mtu_list:
        logger.warning("Keine aktiven Netzwerk-Interfaces gefunden. Nutze Fallback-MTU 1500.")
        return 1500
    min_mtu = min(mtu_list)
    logger.info("return minimum mtu {}".format(min_mtu))
    return min_mtu


def get_ips():
    h_name = socket.gethostname()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        result4 = s.getsockname()[0]
    except Exception as e:
        logger.warning("Get IP Error {} - using 127.0.0.1".format(e))
        result4 = '127.0.0.1'
    finally:
        s.close()
    result6raw = socket.getaddrinfo(h_name, 0, socket.AF_INET6)
    result6 = []
    for ipv6 in result6raw:
        result6.append(ipv6[4][0])
    result6 = list(dict.fromkeys(result6))
    logger.debug("Return IPs {} and {}".format(result4, result6))
    return [[result4], result6]


if __name__ == "__main__":
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.DEBUG)

    logger.info(get_ips())
    logger.info(get_min_mtu())
