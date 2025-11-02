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
    result4 = []
    result6 = []
    interface_data = psutil.net_if_stats()
    for interface, stats in interface_data.items():
        if stats.isup and not interface.lower().startswith('lo'):
            logger.debug("network interface: {} got following properties: {}".format(interface, stats))
            interface_addr = psutil.net_if_addrs().get(interface)
            for snic_addr in interface_addr:
                if snic_addr.family == socket.AF_INET:
                    result4.append(snic_addr.address)
                if snic_addr.family == socket.AF_INET6:
                    result6.append(snic_addr.address)
        else:
            logger.debug(f"Skipping interface {interface} (isup: {stats.isup})")
    return [result4, result6]


if __name__ == "__main__":
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.DEBUG)

    logger.info(get_ips())
    logger.info(get_min_mtu())
