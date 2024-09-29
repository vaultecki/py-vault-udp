import socket
import psutil


def get_min_mtu(debug=False):
    interface_data = psutil.net_if_stats()
    mtu_list = []
    for interface, value in interface_data.items():
        if debug:
            print("network interface: {} got following properties: {}".format(interface, value))
        mtu_list.append(value.mtu)
    if mtu_list:
        return min(mtu_list)
    return 1500


def get_ips(debug=False):
    h_name = socket.gethostname()
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 1))
        result4 = s.getsockname()[0]
    except Exception as e:
        if debug:
            print("Error {}".format(e))
        result4 = '127.0.0.1'
    finally:
        s.close()
    result6raw = socket.getaddrinfo(h_name, 0, socket.AF_INET6)
    result6 = []
    for ipv6 in result6raw:
        result6.append(ipv6[4][0])
    result6 = list(dict.fromkeys(result6))
    return [[result4], result6]


if __name__ == "__main__":
    print(get_ips(True))
    print(get_min_mtu(True))
