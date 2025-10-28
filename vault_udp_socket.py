import vault_ip
import vault_udp_encryption
import json
import math
import logging
import random
import socket
import threading
import time
import PySignal

logger = logging.getLogger(__name__)


class UDPSocketClass:
    """class to use bidirectional udp connection between applications

    enables opportunistic encryption between parties
    you can use your own keys in public key encryption

    warning: only one connection per ip supported for now
    """
    # signals for use with class
    # udp_recv_data signal is emitted with received string
    # udp_send_data signal is subscribed to send function, can be used to send str from other applications
    udp_recv_data = PySignal.ClassSignal()
    udp_send_data = PySignal.ClassSignal()

    def __init__(self, recv_port=11000):
        self.recv_port = recv_port  # where do you expect to get a msg?
        self.mtu = vault_ip.get_min_mtu() - 1
        self.mask_addresses = []
        self.reads = None
        self.writes = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.thread_stop = False
        self.timeout = 0
        self.thread_started = False
        self.lifetime = 60
        # public key encryption -> use nacl for keys and encryption
        self.pkse = vault_udp_encryption.VaultAsymmetricEncryption(lifetime=self.lifetime)
        self.udp_send_data.connect(self.send_data)
        threading.Timer(0.25, self.thread_read_socket).start()
        threading.Timer(5.0, self.__thread_key_management).start()

    def update_addr(self, addr=()):
        """update list of ip/port combinations to send packets to
           multiple recipients are allowed !but only one per ip!

        param addr: address to send packets to
        type addr: tuple of ip and port
        """
        logger.info("Update addr {}".format(addr))
        if addr:
            logger.debug("set new ip: {} port: {} combination".format(addr[0], addr[1]))
            send_ip = addr[0]
            send_port = addr[1]
            try:
                send_port_int = int(send_port)
            except ValueError:
                send_port_int = 11000
            logger.debug("new int port: {} - str port: {}".format(send_port_int, send_port))
            if send_port_int < 1500:
                send_port_int = 1500
            if send_port_int > 65000:
                send_port_int = 65000
            addr = [send_ip, send_port_int]
            if addr not in self.mask_addresses:
                self.mask_addresses.append(addr)
                self.__send_akey(tuple(addr))

    def update_recv_port(self, recv_port=""):
        """update receive port for listening

        param recv_port: port to bind udp socket for listening
        type recv_port: int
        """
        # TODO make checks look nicer
        logger.info("Update port {}".format(recv_port))
        if recv_port:
            recv_port_int = self.recv_port
            try:
                recv_port_int = int(recv_port)
            except ValueError:
                pass
            if recv_port_int < 1500:
                recv_port_int = 1500
            if recv_port_int > 65000:
                recv_port_int = 65000
            if recv_port_int != self.recv_port:
                self.recv_port = recv_port_int
                if self.thread_started:
                    self.thread_stop = True
                    self.reads.close()
                    threading.Timer(self.timeout+3, self.thread_read_socket).start()

    def read_socket(self):
        """receive incoming data and opportunistic decrypt it
           use data for key exchange
           emmit udp_recv_data signal with userdata if found
        """
        # TODO get send_addr
        packet, addr = self.reads.recvfrom(48000)
        decrypt_data = self.pkse.decrypt(packet.decode("utf-8"), addr)
        logger.debug("recv {} -> asm decrypt msg: {} from {}".format(self.recv_port, decrypt_data, addr))

        try:
            dict_data = json.loads(decrypt_data)
        except Exception as e:
            dict_data = {}
            logger.debug("error unpacking packet {}: {}".format(decrypt_data, e))

        if "data" in dict_data:
            logger.debug("data to emmit: {}".format(dict_data.get("data")))
            self.udp_recv_data.emit(dict_data.get("data"), addr)
        elif "akey" in dict_data:
            if "port" in dict_data:
                port = dict_data.get("port")
                addr = tuple([addr[0], port])
            if not self.pkse.key_exists(addr):
                logger.info("pkse: new asm key {} for {}".format(dict_data.get("akey", False), addr))
                self.pkse.update_key(tuple(addr), dict_data.get("akey", False))
                self.__send_akey(addr)
            self.pkse.update_key(tuple(addr), dict_data.get("akey", False))

    def thread_read_socket(self):
        """funktion to start binding and listening on udp sockets
        """
        self.reads = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.thread_started = True
        self.reads.settimeout(self.timeout)
        self.reads.bind(('', self.recv_port))
        logger.info("Thread to read socket started normal")
        while not self.thread_stop:
            try:
                self.read_socket()
            except Exception as e:
                # logger.info("error read socket: {}".format(e))
                # time.sleep(0.25)
                pass
        logger.info("Thread closed normal")

    def __padding(self, length):
        """create random string for padding data

        param length: length of return string
        type length: int

        return: random string
        rtype: str
        """
        logger.debug("padding data len {}".format(length))
        alphabet = "abcdefghijklmnopqrstuvwxyz"
        alphabet += alphabet.upper()
        alphabet += "0123456789.- +_?!^°§$%&/()=;:<>|"
        return_string = ""
        for number in range(length):
            return_string += random.choice(alphabet)
        return return_string

    def __thread_key_management(self):
        """key management - resend pkse keys and start ske key exchange if needed
        """
        while not self.thread_stop:
            for addr in self.mask_addresses:
                logger.debug("key management update for {}".format(addr))
                self.__send_akey(addr=addr)
            time.sleep(random.randint(5, math.floor(self.lifetime/3)))

    def __send_akey(self, addr=None):
        """prepare pkse key data for sending

        param addr: address to send key to
        type addr: tuple ip and port
        """
        data_2_send = {"akey": self.pkse.public_key, "port": self.recv_port, "ign": ""}
        self.__send(data_2_send, addr)

    def send_data(self, str_to_send, addr=None):
        """function to call from user of udp socket to send data
           prepares data

        param str_to_send: string to send
        type str_to_send: str
        param addr: addr to send to - None for to all known
        type addr: tuple ip and port
        """
        if type(str_to_send) is not str:
            raise TypeError("expected str")

        data_2_send = {"data": str_to_send, "ign": ""}
        self.__send(dict_data=data_2_send, addr=addr)

    def __send(self, dict_data, addr=None):
        """ internal send method, applies opportunistic encryption before sending data over udp
            applies padding to data to get equal length

        param dict_data: data to send
        type dict_data: dict
        param addr: addr to send data to
        type addr: tuple ip and port
        """
        logger.debug("{} -> {}: str to send: {}".format(self.recv_port, addr, json.dumps(dict_data)))
        if len(json.dumps(dict_data)) > self.mtu:
            raise ValueError("msg to long")

        dict_data.update({"ign": self.__padding(self.mtu - len(json.dumps(dict_data)))})
        data_2_send = json.dumps(dict_data)

        if addr:
            all_addresses = [addr]
        else:
            all_addresses = self.mask_addresses

        for address in all_addresses:
            text_encrypted = self.pkse.encrypt(data_2_send, address)
            logger.debug("{} -> {}: send bytes: {}".format(self.recv_port, address,
                                                               text_encrypted.encode("utf-8")))
            self.writes.sendto(text_encrypted.encode("utf-8"), tuple(address))

    def stop(self):
        """ stops pkse, ske clean_ups and socket operation"""
        self.pkse.stop()
        self.thread_stop = True
        self.reads.close()


if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.DEBUG)
    start = time.time()

    udp = UDPSocketClass(11000)
    udp.update_addr(("127.0.0.1", "8000"))
    time.sleep(1)
    udp2 = UDPSocketClass(8000)
    udp2.update_addr(("127.0.0.1", "11000"))
    for i in range(100):
        logger.info("{}: {}".format(i, math.floor(time.time() - start)))
        udp.send_data("hello world {}".format(i))
        time.sleep(random.randint(5, 20))
        udp2.send_data("world helo {}".format(i))
        time.sleep(random.randint(5, 20))

    udp2.stop()
    udp.stop()
