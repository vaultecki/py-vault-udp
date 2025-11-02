import os

from .vault_ip import get_ips, get_min_mtu
from .vault_udp_encryption import VaultAsymmetricEncryption
import json
import math
import logging
import random
import socket
import threading
import time
import PySignal
import pyzstd
import msgpack

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
        self.mtu = get_min_mtu() - 10
        self.mask_addresses = []
        self.reads = None
        self.writes = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.thread_stop = False
        self.timeout = 0
        self.thread_started = False
        self.lifetime = 60
        # public key encryption -> use nacl for keys and encryption
        self.pkse = VaultAsymmetricEncryption(lifetime=self.lifetime)
        self.udp_send_data.connect(self.send_data)

        self.read_thread = threading.Thread(target=self.thread_read_socket, daemon=True)
        self.read_thread.start()

        self.key_mgmt_thread = threading.Thread(target=self.__thread_key_management, daemon=True)
        self.key_mgmt_thread.start()

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
                logger.info(f"Neustart des Lese-Threads für Port {recv_port_int}")
                # 1. Alten Thread signalisieren zu stoppen
                self.thread_stop = True
                # 2. Socket schließen, um recvfrom zu deblockieren
                if self.reads:
                    self.reads.close()
                # 3. Warten, bis der alte Thread wirklich beendet ist
                if self.read_thread and self.read_thread.is_alive():
                    self.read_thread.join(timeout=2.0)  # Warten max. 2 Sek.
                # 4. Port aktualisieren und Flag zurücksetzen
                self.recv_port = recv_port_int
                self.thread_stop = False  # WICHTIG: Flag zurücksetzen
                # 5. Neuen Thread sauber starten
                logger.info("Starte neuen Lese-Thread...")
                self.read_thread = threading.Thread(target=self.thread_read_socket, daemon=True)
                self.read_thread.start()

    def read_socket(self):
        """receive incoming data and opportunistic decrypt it
           use data for key exchange
           emmit udp_recv_data signal with userdata if found
        """
        # TODO get send_addr
        packet, addr = self.reads.recvfrom(48000)
        try:
            decrypt_data = self.pkse.decrypt(packet, addr)
        except Exception as e:
            decrypt_data = packet
        logger.debug("recv {} -> asm decrypt msg: {} from {}".format(self.recv_port, decrypt_data, addr))

        try:
            unpacked_data = msgpack.unpackb(decrypt_data)
            payload_bytes = pyzstd.decompress(unpacked_data[0])
            control_bytes = unpacked_data[1]
            logger.debug(f"uncompressed data {payload_bytes}")
        except Exception as e:
            logger.debug("error unpacking packet {}: {}".format(decrypt_data, e))
            return

        self.udp_recv_data.emit(payload_bytes)

        try:
            control_dict = json.loads(control_bytes.decode("utf-8"))
            if "akey" in control_dict:
                if "port" in control_dict:
                    port = control_dict.get("port")
                    addr = tuple([addr[0], port])
                if not self.pkse.key_exists(addr):
                    logger.info("pkse: new asm key {} for {}".format(control_dict.get("akey", False), addr))
                    self.pkse.update_key(tuple(addr), control_dict.get("akey", False))
                    self.__send_akey(addr)
                self.pkse.update_key(tuple(addr), control_dict.get("akey", False))
                return

        except (json.JSONDecodeError, UnicodeDecodeError, AttributeError):
            logger.warning(f"miss formated control data from {addr}.")
            return

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
            except socket.timeout:
                # Timeout ist normal, einfach weitermachen
                continue
            except Exception as e:
                # Verhindert den Absturz des Threads
                if self.thread_stop:
                    # Gewollter Abbruch nach self.stop()
                    break
                #logger.error(f"Fehler in read_socket: {e}")
                time.sleep(0.1)
        logger.info("Thread closed normal")

    def __padding(self, length):
        """create random BYTES for padding data
        ...
        return: random bytes
        rtype: bytes
        """
        if length <= 0:
            return b""  # Leere bytes
        logger.debug("padding data len {}".format(length))
        return os.urandom(length)

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
        data_2_send = json.dumps({"akey": self.pkse.public_key, "port": self.recv_port, "ign": ""})
        if isinstance(data_2_send, str):
            data_2_send = data_2_send.encode("utf-8")
        #compressed_data = pyzstd.compress(data_2_send, 16)
        self.__send(control_data=data_2_send, addr=addr)

    def send_data(self, data_2_send, addr=None):
        """function to call from user of udp socket to send data
           prepares data

        param str_to_send: data to send
        type str_to_send: str or bytes
        param addr: addr to send to - None for to all known
        type addr: tuple ip and port
        """
        if isinstance(data_2_send, str):
            data_2_send = data_2_send.encode("utf-8")
        if not isinstance(data_2_send, bytes):
            raise TypeError
        compressed_data = pyzstd.compress(data_2_send, 16)

        self.__send(payload_data=compressed_data, addr=addr)

    def __send(self, payload_data=b"", control_data=b"", addr=None):
        """ internal send method, applies opportunistic encryption before sending data over udp
            applies padding to data to get equal length

        param data: data to send
        type data: bytes
        param addr: addr to send data to
        type addr: tuple ip and port
        """
        logger.debug("{} -> {}: data to send: {}".format(self.recv_port, addr, payload_data))
        packed_data = msgpack.packb([payload_data, control_data, b""])
        if len(packed_data) > self.mtu:
            raise ValueError("msg to long")

        padding_data = self.__padding(self.mtu - len(packed_data))
        packed_data = msgpack.packb([payload_data, control_data, padding_data])

        if addr:
            all_addresses = [addr]
        else:
            all_addresses = self.mask_addresses

        for address in all_addresses:
            text_encrypted = self.pkse.encrypt(packed_data, address)
            logger.debug("{} -> {}: send bytes: {}".format(self.recv_port, address,
                                                               text_encrypted))
            self.writes.sendto(text_encrypted, tuple(address))

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
