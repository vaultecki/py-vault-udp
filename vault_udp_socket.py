import vault_udp_socket_helper
import vault_ip

import json
import math
import nacl.exceptions
import random
import socket
import threading
import time
import PySignal


def dprint(text, debug=False):
    """debug print - only prints if debug set to True
    :param text: text to print
    :type text: str
    :param debug: true if it should print
    :type debug: bool
    """
    if debug:
        print(text)


class PubKeySignalEncryption:
    """public key encryption for use with udp class
    """
    def __init__(self, private_key=None, lifetime=60, debug=False):
        self.__keys = {}
        self.__keys_last_update = {}
        self.key_max_lifetime = lifetime
        self.debug = debug
        self.run_clean_ups = True
        if private_key:
            self.__private_key = private_key
            self.public_key = vault_udp_socket_helper.generate_public_key(self.__private_key)
        else:
            self.public_key = self.generate_key()
        threading.Timer(random.randint(1, math.floor(self.key_max_lifetime/2)), self.__thread_clean_up).start()

    def generate_key(self):
        """generates a new pair of private, public key

        :return: public key
        :rtype: str
        """
        dprint("Generate new keys for asymmetric encryption")
        public_key, private_key = vault_udp_socket_helper.generate_keys_asym()
        self.set_private_key(private_key)
        return public_key

    def set_private_key(self, private_key):
        """generates a new public key for the given private key and set private key to use

        param private_key: private nacl key for use
        type private_key: str
        return: public key
        rtype: str
        """
        dprint("pkse: set private key: {}".format(private_key), self.debug)
        self.__private_key = private_key
        self.public_key = vault_udp_socket_helper.generate_public_key(self.__private_key)
        return self.public_key

    def update_key(self, addr, key):
        """sets a key for later use in encryption for given address port pair

        param addr: tuple of address port pair
        type addr: tuple
        param key: public key to use with address for encryption
        type key: str
        """
        if key:
            dprint("pkse: update Key: {} for {}".format(key, addr), self.debug)
            self.__keys.update({tuple(addr): key})
            self.__keys_last_update.update({tuple(addr): math.floor(time.time())})

    def key_exists(self, addr):
        """checks if key for given addr exists in dict

        :return: true if key exists, false if not
        :rtype: bool
        """
        self.__clean_up()
        return tuple(addr) in self.__keys

    def remove_key(self, addr):
        """remove key from dict

        :return: public key
        :rtype: str
        """
        if tuple(addr) in self.__keys:
            dprint("pkse: remove key for addr {}".format(addr), self.debug)
            self.__keys.pop(tuple(addr))
            self.__keys_last_update.pop(tuple(addr))

    def __thread_clean_up(self):
        while self.run_clean_ups:
            self.__clean_up()
            time.sleep(random.randint(5, math.floor(self.key_max_lifetime/2)))

    def __clean_up(self):
        """keys have a lifespan, remove keys exceeding that span
        """
        addr_remove = []
        for addr, last_seen in self.__keys_last_update.items():
            if math.floor(time.time()) - last_seen > self.key_max_lifetime:
                addr_remove.append(addr)
        for addr in addr_remove:
            self.remove_key(addr)

    def decrypt(self, data, addr):
        """tries to decrypt given encrypted text, if decryption not possible returns data

        param data: encrypted text
        type data: str
        param addr: tuple of ip and port
        type addr: tuple

        return: text
        rtype: str
        """
        dprint("pkse: recv {}: data {}".format(addr, data.replace("\n", "")), self.debug)
        if not self.__private_key:
            return data

        try:
            text = vault_udp_socket_helper.decrypt_asym(self.__private_key, data)
        except TypeError:
            text = data
        except nacl.exceptions.InvalidkeyError:
            text = data
        except Exception as e:
            dprint("sym decryption error: {}".format(e), self.debug)
            text = data
        dprint("pkse: recv {}: text {}".format(addr, text.replace("\n", "")), self.debug)
        return text

    def encrypt(self, data, addr):
        """tries to encrypt given data, if not possible returns data

        param data: plain text
        type data: str
        param addr: tuple of ip and port
        type addr: tuple

        return: encrypted text
        rtype: str
        """
        dprint("pkse: encrypt {}: str {}".format(addr, data.replace("\n", "")), self.debug)
        if not self.__keys.get(tuple(addr), False):
            return data

        text = vault_udp_socket_helper.encrypt_asym(self.__keys.get(tuple(addr)), data)
        dprint("pkse: encrypted {}: str {}".format(addr, text.replace("\n", "")), self.debug)
        return text


class SymKeyExchange:
    def __init__(self, lifetime=60, debug=False):
        self.debug = debug
        self.key_max_lifetime = lifetime
        self.__keys = {}
        self.__keys_last_update = {}
        dprint("ske: generate public msg and private key", self.debug)
        self.public_msg, self.__private_key = vault_udp_socket_helper.newhope_keygen()
        self.run_clean_ups = True
        threading.Timer(random.randint(1, math.floor(self.key_max_lifetime/2)), self.__thread_clean_up).start()

    def key_exists(self, addr):
        """checks if key for given addr exists in dict

        :return: true if key exists, false if not
        :rtype: bool
        """
        self.__clean_up()
        return tuple(addr) in self.__keys

    def ip_exists(self, ip):
        """checks for ip in key storage

        param ip: ip
        type ip: str

        return: true if ip exists in storage, false if not
        rtype: bool
        """
        key_list = list(self.__keys.keys())
        for key in key_list:
            if ip in key[0]:
                return key
        return False

    def __thread_clean_up(self):
        while self.run_clean_ups:
            self.__clean_up()
            time.sleep(random.randint(5, math.floor(self.key_max_lifetime/2)))

    def __clean_up(self):
        """key have a lifespan, remove keys if time exceeded
        """
        dprint("ske: clean up run", self.debug)
        addr_remove = []
        for addr, last_seen in self.__keys_last_update.items():
            if math.floor(time.time()) - last_seen > self.key_max_lifetime:
                addr_remove.append(addr)
        for addr in addr_remove:
            self.__remove_key(addr)

    def key_exchange_b(self, public_msg, addr):
        dprint("ske: Key-Exchange-B from {}".format(addr), self.debug)
        public_msg_2, shared_key = vault_udp_socket_helper.newhope_shared_b(public_msg)
        self.__update_key(addr, shared_key)
        return public_msg_2

    def __remove_key(self, addr):
        """removes key from storage

        param addr: tuple of ip and port
        type addr: tuple
        """
        if tuple(addr) in self.__keys:
            dprint("ske: remove key for addr {}".format(addr), self.debug)
            self.__keys.pop(tuple(addr))
            self.__keys_last_update.pop(tuple(addr))

    def key_exchange_a(self, public_msg, addr):
        if public_msg:
            dprint("ske: Key-Exchange-A from {}".format(addr), self.debug)
            self.__remove_key(addr)
            shared_key = vault_udp_socket_helper.newhope_shared_a(public_msg, self.__private_key)
            self.__update_key(addr, shared_key)

    def encrypt(self, text, addr):
        """tries to encrypt given encrypted text, if decryption not possible returns text as is

        param text: plain text
        type text: str
        param addr: tuple of ip and port
        type addr: tuple

        return: text
        rtype: str
        """
        self.__clean_up()
        key = self.__keys.get(tuple(addr))
        if not key:
            return text

        encrypted_text = vault_udp_socket_helper.encrypt_sym(key, text)
        return encrypted_text

    def decrypt(self, encrypted_text, addr):
        """tries to decrypt given encrypted text, if decryption not possible returns text as is

        param encrypted_text: encrypted text
        type encrypted_text: str
        param addr: tuple of ip and port
        type addr: tuple or bool

        return: text
        rtype: str
        """
        dprint("ske decrypt {}: {}".format(addr, encrypted_text.replace("\n", "")), self.debug)
        if not addr:
            return encrypted_text

        key = self.__keys.get(tuple(addr), False)
        if not key:
            return encrypted_text

        try:
            text = vault_udp_socket_helper.decrypt_sym(str(key), encrypted_text)
        except TypeError:
            text = encrypted_text
        except nacl.exceptions.InvalidkeyError:
            text = encrypted_text
        except Exception as e:
            dprint("sym decryption error: {}".format(e), self.debug)
            text = encrypted_text
        dprint("ske decrypted {}: {}".format(addr, text.replace("\n", "")), self.debug)
        return text

    def __update_key(self, addr, key):
        """sets a key for later use in encryption for given address port pair

        param addr: tuple of address port pair
        type addr: tuple
        param key: public key to use with address for encryption
        type key: str
        """
        if key:
            dprint("SKE: update Key: {} for {}".format(key, addr), self.debug)
            self.__keys.update({tuple(addr): key})
            self.__keys_last_update.update({tuple(addr): math.floor(time.time())})


class UDPSocketClass:
    """class to use bidirectional udp connection between applications

    enables opportunistic encryption between parties
    you can use your own keys in public key encryption

    warning: only one connection per ip supported for now
    warning: encryption may not be production ready -> look at bsi and used libraries for advice
    """
    # signals for use with class
    # udp_recv_data signal is emitted with received string
    # udp_send_data signal is subscribed to send function, can be used to send str from other applications
    udp_recv_data = PySignal.ClassSignal()
    udp_send_data = PySignal.ClassSignal()

    def __init__(self, recv_port=11000, debug=False):
        self.recv_port = recv_port  # where do you expect to get a msg?
        self.debug = debug
        self.mtu = vault_ip.get_min_mtu(debug=self.debug) - 1
        self.mask_addresses = []
        self.reads = None
        self.writes = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.thread_stop = False
        self.timeout = 0
        self.thread_started = False
        self.lifetime = 60
        # public key encryption -> use nacl for keys and encryption
        self.pkse = PubKeySignalEncryption(debug=self.debug, lifetime=self.lifetime)
        # test of symmetric encryption with key exchange from newhope
        # warning - maybe not stable, not production ready
        self.ske = SymKeyExchange(debug=self.debug, lifetime=2*self.lifetime)
        self.ske_init_time = {}
        # self.ske_init_public_msg = {}
        self.udp_send_data.connect(self.send_data)
        threading.Timer(0.25, self.thread_read_socket).start()
        threading.Timer(5.0, self.__thread_key_management).start()

    def update_addr(self, addr=()):
        """update list of ip/port combinations to send packets to
           multiple recipients are allowed !but only one per ip!

        param addr: address to send packets to
        type addr: tuple of ip and port
        """
        # TODO make checks look nicer
        dprint("Update addr {}".format(addr), self.debug)
        if addr:
            dprint("set new ip: {} port: {} combination".format(addr[0], addr[1]), self.debug)
            send_ip = addr[0]
            send_port = addr[1]
            try:
                send_port_int = int(send_port)
            except ValueError:
                send_port_int = 11000
            dprint("new int port: {} - str port: {}".format(send_port_int, send_port), self.debug)
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
        dprint("Update port {}".format(recv_port), self.debug)
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
        dprint("recv {} -> bytes: {} from {}".format(self.recv_port, packet, addr), self.debug)
        addr_ske = self.ske.ip_exists(addr[0])
        decrypt_data = self.ske.decrypt(packet.decode("utf-8"), addr_ske)
        dprint("recv {} -> sym decrypt msg: {} from {}".format(self.recv_port,
                                                               decrypt_data.replace("\n", ""), addr), self.debug)
        if packet.decode("utf-8") == decrypt_data:
            decrypt_data = self.pkse.decrypt(packet.decode("utf-8"), addr)
            dprint("recv {} -> asm decrypt msg: {} from {}".format(self.recv_port,
                                                                   decrypt_data.replace("\n", ""), addr), self.debug)

        try:
            dict_data = json.loads(decrypt_data)
        except Exception as e:
            dict_data = {}
            dprint("error unpacking packet {}: {}".format(decrypt_data, e), self.debug)

        if "data" in dict_data:
            dprint("data to emmit: {}".format(dict_data.get("data").replace("\n", "")), self.debug)
            self.udp_recv_data.emit(dict_data.get("data"), addr)
        elif "akey" in dict_data:
            if "port" in dict_data:
                port = dict_data.get("port")
                addr = tuple([addr[0], port])
            if not self.pkse.key_exists(addr):
                dprint("pkse: new asm key {} for {}".format(dict_data.get("akey", False), addr), self.debug)
                self.pkse.update_key(tuple(addr), dict_data.get("akey", False))
                self.__send_akey(addr)
            self.pkse.update_key(tuple(addr), dict_data.get("akey", False))
        elif "skeyb" in dict_data:
            if "port" in dict_data:
                port = dict_data.get("port")
                addr = tuple([addr[0], port])
            if not self.ske.key_exists(addr) and self.pkse.key_exists(addr):
                dprint("{} -> start sym encryption - B".format(self.recv_port), self.debug)
                public_msg = dict_data.get("skeyb", False)
                time_ske = dict_data.get("time", 0)
                if time_ske < self.ske_init_time.get(tuple(addr), time.time()) and public_msg:
                    public_msg_2 = self.ske.key_exchange_b(public_msg, addr)
                    # self.ske_init_public_msg.update(tuple(addr), public_msg_2)
                    self.__send_skey(addr, public_msg_2)
                elif public_msg:
                    # public_msg_2 = self.ske_init_public_msg.get(tuple(addr), False)
                    self.__send_skey(addr, False)

        elif "skeya" in dict_data:
            dprint("start sym encryption - A", self.debug)
            if "port" in dict_data:
                port = dict_data.get("port")
                addr = tuple([addr[0], port])
            public_msg = dict_data.get("skeya", False)
            self.ske.key_exchange_a(public_msg, addr)

    def __send_skey(self, addr, public_msg=False):
        """sending key exchange messages for ske
           explicit only using pkse for encryption for sending

        param public_msg: public_msg from new_hope
        type public_msg: [str, str]
        param addr: address to send packets to
        type addr: tuple of ip and port
        """
        # print("{} -> public msg: {}".format(self.recv_port, public_msg))
        if not public_msg:
            time_ske = self.ske_init_time.get(tuple(addr), time.time())
            data_2_send = json.dumps({"skeyb": self.ske.public_msg, "port": self.recv_port, "time": time_ske}, indent=0)
            self.ske_init_time.update({tuple(addr): time_ske})
        else:
            data_2_send = json.dumps({"skeya": public_msg, "port": self.recv_port}, indent=0)
            if tuple(addr) in self.ske_init_time:
                self.ske_init_time.pop(tuple(addr))
        text_encrypted = self.pkse.encrypt(data_2_send, addr)
        dprint("ske: {} -> {}: send bytes: {}".format(self.recv_port, addr,
                                                      data_2_send.replace("\n", "").encode("utf-8")), self.debug)
        self.writes.sendto(text_encrypted.encode("utf-8"), tuple(addr))

    def thread_read_socket(self):
        """funktion to start binding and listening on udp sockets
        """
        self.reads = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.thread_started = True
        self.reads.settimeout(self.timeout)
        self.reads.bind(('', self.recv_port))
        dprint("Thread to read socket started normal", self.debug)
        while not self.thread_stop:
            try:
                self.read_socket()
            except Exception as e:
                dprint("error read socket: {}".format(e), False)
                # time.sleep(0.25)
                pass
        dprint("Thread closed normal", self.debug)

    def __padding(self, length):
        """create random string for padding data

        param length: length of return string
        type length: int

        return: random string
        rtype: str
        """
        dprint("padding data len {}".format(length), self.debug)
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
                dprint("key management update for {}".format(addr), self.debug)
                self.__send_akey(addr=addr)
                if not self.ske.key_exists(addr) and self.pkse.key_exists(addr):
                    self.__send_skey(addr=addr)
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
        if type(str_to_send) is str:
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
        dprint("{} -> {}: str to send: {}".format(self.recv_port, addr,
                                                  json.dumps(dict_data, indent=0).replace("\n", "")), self.debug)
        if len(json.dumps(dict_data, indent=0)) > self.mtu:
            raise ValueError("msg to long")

        dict_data.update({"ign": self.__padding(self.mtu - len(json.dumps(dict_data, indent=0)))})
        data_2_send = json.dumps(dict_data, indent=0)

        if addr:
            all_addresses = [addr]
        else:
            all_addresses = self.mask_addresses

        for address in all_addresses:
            text_encrypted = self.ske.encrypt(data_2_send, address)
            dprint("{} -> {}: send bytes: {}".format(self.recv_port, address,
                                                     text_encrypted.replace("\n", "").encode("utf-8")), self.debug)
            if text_encrypted == data_2_send:
                text_encrypted = self.pkse.encrypt(data_2_send, address)
                dprint("{} -> {}: send bytes: {}".format(self.recv_port, address,
                                                         text_encrypted.replace("\n", "").encode("utf-8")), self.debug)
            self.writes.sendto(text_encrypted.encode("utf-8"), tuple(address))

    def stop(self):
        """ stops pkse, ske clean_ups and socket operation"""
        self.pkse.run_clean_ups = False
        self.ske.run_clean_ups = False
        self.thread_stop = True
        self.reads.close()


if __name__ == '__main__':
    start = time.time()
    udp = UDPSocketClass(11000, False)
    udp.update_addr(("127.0.0.1", "8000"))
    time.sleep(1)
    udp2 = UDPSocketClass(8000, True)
    udp2.update_addr(("127.0.0.1", "11000"))
    for i in range(100):
        print("{}: {}".format(i, math.floor(time.time() - start)))
        udp.send_data("hello world {}".format(i))
        time.sleep(random.randint(5, 20))
        udp2.send_data("world helo {}".format(i))
        time.sleep(random.randint(5, 20))
    udp2.stop()
    udp.stop()
