import vault_udp_socket_helper
import time
import random
import math
import logging
import nacl.exceptions
import threading


logger = logging.getLogger(__name__)


class VaultEncryption:
    def __init__(self, lifetime=60):
        self.keys = dict()
        self.keys_last_update = dict()
        self.key_max_lifetime = lifetime
        self.run_clean_ups = True

    def key_exists(self, addr):
        """checks if key for given addr exists in dict

        :return: true if key exists, false if not
        :rtype: bool
        """
        self.clean_up()
        return tuple(addr) in self.keys

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

    def update_key(self, addr, key):
        """sets a key for later use in encryption for given address port pair

        param addr: tuple of address port pair
        type addr: tuple
        param key: public key to use with address for encryption
        type key: str
        """
        if key:
            logger.debug("ve: update Key: {} for {}".format(key, addr))
            self.keys.update({tuple(addr): key})
            self.keys_last_update.update({tuple(addr): math.floor(time.time())})

    def remove_key(self, addr):
        """remove key from dict

        :return: public key
        :rtype: str
        """
        if tuple(addr) in self.keys:
            logger.info("ve: remove key for addr {}".format(addr))
            self.keys.pop(tuple(addr))
            self.keys_last_update.pop(tuple(addr))

    def thread_clean_up(self):
        while self.run_clean_ups:
            self.clean_up()
            time.sleep(random.randint(5, math.floor(self.key_max_lifetime/2)))

    def clean_up(self):
        """keys have a lifespan, remove keys exceeding that span
        """
        addr_remove = []
        for addr, last_seen in self.keys_last_update.items():
            if math.floor(time.time()) - last_seen > self.key_max_lifetime:
                addr_remove.append(addr)
        for addr in addr_remove:
            self.remove_key(addr)

    def stop(self):
        self.run_clean_ups = False


class VaultAsymmetricEncryption(VaultEncryption):
    def __init__(self, lifetime=60, private_key=None):
        logger.info("init [v]ault [a]ymmetric [e]ncryption")
        super().__init__(lifetime)
        self.__private_key = ""
        self.public_key = ""
        if private_key:
            self.set_private_key(private_key)
        else:
            self.generate_key()
        # threading.Timer(random.randint(1, math.floor(self.__key_max_lifetime / 2)), self.__thread_clean_up).start()

    def generate_key(self):
        """generates a new pair of private, public key

        :return: public key
        :rtype: str
        """
        logger.info("generate new keys for vae")
        public_key, private_key = vault_udp_socket_helper.generate_keys_asym()
        self.set_private_key(private_key)
        return self.public_key

    def set_private_key(self, private_key):
        """generates a new public key for the given private key and set private key to use

        param private_key: private nacl key for use
        type private_key: str
        return: public key
        rtype: str
        """
        logger.debug("vae: set private key: {}".format(private_key))
        self.__private_key = private_key
        self.public_key = vault_udp_socket_helper.generate_public_key(self.__private_key)
        return self.public_key

    def decrypt(self, data, addr):
        """tries to decrypt given encrypted text, if decryption not possible returns data

        param data: encrypted text
        type data: str
        param addr: tuple of ip and port
        type addr: tuple

        return: text
        rtype: str
        """
        logger.debug("vae: recv {}: data {}".format(addr, data.replace("\n", "")))
        if not self.__private_key:
            return data

        try:
            text = vault_udp_socket_helper.decrypt_asym(self.__private_key, data)
        except TypeError:
            text = data
        except nacl.exceptions.InvalidkeyError:
            text = data
        except Exception as e:
            logger.debug("asym decryption error: {}".format(e))
            text = data
        logger.info("vae: recv {}: text {}".format(addr, text.replace("\n", "")))
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
        logger.debug("vae: encrypt {}: str {}".format(addr, data.replace("\n", "")))
        if not self.keys.get(tuple(addr), False):
            return data

        text = vault_udp_socket_helper.encrypt_asym(self.keys.get(tuple(addr)), data)
        logger.debug("vae: encrypted {}: str {}".format(addr, text.replace("\n", "")))
        return text


class VaultSymmetricEncryption(VaultEncryption):
    def __init__(self, lifetime=180):
        logger.info("init [v]ault [s]ymmetric [e]ncryption")
        super().__init__(lifetime)
        self.public_msg, self.__private_key = vault_udp_socket_helper.newhope_keygen()
        self.run_clean_ups = True
        # threading.Timer(random.randint(1, math.floor(self.key_max_lifetime / 2)), self.__thread_clean_up).start()

    def key_exchange_b(self, public_msg, addr):
        logger.info("vse: Key-Exchange-B from {}".format(addr))
        public_msg_2, shared_key = vault_udp_socket_helper.newhope_shared_b(public_msg)
        self.update_key(addr, shared_key)
        return public_msg_2

    def key_exchange_a(self, public_msg, addr):
        if public_msg:
            logger.info("vse: Key-Exchange-A from {}".format(addr))
            self.remove_key(addr)
            shared_key = vault_udp_socket_helper.newhope_shared_a(public_msg, self.__private_key)
            self.update_key(addr, shared_key)

    def encrypt(self, text, addr):
        """tries to encrypt given encrypted text, if decryption not possible returns text as is

        param text: plain text
        type text: str
        param addr: tuple of ip and port
        type addr: tuple

        return: text
        rtype: str
        """
        self.clean_up()
        key = self.keys.get(tuple(addr))
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
        logger.debug("vse decrypt {}: {}".format(addr, encrypted_text.replace("\n", "")))
        if not addr:
            return encrypted_text

        key = self.keys.get(tuple(addr), False)
        if not key:
            return encrypted_text

        try:
            text = vault_udp_socket_helper.decrypt_sym(str(key), encrypted_text)
        except TypeError:
            text = encrypted_text
        except nacl.exceptions.InvalidkeyError:
            text = encrypted_text
        except Exception as e:
            logger.info("sym decryption error: {}".format(e))
            text = encrypted_text
        logger.debug("vse decrypted {}: {}".format(addr, text.replace("\n", "")))
        return text


if __name__ == '__main__':
    logger = logging.getLogger(__name__)
    logging.basicConfig(level=logging.DEBUG)

    print("moin")
    vase = VaultAsymmetricEncryption()
    print(vase)

    print("tag")
    vse = VaultSymmetricEncryption()
    print(vse)
