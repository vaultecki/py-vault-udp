import vault_udp_socket_helper
import time
import random
import math
import logging

logger = logging.getLogger(__name__)


class VaultEncryption:
    def __new__(cls, name, bases, dict):
        needed_functions = ["encrypt", "decrypt"]
        for function in needed_functions:
            if function not in dict:
                raise Exception("class not complete")

    def key_exists(self, addr):
        """checks if key for given addr exists in dict

        :return: true if key exists, false if not
        :rtype: bool
        """
        self.__clean_up()
        return tuple(addr) in self.__keys

    def update_key(self, addr, key):
        """sets a key for later use in encryption for given address port pair

        param addr: tuple of address port pair
        type addr: tuple
        param key: public key to use with address for encryption
        type key: str
        """
        if key:
            logger.debug("ve: update Key: {} for {}".format(key, addr))
            self.__keys.update({tuple(addr): key})
            self.__keys_last_update.update({tuple(addr): math.floor(time.time())})

    def remove_key(self, addr):
        """remove key from dict

        :return: public key
        :rtype: str
        """
        if tuple(addr) in self.__keys:
            logger.info("ve: remove key for addr {}".format(addr))
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


class AsymmetricEncryption(metaclass=VaultEncryption):
    def __init__(self, lifetime=60):
        self.__keys = {}
        self.__keys_last_update = {}
        self.key_max_lifetime = lifetime
        self.run_clean_ups = True

    def encrypt(self):
        pass

    def decrypt(self):
        pass


if __name__ == '__main__':
    print("moin")
    ase = AsymmetricEncryption()
    print(ase)
