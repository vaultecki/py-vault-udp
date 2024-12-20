import base64
import nacl.encoding
import nacl.hash
import nacl.public
import nacl.secret
import nacl.signing
import nacl.utils
import pynewhope.newhope


def encrypt_sym(key, message):
    """uses nacl symmetric encryption box to encrypt message

    param key: secret for nacl box
    type key: str
    param message: message to encrypt
    type message: str

    return: returns base64 coded encrypted str
    rtype: str
    """
    if type(message) is not str and type(message) is not bytes:
        message = "{}".format(message)
    if type(message) is str:
        message = message.encode("utf-8")
    if not type(message) is bytes:
        raise TypeError
    sym_hasher = nacl.hash.sha256
    key_bytes = sym_hasher(key.encode("utf-8"), encoder=nacl.encoding.RawEncoder)
    box = nacl.secret.SecretBox(key_bytes)
    encrypted = bytes(box.encrypt(message))
    encrypted_binary_str = base64.b64encode(encrypted).decode("utf-8")
    return encrypted_binary_str


def decrypt_sym(key, encrypted_binary_str):
    """uses nacl symmetric encryption box to decrypt message

    param key: secret for nacl box
    type key: str
    param encrypted_binary_str: base64 encoded encrypted message
    type encrypted_binary_str: str

    return: returns decrypted message
    rtype: str
    """
    sym_hasher = nacl.hash.sha256
    key_bytes = sym_hasher(key.encode("utf-8"), encoder=nacl.encoding.RawEncoder)
    encrypted_bytes = base64.b64decode(encrypted_binary_str)
    box = nacl.secret.SecretBox(key_bytes)
    plaintext_str = box.decrypt(encrypted_bytes).decode("utf-8")
    return plaintext_str


def message_sign(private_key, message):
    signing_key = nacl.signing.SigningKey(private_key.encode())
    signed = signing_key.sign(message)
    return signed


def message_verify(public_key, message):
    verify_key = nacl.signing.VerifyKey(public_key.encode())
    return_value = 1
    try:
        verify_key.verify(message)
    except Exception as e:
        print("Error {}".format(e))
        return_value = False
    return return_value


def to_base64(msg):
    if type(msg) is str:
        return base64.b64encode(msg.encode('utf-8'))
    if type(msg) is bytes:
        return base64.b64encode(msg)


def to_base64_str(msg):
    if type(msg) is str:
        return base64.b64encode(msg.encode('utf-8')).decode('utf-8')
    if type(msg) is bytes:
        return base64.b64encode(msg).decode('utf-8')


def from_base64_byte(msg):
    if type(msg) is str:
        return base64.b64decode(msg)


def from_base64_str(msg):
    if type(msg) is str:
        return base64.b64decode(msg).decode('utf-8')


def to_binary(msg):
    binary = base64.b64decode(msg)
    return binary


def generate_keys_asym():
    """generates public/ private key pair with pynacl and returns them as strings

    :return: public_key, private_key
    :rtype: str, str
    """
    private_key = nacl.public.PrivateKey.generate()
    public_key = to_base64_str(bytes(private_key.public_key))
    private_key = to_base64_str(bytes(private_key))
    return public_key, private_key


def generate_public_key(private_key):
    """generates a public key for a given private key with pynacl

    param private_key: private key as str
    type private_key: str

    return: return public key
    rtype: str
    """
    private_key = nacl.public.PrivateKey(to_binary(private_key))
    public_key = to_base64_str(bytes(private_key.public_key))
    return public_key


def encrypt_asym(public_key, message):
    """asymmetric encryption for a message with pynacl

    param public_key: public key used for encryption as str
    type public_key: str
    param message: message to encrypt as str or bytes
    type message: str or bytes

    return: encrypted message
    rtype: str
    """
    if type(message) is str:
        message = message.encode("utf-8")
    if not type(message) is bytes:
        raise TypeError
    encrypt_box = nacl.public.SealedBox(nacl.public.PublicKey(to_binary(public_key)))
    encrypted = encrypt_box.encrypt(message, encoder=nacl.encoding.Base64Encoder).decode("utf-8")
    return encrypted


def decrypt_asym(private_key, message):
    """asymmetric decryption for a message with pynacl

    param private_key: key used for decryption
    type private_key: str
    param message: message to decrypt as str or bytes
    type message: str or bytes

    return: decrypted message
    rtype: str
    """
    if type(message) is str:
        message = message.encode("utf-8")
    if not type(message) is bytes:
        raise TypeError
    decrypt_box = nacl.public.SealedBox(nacl.public.PrivateKey(to_binary(private_key)))
    decrypted = decrypt_box.decrypt(message, encoder=nacl.encoding.Base64Encoder).decode("utf-8")
    return decrypted


def list_int_2_str(key):
    # warning for testing only - do not use it for production
    return_bytes = b''
    for number in key:
        # print("{} -> {}".format(number, hex(number)))
        return_bytes += hex(number).encode("utf-8")
    # print(return_bytes)
    return to_base64_str(return_bytes)


def str_to_list_int(base64_str):
    # warning for testing only - do not use it for production
    bytes_2_convert = from_base64_byte(base64_str)
    # print(bytes_2_convert.decode("utf-8").split("0x")[1:])
    list_integer = []
    for i in bytes_2_convert.decode("utf-8").split("0x")[1:]:
        list_integer.append(int(i, 16))
    return list_integer


def newhope_keygen():
    # warning for testing only - do not use it for production
    private_key, public_msg = pynewhope.newhope.keygen()
    private_key = list_int_2_str(private_key)
    public_msg = (list_int_2_str(public_msg[0]), to_base64_str(public_msg[1]))
    return public_msg, private_key


def newhope_shared_b(public_msg):
    # warning for testing only - do not use it for production
    public_msg = (str_to_list_int(public_msg[0]), from_base64_byte(public_msg[1]))
    shared_key, public_msg = pynewhope.newhope.sharedB(public_msg)

    public_msg = (list_int_2_str(public_msg[0]), list_int_2_str(public_msg[1]))
    shared_key = list_int_2_str(shared_key)
    return public_msg, shared_key


def newhope_shared_a(public_msg, private_key):
    # warning for testing only - do not use it for production
    public_msg = (str_to_list_int(public_msg[0]), str_to_list_int(public_msg[1]))
    private_key = (str_to_list_int(private_key))

    shared_key = pynewhope.newhope.sharedA(public_msg, private_key)
    shared_key = list_int_2_str(shared_key)
    return shared_key


if __name__ == '__main__':
    text = "geheim"

    pw = "12345"
    hasher = nacl.hash.sha256
    secret = hasher(pw.encode("utf-8"), encoder=nacl.encoding.Base64Encoder).decode("utf-8")

    # sym encryption
    print("sym key: {}, type: {}".format(secret, type(secret)))
    encrypted_text = encrypt_sym(secret, text)
    print("text encrypted: {}, type:{}".format(encrypted_text, type(encrypted_text)))

    decrypted_text = decrypt_sym(secret, encrypted_text)
    print("decrypted text: {}, type: {}".format(decrypted_text, type(decrypted_text)))

    # asym encryption
    pub_key, private_key = generate_keys_asym()
    print("public key: {}, type: {}".format(pub_key, type(pub_key)))
    print("private key: {}, type: {}".format(private_key, type(private_key)))

    encrypted_text = encrypt_asym(pub_key, text)
    print("asym encrypted: {}, type: {}".format(encrypted_text, type(encrypted_text)))

    plaintext = decrypt_asym(private_key, encrypted_text)
    print("asym decrypted: {}, type: {}".format(plaintext, type(plaintext)))

    # key exchange with newhope
    print("new hope key exchange test")
    public_msg, private_key = newhope_keygen()
    print("new hope - len public msg: ({}, {}) and public msg: {}".format(len(public_msg[0]),
                                                                          len(public_msg[1]), public_msg))
    print("new hope types - public_msg: ({}, {}) -> {}".format(type(public_msg[0]),
                                                               type(public_msg[1]), type(public_msg)))
    public_msg_2, shared_key = newhope_shared_b(list(public_msg))
    print("new hope - len public msg 2: ({}, {}) and public msg: {}".format(len(public_msg_2[0]),
                                                                            len(public_msg_2[1]), public_msg_2))
    print("new hope types - public_msg 2: ({}, {}) -> {}".format(type(public_msg_2[0]),
                                                                 type(public_msg_2[1]), type(public_msg_2)))

    shared_key_2 = newhope_shared_a(public_msg_2, private_key)
    print("new hope shared_key 1: {} -> type {}".format(shared_key, type(shared_key)))
    print("new hope shared_key 2: {} -> type {}".format(shared_key_2, type(shared_key_2)))

    encrypted_text = encrypt_sym(shared_key, text)
    print(encrypted_text)
    decrypted_text = decrypt_sym(shared_key_2, encrypted_text)
    print(decrypted_text)
