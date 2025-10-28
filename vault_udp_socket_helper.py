import base64
import nacl.encoding
import nacl.hash
import nacl.public
import nacl.secret
import nacl.signing
import nacl.utils


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


if __name__ == '__main__':
    text = "geheim"

    pw = "12345"
    hasher = nacl.hash.sha256
    secret = hasher(pw.encode("utf-8"), encoder=nacl.encoding.Base64Encoder).decode("utf-8")

    # asym encryption
    pub_key, private_key = generate_keys_asym()
    print("public key: {}, type: {}".format(pub_key, type(pub_key)))
    print("private key: {}, type: {}".format(private_key, type(private_key)))

    encrypted_text = encrypt_asym(pub_key, text)
    print("asym encrypted: {}, type: {}".format(encrypted_text, type(encrypted_text)))

    plaintext = decrypt_asym(private_key, encrypted_text)
    print("asym decrypted: {}, type: {}".format(plaintext, type(plaintext)))

