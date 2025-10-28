import base64
import nacl.encoding
import nacl.hash
import nacl.public
import nacl.secret
import nacl.signing
import nacl.utils


def bytes_to_b64_str(data: bytes) -> str:
    """Konvertiert bytes in einen Base64-codierten String."""
    return base64.b64encode(data).decode('utf-8')


def b64_str_to_bytes(data: str) -> bytes:
    """Konvertiert einen Base64-codierten String zurück in bytes."""
    if isinstance(data, bytes):
         data = data.decode('utf-8')
    return base64.b64decode(data.encode('utf-8'))


def generate_keys_asym():
    """generates public/ private key pair with pynacl and returns them as strings

    :return: public_key, private_key
    :rtype: str, str
    """
    private_key = nacl.public.PrivateKey.generate()
    public_key = bytes_to_b64_str(bytes(private_key.public_key))
    private_key = bytes_to_b64_str(bytes(private_key))
    return public_key, private_key


def generate_public_key(private_key):
    """generates a public key for a given private key with pynacl

    param private_key: private key as str
    type private_key: str

    return: return public key
    rtype: str
    """
    private_key = nacl.public.PrivateKey(b64_str_to_bytes(private_key))
    public_key = bytes_to_b64_str(bytes(private_key.public_key))
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
    if isinstance(message, str):
        message = message.encode("utf-8")
    if not isinstance(message, bytes):
        raise TypeError
    encrypt_box = nacl.public.SealedBox(nacl.public.PublicKey(b64_str_to_bytes(public_key)))
    encrypted = encrypt_box.encrypt(message, encoder=nacl.encoding.Base64Encoder)
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
    if isinstance(message, str):
        message = message.encode("utf-8")
    if not isinstance(message, bytes):
        raise TypeError
    decrypt_box = nacl.public.SealedBox(nacl.public.PrivateKey(b64_str_to_bytes(private_key)))
    decrypted = decrypt_box.decrypt(message, encoder=nacl.encoding.Base64Encoder)
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

