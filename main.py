import os
import sys

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def increment_counter(counter):
    return (int.from_bytes(counter, "big") + 1).to_bytes(len(counter), "big")


def encrypt_cbc(plaintext: bytes, key: bytes):
    block_size = 16
    random_iv = os.urandom(block_size)
    plaintext = pad(plaintext, block_size)

    cipher_blocks = []
    previous_block = random_iv

    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i : i + block_size]
        xored_block = xor(block, previous_block)
        encrypted_block = cipher.encrypt(xored_block)
        cipher_blocks.append(encrypted_block)
        previous_block = encrypted_block

    return random_iv + b"".join(cipher_blocks)


def decrypt_cbc(ciphertext: bytes, key: bytes):
    block_size = 16
    random_iv = ciphertext[0:block_size]
    ciphertext = ciphertext[block_size:]

    plaintext = []
    previous_block = random_iv

    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i : i + block_size]
        decrypted_block = cipher.decrypt(block)
        plaintext_block = xor(decrypted_block, previous_block)
        plaintext.append(plaintext_block)
        previous_block = block

    return unpad(b"".join(plaintext), block_size)


def encrypt_ctr(plaintext: bytes, key: bytes):
    block_size = 16

    random_iv = os.urandom(block_size)
    counter = random_iv
    ciphertext = b""

    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i : i + block_size]
        keystream = cipher.encrypt(counter)
        ciphertext += xor(block, keystream[: len(block)])
        counter = increment_counter(counter)

    return random_iv + ciphertext


def decrypt_ctr(ciphertext: bytes, key: bytes):
    block_size = 16
    random_iv = ciphertext[0:block_size]
    ciphertext = ciphertext[block_size:]

    plaintext = b""
    counter = random_iv

    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(0, len(ciphertext), block_size):
        block = ciphertext[i : i + block_size]
        keystream = cipher.encrypt(counter)
        plaintext += xor(block, keystream[: len(block)])
        counter = increment_counter(counter)

    return plaintext


def main():
    args = sys.argv
    if len(args) != 5:
        print(
            'Invalid input.\nExpected usage: python3 main.py <method> <strategy> <param1> <param2>\nWhere, if method is "encrypt", param1 = key and param2 = plaintext, and if method is "decrypt", param1 = key and param2 = ciphertext.',
        )
        sys.exit(1)

    method = args[1]
    strategy = args[2]

    if method != "encrypt" and method != "decrypt":
        print('Invalid method.\nExpected "encrypt" or "decrypt".')
        sys.exit(1)

    if strategy != "cbc" and strategy != "ctr":
        print('Invalid strategy.\nExpected "cbc" or "ctr".')
        sys.exit(1)

    match method:
        case "encrypt":
            key = bytes.fromhex(args[3])
            plaintext = args[4].encode()
            match strategy:
                case "cbc":
                    print("CBC Encrypt")
                    encrypted = encrypt_cbc(plaintext, key)
                    print("Ciphertext:", encrypted.hex())
                case "ctr":
                    print("CTR Encrypt")
                    encrypted = encrypt_ctr(plaintext, key)
                    print("Ciphertext:", encrypted.hex())
        case "decrypt":
            key = bytes.fromhex(args[3])
            cipher = bytes.fromhex(args[4])
            match strategy:
                case "cbc":
                    print("CBC Decrypt")
                    decrypted = decrypt_cbc(cipher, key)
                    print("Message:", decrypted.decode())
                case "ctr":
                    print("CTR Decrypt")
                    decrypted = decrypt_ctr(cipher, key)
                    print("Message:", decrypted.decode())

    sys.exit(0)


if __name__ == "__main__":
    main()
