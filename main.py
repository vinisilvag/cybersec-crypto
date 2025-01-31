import os
import sys

from Crypto.Cipher import AES


# pad function
def pkcs5_pad(data: bytes, block_size: int) -> bytes:
    pad_len = block_size - (len(data) % block_size)
    return data + bytes([pad_len] * pad_len)


# unpad function
def pkcs5_unpad(data: bytes, block_size: int) -> bytes:
    pad_len = data[-1]
    if (
        pad_len < 1
        or pad_len > block_size
        or data[-pad_len:] != bytes([pad_len] * pad_len)
    ):
        raise ValueError("Invalid padding")
    return data[:-pad_len]


# apply the XOR gate between two bytes
def xor(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# increment the counter
def increment_counter(counter: bytes) -> bytes:
    # get the integer from the bytes with big endian order, increment and encode again
    return (int.from_bytes(counter, "big") + 1).to_bytes(len(counter), "big")


# encrypt based on the CBC method
def encrypt_cbc(plaintext: bytes, key: bytes) -> bytes:
    # define the block size
    block_size = 16

    # generate the random IV and pad the plaintext with the size of the block
    random_iv = os.urandom(block_size)
    plaintext = pkcs5_pad(plaintext, block_size)

    # initialize the cipher blocks
    cipher_blocks = []
    previous_block = random_iv

    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(0, len(plaintext), block_size):
        # get the block and do the XOR with the previous block
        block = plaintext[i : i + block_size]
        xored_block = xor(block, previous_block)
        # encrypt using AES
        encrypted_block = cipher.encrypt(xored_block)
        # append and update the previous block to the recently ciphered block
        cipher_blocks.append(encrypted_block)
        previous_block = encrypted_block

    # append the random IV with the cipher blocks
    return random_iv + b"".join(cipher_blocks)


# decrypt based on the CBC method
def decrypt_cbc(ciphertext: bytes, key: bytes) -> bytes:
    # define the block size
    block_size = 16

    # extract the ciphered text and the random IV
    random_iv = ciphertext[0:block_size]
    ciphertext = ciphertext[block_size:]

    # plaintext list
    plaintext = []
    previous_block = random_iv

    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(0, len(ciphertext), block_size):
        # extract the block and decrypt using AES
        block = ciphertext[i : i + block_size]
        decrypted_block = cipher.decrypt(block)
        # do the XOR with the previous block to get the plaintext
        plaintext_block = xor(decrypted_block, previous_block)
        # append to the list and update the previous block
        plaintext.append(plaintext_block)
        previous_block = block

    # join the plaintext blocks list and remove the padding
    return pkcs5_unpad(b"".join(plaintext), block_size)


# encrypt based on the CTR method
def encrypt_ctr(plaintext: bytes, key: bytes) -> bytes:
    # define the block size
    block_size = 16

    # generate the random IV and start the counter and the ciphertext bytes
    random_iv = os.urandom(block_size)
    counter = random_iv
    ciphertext = b""

    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(0, len(plaintext), block_size):
        # extract the block and generate the keystream by encrypting the counter
        block = plaintext[i : i + block_size]
        keystream = cipher.encrypt(counter)
        # get the ciphertext doing the XOR between the block and the keystream generated with the len of the block
        ciphertext += xor(block, keystream[: len(block)])
        # increment the counter
        counter = increment_counter(counter)

    # return ciphertext with the random IV as prefix
    return random_iv + ciphertext


# decrypt based on the CTR method
def decrypt_ctr(ciphertext: bytes, key: bytes) -> bytes:
    # define the block size
    block_size = 16

    # extract the random IV and the ciphertext
    random_iv = ciphertext[0:block_size]
    ciphertext = ciphertext[block_size:]

    # define the plaintext bytes and the initial counter
    plaintext = b""
    counter = random_iv

    cipher = AES.new(key, AES.MODE_ECB)
    for i in range(0, len(ciphertext), block_size):
        # extract the block and generate the keystream by encrypting the counter
        block = ciphertext[i : i + block_size]
        keystream = cipher.encrypt(counter)
        # get the plaintext doing the XOR between the block and the keystream prefix with the size of the block
        plaintext += xor(block, keystream[: len(block)])
        # increment the counter
        counter = increment_counter(counter)

    # return the plaintext
    return plaintext


def main():
    # parse arguments
    args = sys.argv
    if len(args) != 5:
        print(
            'Invalid input.\nExpected usage: python3 main.py <method> <strategy> <param1> <param2>\nWhere, if method is "encrypt", param1 = key and param2 = plaintext, and if method is "decrypt", param1 = key and param2 = ciphertext.',
        )
        sys.exit(1)

    # extract the method and the cryptography strategy used
    method = args[1]
    strategy = args[2]

    # validate method and strategy
    if method != "encrypt" and method != "decrypt":
        print('Invalid method.\nExpected "encrypt" or "decrypt".')
        sys.exit(1)
    if strategy != "cbc" and strategy != "ctr":
        print('Invalid strategy.\nExpected "cbc" or "ctr".')
        sys.exit(1)

    # apply the method + strategy and return the result
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
