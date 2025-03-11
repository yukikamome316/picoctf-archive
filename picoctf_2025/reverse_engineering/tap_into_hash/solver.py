import sys
import hashlib
import codecs


def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))


def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]


def decrypt(encrypted, key):
    block_size = 16
    key_hash = hashlib.sha256(key).digest()

    decrypted = b""
    for i in range(0, len(encrypted), block_size):
        block = encrypted[i : i + block_size]
        decrypted += xor_bytes(block, key_hash)

    unpadded = unpad(decrypted)
    return unpadded.decode("utf-8")


def parse_bytes_literal(literal):
    literal = literal.strip()
    if literal.startswith("b'") or literal.startswith('b"'):
        inner = literal[2:-1]
        return codecs.decode(inner, "unicode_escape").encode("latin1")
    else:
        raise ValueError("Not a valid bytes literal")


def main():
    try:
        with open("enc_flag", "r") as f:
            lines = f.read().splitlines()
    except Exception as e:
        print("Error reading enc_flag file:", e)
        sys.exit(1)

    try:
        key_line = next(line for line in lines if line.startswith("Key:"))
        enc_line = next(
            line for line in lines if line.startswith("Encrypted Blockchain:")
        )
        key_literal = key_line[len("Key:") :].strip()
        encrypted_literal = enc_line[len("Encrypted Blockchain:") :].strip()

        key = parse_bytes_literal(key_literal)
        encrypted = parse_bytes_literal(encrypted_literal)
    except Exception as e:
        print("Error parsing enc_flag file:", e)
        sys.exit(1)

    decrypted_message = decrypt(encrypted, key)
    print("Decrypted Blockchain:", decrypted_message)


if __name__ == "__main__":
    main()
