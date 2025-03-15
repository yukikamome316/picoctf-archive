import sys
import ast


def extract_hex(scrambled):
    """Traverse the top-level lists and keep only items that are strings starting with '0x'."""
    hex_items = []
    for sub in scrambled:
        # Only consider items that are plain strings, not nested lists.
        for item in sub:
            if isinstance(item, str) and item.startswith("0x"):
                hex_items.append(item)
    return hex_items


def decode_hex_flag(hex_list):
    """Convert list of "0x.." hex strings into a text flag."""
    # Convert each hex string to a character.
    return "".join(chr(int(h, 16)) for h in hex_list)


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <scrambled_file>")
        sys.exit(1)

    # Read scrambled structure from file.
    with open(sys.argv[1], "r") as f:
        data = f.read()

    # Safely parse the printed scrambled structure.
    try:
        scrambled = ast.literal_eval(data)
    except Exception as e:
        print("Error parsing the scrambled data:", e)
        sys.exit(1)

    # Unscramble by extracting hex strings and decoding them.
    hex_list = extract_hex(scrambled)
    flag = decode_hex_flag(hex_list)
    print("Recovered flag:")
    print(flag)


if __name__ == "__main__":
    main()
