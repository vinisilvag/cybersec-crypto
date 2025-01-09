import sys


def encrypt():
    pass


def decrypt():
    pass


def main():
    args = sys.argv
    if len(args) != 4:
        print(
            "Invalid input.\nExpected usage: python3 main.py <strategy> <key> <cipher>",
        )
        sys.exit(1)

    strategy = args[1]
    key = args[2]
    cipher = args[3]

    match strategy:
        case "cbc":
            print("cbc")
            pass
        case "ctr":
            print("ctr")
            pass
        case _:
            print('Invalid strategy.\nExpected "cbc" or "ctr".')
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
