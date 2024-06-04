
import argparse

from encryption import decrypt_file, encrypt_file
from generate_key import generate_key_iv

def main():
    parser = argparse.ArgumentParser(
        description="AES File Encryption/Decryption Tool",
        formatter_class=argparse.RawTextHelpFormatter
    )

    parser.add_argument(
        "--mode", 
        choices=["encrypt", "decrypt"], 
        required=True,
        help="Mode of operation:\n"
            "  encrypt - Encrypt the file\n"
            "  decrypt - Decrypt the file"
    )
    parser.add_argument(
        "--file", 
        required=True,
        help="Path to the file to encrypt or decrypt"
    )
    parser.add_argument(
        "--key", 
        help="Encryption/Decryption key (32 bytes for AES-256)\n"
            "Required only for decryption mode.",
        nargs='?', 
        default=None
    )

    args = parser.parse_args()

    if args.mode == "encrypt":
        key, iv = generate_key_iv()
        encrypt_file(args.file, key, iv)
        print(f"File encrypted. Key: {key.hex()}")
    elif args.mode == "decrypt":
        if not args.key:
            print("Decryption key required for decrypt mode.")
            return
        key = bytes.fromhex(args.key)
        decrypt_file(args.file, key)
        print("File decrypted.")

if __name__ == "__main__":
    main()
