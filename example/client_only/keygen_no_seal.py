import argparse
import os

from pyenvector.crypto import KeyGenerator

DIM = 512  # Dimension for the context


def main(key_path, key_id):
    # Key Path
    key_dir = f"{key_path}/{key_id}"

    # Delete existing keys if they exist
    if os.path.exists(key_dir):
        for file in os.listdir(key_dir):
            file_path = os.path.join(key_dir, file)
            if os.path.isfile(file_path):
                os.remove(file_path)
        print(f"Deleted existing keys in {key_dir}")

    # Generate keys
    keygen = KeyGenerator(key_dir)
    keygen.generate_keys()
    print(f"Generated keys in {key_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="enVector KeyGen Example")
    parser.add_argument("--key_path", type=str, default="./keys", help="Path to the directory where keys are stored")
    parser.add_argument("--key_id", type=str, default="test-key", help="ID of the key to generate")
    args = parser.parse_args()

    main(args.key_path, args.key_id)
