"""
enVector High-Level API End-to-End Example

This example demonstrates the following steps using the high-level enVector API:
- Initialize the enVector environment
- Create an index
- Insert random vector data
- Search vectors
- Clean up index and key

How to run:
    python ./example/e2e_high_level_api.py
"""

import argparse

import pyenvector as ev


def main(args):
    # Initialize enVector

    ENVECTOR_ADDRESS = f"{args.host}:{args.port}"
    ev.init_connect(address=ENVECTOR_ADDRESS)
    if args.index_name in ev.get_index_list():
        ev.drop_index(args.index_name)
    if args.key_id in ev.get_key_list():
        ev.unload_key(args.key_id)
    print("enVector example resources cleaned up.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="enVector INIT")
    parser.add_argument("--host", type=str, default="localhost", help="Host for enVector connection")
    parser.add_argument("--port", type=int, default=50050, help="Port for enVector connection")
    parser.add_argument("--index-name", type=str, default="basic_init_idx", help="Index name to drop")
    parser.add_argument("--key-id", type=str, default="test-key-mm32-ip3", help="Key ID to unload")
    args = parser.parse_args()
    main(args)
