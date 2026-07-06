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
    ev.init_index_config(key_path="./keys", auto_key_setup=False)
    if args.index_name in ev.get_index_list():
        ev.drop_index(args.index_name)
    key_info = ev.get_key_info(args.key_id) if args.key_id in ev.get_key_list() else {}
    if key_info.get("is_loaded"):
        ev.unload_key(args.key_id)
    print("enVector example resources cleaned up.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="enVector INIT")
    parser.add_argument("--host", type=str, default="localhost", help="Host for enVector connection")
    parser.add_argument("--port", type=int, default=50050, help="Port for enVector connection")
    parser.add_argument("--index-name", type=str, default="basic_twostep_idx", help="Index name to drop")
    parser.add_argument("--key-id", type=str, default="test-key-mm32-ip3", help="Key ID to unload")
    parser.add_argument("--eval-mode", "--eval_mode", dest="eval_mode", type=str, default="mm32", choices=["mm", "mms", "mm32", "mms32"], help="Evaluation mode")
    parser.add_argument("--preset", type=str, default="ip3", help="Parameter preset")
    args = parser.parse_args()
    main(args)
