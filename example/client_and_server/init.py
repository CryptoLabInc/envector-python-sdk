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
    ev.reset()
    print("enVector reset.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="enVector INIT")
    parser.add_argument("--host", type=str, default="localhost", help="Host for enVector connection")
    parser.add_argument("--port", type=int, default=50050, help="Port for enVector connection")
    args = parser.parse_args()
    main(args)
