#!/bin/python3
import sys
import os
import argparse
import info


parser = argparse.ArgumentParser()
parser.add_argument(
    "-v",
    "--version",
    action="version",
    version=info.version,
    help="show version",
)


def main():
    args = parser.parse_args()
    pass


if __name__ == "__main__":
    main()
