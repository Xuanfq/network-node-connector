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

subparser = parser.add_subparsers()

parser_server = subparser.add_parser("server", help="server command")
server_action_group = parser_server.add_mutually_exclusive_group(required=True)
server_action_group.add_argument("--start", action="store_true")
server_action_group.add_argument("--stop", action="store_true")
server_action_group.add_argument("--status", action="store_true")
server_action_group.add_argument("--restart", action="store_true")
server_action_group.add_argument_group()


def main():
    args = parser.parse_args()
    pass


if __name__ == "__main__":
    main()
