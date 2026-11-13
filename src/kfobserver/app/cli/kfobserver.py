# -*- encoding: utf-8 -*-
"""
kfobserver.app.cli.kfobserver module

CLI entry point for the observer operational network.
"""

import multicommand
from keri import help
from keri.app.directing import runController

from kfobserver.app.cli import commands
from kfobserver.core import evidence


logger = help.ogler.getLogger()


def main():
    """Entry point for the kf-observer CLI."""
    parser = multicommand.create_parser(commands)
    args = parser.parse_args()

    if not hasattr(args, "handler"):
        parser.print_help()
        return

    try:
        doers = args.handler(args)
        if not doers:
            return
        runController(doers=doers, expire=0.0, tock=evidence.doistTock())
    except Exception as ex:
        print(f"ERR: {ex}")
        return -1


if __name__ == "__main__":
    main()
