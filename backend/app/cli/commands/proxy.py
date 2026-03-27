"""
CLI handler for the ph-proxy subcommand.

Starts the forward intercepting proxy.
"""

import logging


def handle(args, display):
    """
    Start ph-proxy with the given CLI arguments.
    """

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format='%(asctime)s [%(name)s] %(levelname)s: %(message)s',
    )

    display.info(f'Starting ph-proxy on :{args.port}')

    from app.core.proxy.server import run

    run(port=args.port)

    return 0
