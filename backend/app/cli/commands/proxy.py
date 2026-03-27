"""
CLI handler for the ph-proxy subcommand.

Starts the forward intercepting proxy.
"""


def handle(args, display):
    """
    Start ph-proxy with the given CLI arguments.
    """

    display.info(f'Starting ph-proxy on :{args.port}')

    if args.verbose:
        display.info('Verbose mode: showing full request/response headers')

    from app.core.proxy.server import run

    run(port=args.port, verbose=args.verbose)

    return 0
