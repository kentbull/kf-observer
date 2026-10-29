# -*- encoding: utf-8 -*-
"""
kfobserver.app.cli.commands.start module

``kf-observer start``: Habery plus HTTP observer node.
"""

import argparse
import logging
import sys
import os

from hio.base import doing
from keri import __version__, help
from keri.app import Configer, Habery, HaberyDoer, Keeper
from keri.cli.common.existing import setupHby
from keri.kering import AuthError, ConfigurationError, Vrsn_2_0

from kfobserver.core import serving, evidence


d = "Runs KERI Foundation observer controller.\n"
d += "Example:\nkf-observer start -a observer -H 6633 --registrar http://127.0.0.1:6632/\n"
parser = argparse.ArgumentParser(description=d)
parser.set_defaults(handler=lambda args: launch(args))
parser.add_argument(
    "-V",
    "--version",
    action="version",
    version=__version__,
    help="Prints out version of script runner.",
)
parser.add_argument(
    "-H",
    "--http",
    action="store",
    default=6633,
    help="Local port number the HTTP server listens on. Default is 6633.",
)
parser.add_argument(
    "-o",
    "--host",
    action="store",
    default="127.0.0.1",
    help="Local host IP address the HTTP server listens on. Default is 127.0.0.1.",
)
parser.add_argument(
    "-n",
    "--name",
    action="store",
    default="observer",
    help="Name of controller. Default is observer.",
)
parser.add_argument(
    "--alias",
    "-a",
    help="human readable alias for the observer identifier prefix",
    default="observer",
)
parser.add_argument(
    "--base",
    "-b",
    help="additional optional prefix to file location of KERI keystore",
    required=False,
    default="",
)
parser.add_argument(
    "--passcode",
    "-p",
    help="22 character encryption passcode for keystore (is not saved)",
    dest="bran",
    default=os.getenv("KLI_KEYSTORE_PASSCODE"),
)
parser.add_argument(
    "--config-dir",
    "-c",
    dest="configDir",
    help="directory override for configuration data",
)
parser.add_argument(
    "--config-file",
    dest="configFile",
    action="store",
    default=None,
    help="configuration filename override",
)
parser.add_argument(
    "--registrar",
    action="append",
    dest="registrars",
    default=None,
    help="Registrar external base URL to poll for bulk TEL. Repeatable.",
)
parser.add_argument(
    "--registrar-ca",
    dest="registrarCa",
    default=None,
    help="Absolute CA bundle path for full-evidence HTTPS registrar sources.",
)
parser.add_argument(
    "--registrar-certedhost",
    action="append",
    dest="registrarCertedhosts",
    default=[],
    metavar="IP=HOSTNAME",
    help=("Required certificate hostname for a full-evidence registrar IP URL. "
          "Repeatable; DNS URLs use their URL hostname."),
)
parser.add_argument(
    "--witness",
    action="append",
    dest="witnesses",
    default=None,
    help=(
        "Witness base URL for issuer KEL fallback (GET /log). "
        "Optional #AID for CESR-DESTINATION, e.g. http://127.0.0.1:5642/#B.... "
        "Repeatable."
    ),
)
parser.add_argument(
    "--poll",
    action="store",
    default=5.0,
    type=float,
    help="Seconds between full-clone registrar polls. Default is 5.0.",
)
parser.add_argument("--full-evidence", action="store_true",
                    help="Use independent complete-proof polling and cache-only queries.")
parser.add_argument("--reader", action="append", default=[], help="Authorized reader AID.")
parser.add_argument("--kel", action="append", default=[], help="Signed KEL bootstrap path.")
parser.add_argument("--timeout", type=float, default=5.0,
                    help="Per-source cooperative HTTP deadline in seconds.")
parser.add_argument(
    "--loglevel",
    action="store",
    required=False,
    default="INFO",
    help="Set log level to DEBUG | INFO | WARNING | ERROR | CRITICAL. Default is INFO",
)
parser.add_argument("--keypath", action="store", required=False, default=None)
parser.add_argument("--certpath", action="store", required=False, default=None)
parser.add_argument("--cafilepath", action="store", required=False, default=None)
parser.add_argument(
    "--no-prompt",
    action="store_true",
    default=None,
    required=False,
    help="Disable interactive prompt",
    dest="noPrompt",
)

FORMAT = "%(asctime)s [kf-observer] %(levelname)-8s %(message)s"


def launch(args):
    """Configure logging and start the observer operational node."""
    help.ogler.level = logging.getLevelName(args.loglevel)
    baseFormatter = logging.Formatter(FORMAT)
    baseFormatter.default_msec_format = None
    help.ogler.baseConsoleHandler.setFormatter(baseFormatter)
    logger = help.ogler.getLogger()

    logger.info(
        "******* Starting kf-observer http/%s:%s ******",
        args.host,
        args.http,
    )

    runObserver(args)

    logger.info(
        "******* Ended kf-observer http/%s:%s ******",
        args.host,
        args.http,
    )


def runObserver(args, expire=0.0):
    """Run the selected observer profile with a caller-specified HIO time limit.

    Parameters:
        args: parsed policy, identity, transport and optional full-evidence flags.
        expire: seconds until normal completion; zero runs until cancellation.
    The original adapter remains the default. The complete-evidence profile
    uses separate reader authorization and independent source acquisition.
    """
    noPrompt = args.noPrompt if args.noPrompt is not None else not sys.stdin.isatty()

    ks = Keeper(name=args.name, base=args.base, temp=False, reopen=True)
    aeid = ks.gbls.get("aeid")
    ks.close()

    cf = None
    if args.configFile:
        cf = Configer(
            name=args.configFile,
            headDirPath=args.configDir,
            temp=False,
            reopen=True,
            clear=False,
        )

    hby = None
    ctx = None
    try:
        if aeid is None:
            hby = Habery(name=args.name, base=args.base, bran=args.bran, cf=cf, version=Vrsn_2_0)
        else:
            if not args.bran and noPrompt:
                raise AuthError(
                    f"passcode required for keystore {args.name!r} but prompting is disabled."
                )
            hby = setupHby(
                name=args.name,
                base=args.base,
                bran=args.bran,
                cf=cf,
                noPrompt=noPrompt,
                version=Vrsn_2_0,
            )

        hbyDoer = HaberyDoer(habery=hby)
        doers = [hbyDoer]
        if args.full_evidence:
            if args.witnesses:
                raise ConfigurationError("full-evidence profile obtains witness evidence from registrar streams")
            ctx, workers = evidence.setup(hby, alias=args.alias, host=args.host,
                port=int(args.http), registrars=args.registrars, readers=args.reader,
                kel=args.kel, interval=args.poll,
                timeout=args.timeout, registrarCafilepath=args.registrarCa,
                registrarCertedhosts=args.registrarCertedhosts,
                keypath=args.keypath, certpath=args.certpath,
                cafilepath=args.cafilepath)
            doers.extend(workers)
        else:
            doers.extend(serving.setup(hby=hby, alias=args.alias, host=args.host,
                port=int(args.http), registrars=args.registrars, witnesses=args.witnesses,
                pollTock=float(args.poll), keypath=args.keypath,
                certpath=args.certpath, cafilepath=args.cafilepath))

        tock = 0.00125
        doist = doing.Doist(limit=expire, tock=tock, real=True)
        doist.do(doers=doers)
    finally:
        if ctx is not None:
            ctx.close()
        if hby is not None:
            hby.close()
