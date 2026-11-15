#!/usr/bin/env python3
"""Check the M6 -> M5 link from the command line. READ-ONLY plus event delivery: it never sends an action.

  python3 backend/m5_tool.py health              ask the M5 gateway if it is ready
  python3 backend/m5_tool.py cases               list M5 cases
  python3 backend/m5_tool.py case CASE_ID        one case (latest risk decision, process and resource operations)
  python3 backend/m5_tool.py timeline CASE_ID    the case's audit timeline
  python3 backend/m5_tool.py decisions CASE_ID   the case's risk decisions
  python3 backend/m5_tool.py poll [--loop SECS]  fetch M5 events, store them in M6, then acknowledge them

Settings come from the environment / .env (see .env.example, section "M5 gateway"). Nothing secret is printed.
"""
import argparse
import json
import sys
import time
from pathlib import Path

from dotenv import load_dotenv

sys.path.insert(0, str(Path(__file__).resolve().parent))
load_dotenv(Path(__file__).resolve().parents[1] / ".env")

from app.integrations.base import IntegrationError  # noqa: E402
from app.integrations.m5.delivery import EventDelivery  # noqa: E402
from app.integrations.m5.gateway import M5Gateway  # noqa: E402
from app.integrations.m5.gateway_config import M5ConfigError, M5GatewayConfig  # noqa: E402
from app.integrations.m5.state_store import M6Store  # noqa: E402


def main(argv=None, env=None, transport=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("health"), sub.add_parser("cases")
    for name in ("case", "timeline", "decisions"):
        sub.add_parser(name).add_argument("case_id")
    poll = sub.add_parser("poll")
    poll.add_argument("--loop", type=float, metavar="SECS", help="repeat every SECS seconds (Ctrl+C to stop)")
    args = parser.parse_args(argv)
    try:
        config = M5GatewayConfig.from_env(env)
        gateway = M5Gateway(config, M6Store(config.data_dir), transport=transport)
    except M5ConfigError as exc:
        print(f"M5 configuration problem: {exc}", file=sys.stderr)
        return 2
    try:
        if args.command == "poll":
            delivery = EventDelivery(gateway, gateway.store)
            while True:
                print(json.dumps(delivery.poll_once(), sort_keys=True))
                if not args.loop:
                    return 0
                time.sleep(args.loop)
        call = {"health": gateway.status, "cases": gateway.list_cases, "case": lambda: gateway.get_case(args.case_id),
                "timeline": lambda: gateway.timeline(args.case_id), "decisions": lambda: gateway.risk_decisions(args.case_id)}[args.command]
        print(json.dumps(call(), indent=2, sort_keys=True))
        return 0
    except IntegrationError as exc:
        print(f"{exc.code}: {exc.message}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
