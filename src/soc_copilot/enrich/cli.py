"""
Command-line entrypoint for one-off enrichment lookups.

Usage:
    python -m soc_copilot.enrich.cli --ip 185.220.101.47
    python -m soc_copilot.enrich.cli --hash <sha256>

Reads VT_API_KEY / ABUSEIPDB_API_KEY from the environment (or a .env file
in the repo root, if python-dotenv is installed and one exists). Requires
at least one key to be set -- see .env.example.

Note: this file is *written* this week but has not been run against the
live VirusTotal/AbuseIPDB APIs from this environment, because this
sandbox's network egress is restricted to a fixed allowlist that does not
include virustotal.com or abuseipdb.com. Everything else in Week 2
(clients, service, retry/backoff, caching, the private-IP guard) is
verified with httpx.MockTransport-based unit tests instead -- see the
Week 2 devlog for the exact commands to run this for real with your own
keys, and please paste the output back so we can confirm it end-to-end.
"""

from __future__ import annotations

import argparse
import json
import sys

from soc_copilot.enrich.service import EnrichmentService

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass


def main() -> None:
    parser = argparse.ArgumentParser(description="Enrich one IP or file hash.")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--ip", help="IP address to look up")
    group.add_argument("--hash", help="SHA-256 file hash to look up")
    args = parser.parse_args()

    try:
        service = EnrichmentService.from_env()
    except RuntimeError as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)

    if args.ip:
        result = service.enrich_ip(args.ip)
    else:
        result = service.enrich_hash(args.hash)

    print(json.dumps(json.loads(result.model_dump_json()), indent=2))


if __name__ == "__main__":
    main()
