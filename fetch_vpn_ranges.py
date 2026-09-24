"""
fetch_vpn_ranges.py
====================
Pulls X4BNet's public VPN + datacenter CIDR lists and writes them out as the
cidr,provider,category CSV that network_trust.load_vpn_ranges() reads.

Source: https://github.com/X4BNet/lists_vpn (public, auto-updated by CI,
no signup / no API key). The lists are plain "one CIDR per line" text files
with no per-provider breakdown, so every row here is written with
provider="X4BNet" -- that's the true source, we're not able to attribute
individual ranges to individual VPN companies from this data.

Usage:
    python fetch_vpn_ranges.py
    python fetch_vpn_ranges.py --output data/vpn_ranges.csv
    python fetch_vpn_ranges.py --categories vpn            # skip datacenter
    python fetch_vpn_ranges.py --include-ipv6              # also pull IPv6
    python fetch_vpn_ranges.py --append                    # keep existing rows

Requires only the standard library -- no pip install needed. Requires
outbound internet access to raw.githubusercontent.com (this script itself
does not run inside the sandbox that built it; run it wherever the app
runs, or anywhere with internet access, and copy the resulting CSV over).
"""

import argparse
import csv
import ipaddress
import os
import sys
import urllib.error
import urllib.request

_BASE = "https://raw.githubusercontent.com/X4BNet/lists_vpn/main/output"

_SOURCES = {
    "vpn": {
        "ipv4": f"{_BASE}/vpn/ipv4.txt",
        "ipv6": f"{_BASE}/vpn/ipv6.txt",
    },
    "datacenter": {
        "ipv4": f"{_BASE}/datacenter/ipv4.txt",
        "ipv6": f"{_BASE}/datacenter/ipv6.txt",
    },
}

_PROVIDER = "X4BNet"  # the lists don't break individual ranges out by provider


def _fetch_text(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "fetch_vpn_ranges.py"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read().decode("utf-8", errors="replace")


def _parse_cidr_lines(text: str):
    """Yields valid CIDRs from a plain 'one per line' list, skipping blank
    lines, comments, and anything that doesn't parse as a network."""
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        yield line


def fetch_category(category: str, include_ipv6: bool) -> list[tuple[str, str, str]]:
    """Returns (cidr, provider, category) rows for one category ('vpn' or
    'datacenter'), fetching ipv4 always and ipv6 if requested."""
    rows = []
    urls = [("ipv4", _SOURCES[category]["ipv4"])]
    if include_ipv6:
        urls.append(("ipv6", _SOURCES[category]["ipv6"]))

    for label, url in urls:
        print(f"Fetching {category} {label} list from {url} ...", file=sys.stderr)
        try:
            text = _fetch_text(url)
        except urllib.error.URLError as e:
            print(f"  skipped ({e}) -- {label} list for {category} not included", file=sys.stderr)
            continue
        count = 0
        for cidr in _parse_cidr_lines(text):
            rows.append((cidr, _PROVIDER, category))
            count += 1
        print(f"  {count} ranges", file=sys.stderr)

    return rows


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output", default="data/vpn_ranges.csv",
        help="Where to write the CSV (default: data/vpn_ranges.csv)",
    )
    parser.add_argument(
        "--categories", nargs="+", choices=["vpn", "datacenter"],
        default=["vpn", "datacenter"],
        help="Which X4BNet lists to include (default: both)",
    )
    parser.add_argument(
        "--include-ipv6", action="store_true",
        help="Also fetch IPv6 ranges (default: IPv4 only)",
    )
    parser.add_argument(
        "--append", action="store_true",
        help="Append to an existing CSV instead of overwriting it "
             "(does not de-duplicate against existing rows)",
    )
    args = parser.parse_args()

    all_rows: list[tuple[str, str, str]] = []
    for category in args.categories:
        all_rows.extend(fetch_category(category, args.include_ipv6))

    if not all_rows:
        print("Nothing fetched -- nothing written.", file=sys.stderr)
        sys.exit(1)

    out_dir = os.path.dirname(args.output)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)

    write_header = not (args.append and os.path.exists(args.output))
    mode = "a" if args.append else "w"
    with open(args.output, mode, newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if write_header:
            writer.writerow(["cidr", "provider", "category"])
        writer.writerows(all_rows)

    verb = "Appended" if args.append else "Wrote"
    print(f"{verb} {len(all_rows)} ranges to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
