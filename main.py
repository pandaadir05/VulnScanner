# main.py

import argparse
from scanner.scanner import scan_url

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Simple Web Vulnerability Scanner")
    parser.add_argument("--url", required=True, help="Target URL to scan")
    args = parser.parse_args()

    scan_url(args.url)
