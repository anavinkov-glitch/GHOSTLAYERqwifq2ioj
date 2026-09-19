#!/usr/bin/env python3
"""Start Ghostlayer.

    python run.py                 http://127.0.0.1:5000
    python run.py --port 8080
    python run.py --host 0.0.0.0  reachable from other machines on the network
"""

from __future__ import annotations

import argparse
import os
import webbrowser

from ghostlayer import create_app


def main() -> None:
    parser = argparse.ArgumentParser(description="Run the Ghostlayer server.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=int(os.environ.get("PORT", 5000)))
    parser.add_argument("--debug", action="store_true", help="auto-reload on code changes")
    parser.add_argument("--open", action="store_true", help="open a browser once it is up")
    args = parser.parse_args()

    app = create_app()

    url = f"http://{'127.0.0.1' if args.host == '0.0.0.0' else args.host}:{args.port}"
    print("\n  Ghostlayer is running at " + url)
    print("  Press Ctrl-C to stop.\n")

    if args.open:
        webbrowser.open(url)

    app.run(host=args.host, port=args.port, debug=args.debug)


if __name__ == "__main__":
    main()
