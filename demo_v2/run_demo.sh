#!/bin/sh
# One command to start the AMTP demo (anchor, server, network path, client).
cd "$(dirname "$0")" && exec ../.venv/bin/python run_demo.py "$@"
