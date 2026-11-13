#!/bin/sh
# Come setup_env.py (lo esegue). Su Windows usa direttamente: python setup_env.py
cd "$(dirname "$0")" && exec python3 setup_env.py "$@"
