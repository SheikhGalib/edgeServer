#!/bin/bash

if [ $# -eq 0 ]; then
    echo "Usage: $0 <device_key>"
    exit 1
fi

DEVICE_KEY=$1
source venv/bin/activate && python edge_server.py --device-id $DEVICE_KEY