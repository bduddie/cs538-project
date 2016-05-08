#!/bin/bash
set -eux

python pox.py log.level --DEBUG misc.sdns-mapper > /tmp/pox.log 2>&1 &
POX_PID="$!"
sleep 1

sudo python mn-sdns.py
kill "$POX_PID"
