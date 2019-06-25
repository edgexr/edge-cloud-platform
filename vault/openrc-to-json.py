#!/usr/bin/python

import json
import os
import sys

openrc = []
for var in os.environ:
    if not var.startswith('OS_'):
        continue

    openrc.append({
        "name": var,
        "value": os.environ[var]
    })

if len(openrc) < 4:
    sys.exit("Error loading OS_* variables from environment")

print(json.dumps({"env": openrc}, indent=4, sort_keys=True))
