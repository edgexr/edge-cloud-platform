#!/usr/bin/python
# Copyright 2022 MobiledgeX, Inc
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


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
