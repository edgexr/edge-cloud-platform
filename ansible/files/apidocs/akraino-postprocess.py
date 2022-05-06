#!/usr/bin/python3
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


import argparse
import json
import re
import sys

def remove_mobiledgex_references(sw):
    for item in list(sw):
        if isinstance(sw[item], dict):
            remove_mobiledgex_references(sw[item])
        elif item == "x-go-package":
            del sw[item]
        elif item == "description":
            sw[item] = re.sub(r'MobiledgeX\s*', '', sw[item]).capitalize()

def fix_introduction(sw, title=None, description=None):
    try:
        if title:
            sw['info']['title'] = title
        else:
            sw['info']['title'] = re.sub(r'MobiledgeX\s*', '', sw['info']['title'])

        if not description:
            del sw['info']['description']
        else:
            sw['info']['description'] = description
    except Exception:
        pass

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--title", "-t", help="Replacement title text")
    parser.add_argument("--description", "-d", help="Replacement description text")
    args = parser.parse_args()

    sw = json.load(sys.stdin)

    remove_mobiledgex_references(sw)
    fix_introduction(sw, title=args.title, description=args.description)

    print(json.dumps(sw, indent=2))

if __name__ == "__main__":
    main()
