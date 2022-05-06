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

from argparse import Namespace
import datetime
import sys

from gvm.protocols.gmp import Gmp

scan_config_id = 'daba56c8-73ec-11df-a475-002264764cea' # Full and fast
scanner_id = '08b69003-5fc2-4037-a479-93b440211c73'     # OpenVAS
port_list_id = '4a4717fe-57d2-11e1-9a26-406186ea4fc5'   # iana-tcp-udp

def create_target(gmp, target_hash, ipaddress, port_list_id=port_list_id):
    name = f"VM Host {target_hash}"

    response = gmp.get_targets(filter_string=target_hash, tasks=False)
    targets = response.xpath('target')

    ntargets = len(targets)
    if ntargets > 1:
        sys.exit(f"Found more than one target for hash: {target_hash}")

    if ntargets == 1:
        # Found existing target
        return targets[0].get('id')

    # Create a new target
    response = gmp.create_target(
        name=name, hosts=[ipaddress], port_list_id=port_list_id
    )
    return response.get('id')


def create_task(gmp, scan_id, ipaddress, target_id, scan_config_id, scanner_id):
    name = f"VM Scan {scan_id} {str(datetime.datetime.now())}"
    response = gmp.create_task(
        name=name,
        config_id=scan_config_id,
        target_id=target_id,
        scanner_id=scanner_id,
    )
    return response.get('id')


def start_task(gmp, task_id):
    response = gmp.start_task(task_id)
    # the response is
    # <start_task_response><report_id>id</report_id></start_task_response>
    return response[0].text


def main(gmp: Gmp, args: Namespace) -> None:
    if len(args.script) < 4:
        print("usage: gvm-script scan-system.py <target-id> <ip-address> <scan-id>")
        sys.exit()

    target_hash = args.argv[1]
    ipaddress = args.argv[2]
    scan_id = args.argv[3]

    target_id = create_target(gmp, target_hash, ipaddress, port_list_id)

    task_id = create_task(
        gmp,
        scan_id,
        ipaddress,
        target_id,
        scan_config_id,
        scanner_id,
    )

    report_id = start_task(gmp, task_id)
    print(f"TASK:{task_id}\nREPORT:{report_id}")

# Only run from within "gvm-script"
if __name__ == '__gmp__':
    main(gmp, args)
