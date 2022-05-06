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
import json
import logging
import sys

from gvm.protocols.gmp import Gmp

def main(gmp: Gmp, args: Namespace) -> None:
    if len(args.script) < 2:
        print("usage: gvm-script scan-status.py <scan-id>")
        sys.exit()

    scan_id = args.argv[1]

    response_xml = gmp.get_tasks(filter_string=scan_id)
    tasks_xml = response_xml.xpath('task')

    ntasks = len(tasks_xml)
    if ntasks < 1:
        sys.exit(f"Could not locate task: {scan_id}")

    if ntasks > 1:
        sys.exit(f"Scan pattern matched {ntasks} tasks")

    task = tasks_xml[0]
    full_status = ''.join(task.xpath('status/text()'))
    creation_time = ''.join(task.xpath('creation_time/text()'))
    scan_start = ''.join(task.xpath('last_report/report/scan_start/text()'))
    scan_end = ''.join(task.xpath('last_report/report/scan_end/text()'))
    severity = ''.join(task.xpath('last_report/report/severity/text()'))
    high_severity_issues = ''.join(task.xpath('last_report/report/result_count/hole/text()'))
    in_use = ''.join(task.xpath('in_use/text()'))
    progress = ''.join(task.xpath('progress/text()'))
    try:
        status = full_status.split()[0]
        in_use = int(in_use)
        progress = float(progress)
        high_severity_issues = int(high_severity_issues or 0)
        if severity:
            severity = float(severity)
        else:
            severity = -1
    except Exception as e:
        # Ignore type-conversion errors
        logging.exception("Type converstion failure")
        status = full_status
        pass

    print(json.dumps({
        "scan_id": scan_id,
        "creation_time": creation_time,
        "scan_start": scan_start,
        "scan_end": scan_end,
        "in_use": in_use,
        "progress": progress,
        "status": status,
        "full_status": full_status,
        "severity": severity,
        "high_severity_issues": high_severity_issues,
    }, indent=4, sort_keys=True))

# Only run from within "gvm-script"
if __name__ == '__gmp__':
    main(gmp, args)
