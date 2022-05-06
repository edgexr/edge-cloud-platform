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


import requests
import json

from ansible.module_utils.basic import *

BASEURL = "https://api.nsone.net/v1"
FILTER_LIST = [
    { "filter": "up", "config": {} },
    { "filter": "geotarget_latlong", "config": {} },
    { "filter": "select_first_n", "config": {"N": "1"} },
]

class NS1Exception(Exception):
    pass

def ns1_api(apikey):
    headers = {
        "X-NSONE-Key": apikey,
    }

    def ns1_api_call(path, method="GET", **kwargs):
        url = "{0}/{1}".format(BASEURL, path)
        return requests.request(method, url, headers=headers, **kwargs)

    return ns1_api_call

def ns1_record_check(r, answers):
    """Check if current NS1 record matches is up to date"""
    present = False
    has_changed = False
    reason = ""

    if r.status_code == requests.codes.not_found:
        present = False
        has_changed = True

    elif r.status_code == requests.codes.ok:
        present = True

        # Check if the record is up to date
        try:
            resp = r.json()

            # Validate filter list
            curr_filters = json.dumps(resp["filters"], sort_keys=True)
            req_filters = json.dumps(FILTER_LIST, sort_keys=True)
            assert curr_filters == req_filters, \
                "filters: {0} != {1}".format(curr_filters, req_filters)

            # Validate answer list
            assert len(resp["answers"]) == len(answers), "answer: num answers"
            for (curr, req) in zip(resp["answers"], answers):
                assert curr["meta"]["note"] == req["region"], \
                    "answer: {0}".format(req["region"])

                for key in ("latitude", "longitude"):
                    assert curr["meta"][key] == req[key], \
                        "answer: {0}/{1}".format(req["region"], key)

                assert curr["answer"][0] == req["ip"], \
                    "answer: {0}/IP".format(req["region"])

        except AssertionError as e:
            has_changed = True
            reason = str(e)
        except Exception as e:
            raise NS1Exception(e)
    else:
        raise NS1Exception("Got: {0} {1}".format(r.status_code, r.text))

    return (present, has_changed, reason)

def ns1_dns_record(module):
    ns1 = ns1_api(module.params["apikey"])
    state = module.params["state"]

    resp = {}
    reason = ""

    zone = module.params["zone"]
    domain = module.params["domain"]
    if "." not in domain:
        domain += "." + zone
    answers = module.params["answers"]

    ns1_record = "zones/{0}/{1}/A".format(zone, domain)
    r = ns1(ns1_record)

    if state == "absent":
        # Delete record is present
        if r.status_code == requests.codes.ok:
            has_changed = present = True
            resp = r.json()

            if not module.check_mode:
                r = ns1(ns1_record, method="DELETE")
                if r.status_code != requests.codes.ok:
                    raise NS1Exception("Got: {0} {1}".format(r.status_code, r.text))
        else:
            has_changed = present = False

    else:
        # Create/update record
        present, has_changed, reason = ns1_record_check(r, answers)
        if not module.check_mode and (not present or has_changed):
            # Set up answer (geo-IP) list for record
            rec_answers = []
            for answer in answers:
                rec_answers.append({
                    "answer": [ answer["ip"] ],
                    "meta": {
                        "latitude": answer["latitude"],
                        "longitude": answer["longitude"],
                        "note": answer["region"],
                        "up": True,
                    },
                })

            if present:
                # Update record
                method = "POST"
            else:
                # Create record
                method = "PUT"

            r = ns1(ns1_record,
                    method=method,
                    json={
                        "zone": zone,
                        "domain": domain,
                        "type": "A",
                        "ttl": 300,
                        "filters": FILTER_LIST,
                        "answers": rec_answers,
                    })
            if r.status_code != requests.codes.ok:
                raise NS1Exception("Got: {0} {1}".format(r.status_code, r.text))

            resp = r.json()

    return (has_changed, {
        "response": resp,
        "reason": reason,
        "present": present,
    })

def main():
    fields = {
        "apikey": {"required": True, "type": "str", "no_log": True},
        "zone": {"required": True, "type": "str"},
        "domain": {"required": True, "type": "str"},
        "answers": {"required": True, "type": "list", "elements": "dict"},
        "state": {
            "default": "present",
            "choices": ["present", "absent"],
            "type": "str",
        },
    }

    module = AnsibleModule(argument_spec=fields,
                           supports_check_mode=True)
    has_changed, result = ns1_dns_record(module)
    module.exit_json(changed=has_changed, meta=result)

if __name__ == "__main__":
    main()
