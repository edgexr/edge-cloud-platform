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
from datetime import datetime, timedelta
import grandfatherson
import json
import hashlib
import logging
import os
import re
import requests
import subprocess

ARTIFACTORY = "https://artifactory.mobiledgex.net/artifactory"
ARTIFACTORY_REPO = "vault-backup"
SNAPSHOT_ROLE = "snapshot.v1"

logging.basicConfig(format="%(asctime)s [%(levelname)s] %(message)s",
                    level=logging.DEBUG)

clogger = logging.getLogger('chardet.charsetprober')
clogger.setLevel(logging.INFO)

class Vault:
    def __init__(self, instance, role_id, secret_id):
        self.addr = "https://vault-{0}.mobiledgex.net".format(instance)
        self.role_id = role_id
        self.secret_id = secret_id
        self._token = None

    @property
    def token(self):
        if not self._token:
            r = requests.post("{0}/v1/auth/approle/login".format(self.addr),
                              json={
                                  "role_id": self.role_id,
                                  "secret_id": self.secret_id,
                              })
            logging.debug(r.text)
            assert r.status_code == requests.codes.ok
            self._token = r.json()["auth"]["client_token"]
        return self._token

    def snapshot(self):
        r = requests.get("{0}/v1/sys/storage/raft/snapshot".format(self.addr),
                         headers={"X-Vault-Token": self.token})
        logging.debug(r.headers)
        assert r.status_code == requests.codes.ok

        p = subprocess.Popen(["tar", "zxfO", "-", "meta.json"],
                             stdin=subprocess.PIPE,
                             stdout=subprocess.PIPE)
        (out, err) = p.communicate(input=r.content)

        meta = json.loads(out.decode("utf-8"))
        logging.debug(meta)
        assert meta["ID"] == "bolt-snapshot"

        md5 = hashlib.md5(r.content).hexdigest()
        sha1 = hashlib.sha1(r.content).hexdigest()

        return r.content, md5, sha1, meta

class Artifactory:
    def __init__(self, token):
        self.addr = ARTIFACTORY
        self.repo = ARTIFACTORY_REPO
        self.token = token

    def upload(self, fname, data, checksums):
        r = requests.put("{0}/{1}/{2}".format(self.addr, self.repo, fname),
                         headers={
                             "Authorization": "Bearer {0}".format(self.token),
                             "X-Checksum-MD5": checksums["md5"],
                             "X-Checksum-Sha1": checksums["sha1"],
                         },
                         data=data)
        logging.debug(r.text)
        assert r.status_code == requests.codes.created

    def cleanup(self, pattern):
        r = requests.get("{0}/api/search/artifact?name=.snap&repos={1}".format(self.addr, ARTIFACTORY_REPO),
                         headers={
                             "Authorization": "Bearer {0}".format(self.token),
                         })
        logging.debug(r.text)
        assert r.status_code == requests.codes.ok

        backup_list = {}
        for result in r.json()["results"]:
            backup = result["uri"]
            if re.search(pattern, backup):
                ts = datetime.strptime(os.path.basename(backup),
                                       "vault-%Y-%m-%d-%H%M.snap")
                fpath = re.sub(r"/api/storage/", "/", backup)
                backup_list[ts] = fpath
        logging.debug("Backup list: {0}".format(backup_list))

        delete_backups = grandfatherson.to_delete(
            backup_list.keys(),
            hours=12, days=7, weeks=4, months=6,
            firstweekday=grandfatherson.SUNDAY,
            now=(datetime.now() - timedelta(minutes=30)))

        for backup in [ backup_list[x] for x in delete_backups ]:
            logging.info("Deleting backup: {0}".format(backup))
            r = requests.delete(backup,
                                headers={
                                    "Authorization": "Bearer {0}".format(self.token),
                                })
            logging.debug(r.text)
            assert r.status_code == requests.codes.no_content

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("vault_instance",
                        choices=["main", "qa", "stage", "dev"],
                        default="main")
    args = parser.parse_args()

    role_id = os.environ["VAULT_ROLE_ID"]
    secret_id = os.environ["VAULT_SECRET_ID"]
    rt_access_token = os.environ["ARTIFACTORY_ACCESS_TOKEN"]

    vault = Vault(args.vault_instance, role_id, secret_id)
    logging.info("Creating vault snapshot")
    content, md5, sha1, meta = vault.snapshot()

    rt = Artifactory(rt_access_token)

    now = datetime.now()
    datestamp = now.strftime("%Y-%m-%d")
    timestamp = now.strftime("%Y-%m-%d-%H%M")

    backup = "{0}/{1}/vault-{2}.snap".format(
                args.vault_instance, datestamp, timestamp)
    logging.info("Uploading snapshot to Artifactory: {0}".format(backup))
    rt.upload(backup, content, {"md5": md5, "sha1": sha1})

    logging.info(json.dumps(meta, indent=4, sort_keys=True))

    logging.info("Deleting old snapshots")
    rt.cleanup(r"{0}/.*/vault-.*\.snap".format(args.vault_instance))
