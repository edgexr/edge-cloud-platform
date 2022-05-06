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
import base64
import json
import logging
import os
import requests
import subprocess
import sys
from tempfile import TemporaryDirectory

CERT_TTL = "49h"

def vault_upload_api(vault_config):
    vault_addr = vault_config["vault_addr"]
    r = requests.post(f"{vault_addr}/v1/auth/approle/login",
                      json={
                          "role_id": vault_config["role_id"],
                          "secret_id": vault_config["secret_id"],
                      })
    if r.status_code != requests.codes.ok:
        raise Exception(f"Failed to generate vault token: {vault_addr}: {r.status_code} {r.text}")

    token = r.json()["auth"]["client_token"]

    def post(setup, kubeconfig):
        b64_bytes = base64.b64encode(kubeconfig.encode())
        b64_str = b64_bytes.decode('ascii')
        logging.debug(f"Payload: {b64_str}")
        r = requests.post(f"{vault_addr}/v1/secret/data/ansible/common/kubeconfigs/{setup}",
                          headers={"X-Vault-Token": token},
                          json={
                              "data": {
                                  "value": b64_str,
                              },
                          })
        if r.status_code != requests.codes.ok:
            raise Exception(f"Failed to upload kubeconfig: {r.status_code} {r.text}")

        # Clean out older versions of the kubeconfigs
        rv = requests.post(f"{vault_addr}/v1/secret/metadata/ansible/common/kubeconfigs/{setup}",
                          headers={"X-Vault-Token": token},
                          json={
                              "max_versions": 4,
                          })
        if rv.status_code != requests.codes.no_content:
            logging.warning(f"Failed to set max_versions for {setup} kubeconfig: {rv.status_code} {rv.text}")

        return r.json()

    return post

def get_kubeconfig(setup, region):
    with TemporaryDirectory() as tempdir:
        kubeconfig = os.path.join(tempdir, "kubeconfig")
        command = ["/usr/local/bin/tctl", "auth", "sign",
                   f"--user=ansible-{setup}",
                   f"--kube-cluster-name={setup}-{region}",
                   "--format=kubernetes", f"--out={kubeconfig}",
                   f"--ttl={CERT_TTL}"]
        logging.debug(command)

        p = subprocess.run(command, stdout=subprocess.PIPE,
                           stderr=subprocess.PIPE, timeout=30, text=True)
        if p.returncode != 0:
            raise Exception(f"{command}: rc={p.returncode} stdout={p.stdout} "
                            f"stderr={p.stderr}")

        with open(kubeconfig) as f:
            return f.read()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("setup", help="Setup")
    parser.add_argument("region", help="Region", nargs="+")
    parser.add_argument("--config", help="Config file")
    parser.add_argument("--debug", help="Print debug output", action="store_true")
    args = parser.parse_args()

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(level=log_level)

    if not args.config:
        args.config = os.path.join("/etc/vault_roles", f"{args.setup}.json")

    with open(args.config) as f:
        vault_config = json.load(f)

    rc = 0

    for region in args.region:
        try:
            upload = vault_upload_api(vault_config)
            kubeconfig = get_kubeconfig(args.setup, region)
            r = upload(region, kubeconfig)
            logging.debug(f"Upload response: {r}")
        except Exception as e:
            logging.exception(f"Error uploading kubeconfig: region={region}: {e}")
            rc = 2

    sys.exit(rc)
