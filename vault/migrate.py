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


import argparse
import getpass
import hvac
import json
import logging
from six.moves import input
import sys

logging.basicConfig(format='[%(levelname)s] %(message)s', level=logging.INFO)
urllib3_logger = logging.getLogger('urllib3')
urllib3_logger.setLevel(logging.CRITICAL)

internal_secret_engines = ('cubbyhole/', 'identity/', 'sys/', 'transit/')
errors = []

def vault_client(url, token):
    client = hvac.Client(url=url, token=token)
    status = client.sys.read_health_status(method='GET')
    assert status['initialized'], "Vault not initialized: {0}".format(url)
    assert not status['sealed'], "Vault sealed: {0}".format(url)
    return client

def migrate(from_client, to_client, mount_point, path=''):
    global errors
    if (path == '' or path.endswith('/')):
        logging.debug("Retrieving secrets under path: {0}{1}".format(mount_point, path))
        seclist = from_client.secrets.kv.v2.list_secrets(mount_point=kv, path=path)
        for sec in seclist['data']['keys']:
            subpath = path + sec
            logging.debug("Descending into path: {0}{1}".format(mount_point, subpath))
            migrate(from_client, to_client, mount_point, subpath)
        return

    logging.debug("Fetching secret: {0}{1}".format(mount_point, path))
    try:
        secret = from_client.secrets.kv.v2.read_secret_version(mount_point=mount_point, path=path)
        logging.info("Migrating secret: {0}{1}".format(mount_point, path))
        logging.debug("{0}".format(json.dumps(secret['data']['data'], sort_keys=True)))

        to_client.secrets.kv.v2.create_or_update_secret(
            mount_point=mount_point,
            path=path,
            secret=secret['data']['data'])
    except Exception as e:
        logging.exception("Failed to fetch secret: {0}{1}".format(mount_point, path))
        errors.append("{0}{1}".format(mount_point, path))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Migrate vault data")
    parser.add_argument('from_vault',
                        help="vault to migrate data from (eg: https://vault-test.mobiledgex.net:8200)")
    parser.add_argument('to_vault',
                        help="vault to migrate data to")
    parser.add_argument('--from-token',
                        help='root token for "from_vault"')
    parser.add_argument('--to-token',
                        help='root token for "to_vault"')

    args = parser.parse_args()

    from_token = args.from_token
    if not from_token:
        from_token = getpass.getpass(prompt='Root token for "{0}: '.format(args.from_vault))

    to_token = args.to_token
    if not to_token:
        to_token = getpass.getpass(prompt='Root token for "{0}": '.format(args.to_vault))

    from_client = vault_client(args.from_vault, from_token)
    to_client = vault_client(args.to_vault, to_token)

    print("\n\nThis will OVERWRITE data in {0} !!\n".format(args.to_vault))
    answer = input("Continue? (yN) ").lower()
    if answer != "y":
        sys.exit("Aborting...")

    engines = from_client.sys.list_mounted_secrets_engines()['data']
    kv_list = [x for x in engines.keys() if x not in internal_secret_engines and engines[x]['type'] == 'kv']

    for kv in kv_list:
        logging.debug("Migrating secret engine: {0}".format(kv))
        migrate(from_client, to_client, kv)

    if errors:
        print("\n\n-- ERROR MIGRATING THESE --")
        for error in errors:
            print(" - {0}".format(error))
