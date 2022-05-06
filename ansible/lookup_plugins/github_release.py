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

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = """
lookup: github_release
short_description: get requested release from github
description:
  - Get latest release from requested branch
  - If no branch specified, get latest release
options:
  _terms:
    description: Github org/repo
    required: True
  github_user:
    description: Github username
    required: False
  github_token:
    description: Github access token
    required: False
  branch:
    description: Branch to pick release from
    required: False
"""

EXAMPLES="""
  - name: Get latest UI release from master branch
    set_fact:
      rel_lookup: "{{ lookup('github_release', 'mobiledgex/edge-cloud-ui', branch='master') }}"
"""

from ansible.errors import AnsibleError, AnsibleParserError
from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display

import json

try:
    import requests
    HAS_REQUESTS = True
    from requests.auth import HTTPBasicAuth
except ImportError as e:
    HAS_REQUESTS = False

display = Display()

class LookupModule(LookupBase):

    def get_latest_release(self, repo, auth):
        url = "https://api.github.com/repos/{0}/releases/latest".format(repo)
        r = requests.get(url, auth=auth)
        r.raise_for_status()
        return r.json().get("tag_name")

    def get_latest_release_in_branch(self, repo, branch, auth):
        for page in range(1, 10):
            display.vvvv("Page: {}".format(page))
            url = "https://api.github.com/repos/{repo}/releases?page={page}".format(
                repo=repo, page=page)
            r = requests.get(url, auth=auth)
            r.raise_for_status()
            for rel in r.json():
                if rel["target_commitish"] == branch:
                    return rel["tag_name"]

        display.v("Could not find release in branch: {0}".format(branch))
        return None

    def run(self, terms, variables=None, **kwargs):
        if not HAS_REQUESTS:
            raise AnsibleError(
                'python requests package is required for vault lookups')

        if variables is not None:
            self._templar.available_variables = variables
        myvars = getattr(self._templar, '_available_variables', {})

        def get_option(v):
            return kwargs.get(v, myvars.get(v))

        user, token = get_option("github_user"), get_option("github_token")
        if user and token:
            auth = HTTPBasicAuth(user, token)
        else:
            auth = None

        branch = get_option("branch")
        if branch:
            display.vv("Looking for release in branch: {}".format(branch))

        ret = []
        for repo in terms:
            display.vvvv("Github repo: {0}".format(repo))

            if branch:
                ret.append(self.get_latest_release_in_branch(repo, branch, auth))
            else:
                ret.append(self.get_latest_release(repo, auth))

        return ret
