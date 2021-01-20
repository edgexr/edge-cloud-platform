#!/usr/bin/env python

from datetime import datetime
import getpass
import json
import os
import logging
import re
import requests
import shutil
import subprocess
import sys

from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

logging.basicConfig(
    format="%(asctime)s [%(levelname)s] %(message)s",
    level=logging.DEBUG if os.environ.get("DEBUG") else logging.INFO)

RESERVED_CLOUDLET_ORGS = ( "edgebox", "mobiledgex" )

def prompt(text, default=None, choices=None, validate=None):
    prompt_str = text
    if choices:
        choices = [str(x) for x in choices]
        prompt_str += " (one of: " + ", ".join(choices) + ")"
    if default:
        prompt_str += " (\"{0}\")".format(default)
    prompt_str += ": "

    reply = None
    while not reply:
        reply = input(prompt_str).strip()
        if not reply:
            if default:
                reply = default
            else:
                continue
        if choices and reply not in choices:
            print("Not a valid choice: {0}".format(reply))
            reply = None
        elif validate:
            vresp = validate(reply)
            if not vresp:
                reply = None

    return reply

def validate_float(string, min_val, max_val):
    if not string:
        return True
    try:
        val = float(string)
    except ValueError:
        print("Not a valid float")
        return False

    if val < min_val or val > max_val:
        print("Value not within bounds [{0},{1}]".format(min_val, max_val))
        return False

    return True

class McAuthException(Exception):
    pass

class MC(dict):

    def __init__(self, varsfile):
        self.varsfile = varsfile
        self.params = {}
        self._username = None
        self._password = None
        self._token = None
        self._regions = None
        self._orgs = None
        self._roles = None
        self._location_defaults = None
        self._location_name = None
        self.revalidate = False

        if not os.path.exists(varsfile):
            varsfile = varsfile + ".reset"

        with open(varsfile, "r") as f:
            self.params = load(f, Loader=Loader)

        for p in self.params:
            if self.params[p] == "UNSET":
                self.params[p] = None

    def _revalidate(self, key):
        default = self.params.get(key)
        if self.revalidate != False and key not in self.revalidate:
            self.params[key] = None
            self.revalidate.add(key)
        return default

    @property
    def host(self):
        key = "mc"
        default = self._revalidate(key)
        if key not in self.params or not self.params[key]:
            self.params[key] = prompt("Console Host", default=default)
            if self.params[key] != default:
                # Reset computed parameters
                for p in ("controller", "deploy-env", "region"):
                    self.params[p] = None
                self._regions = self._orgs = self._roles = None
                self._username = self._password = self._token = None

        return self.params[key]

    @property
    def username(self):
        if not self._username:
            u = os.environ.get("LDAP_ID")
            if not u:
                u = prompt("Console username", getpass.getuser())
            self._username = u
        return self._username

    @property
    def password(self):
        if not self._password:
            # Attempt to get password from macOS keychain
            keychain_path = "https://vault-{0}.mobiledgex.net/ldap".format(self.deploy_env)
            p = subprocess.Popen(["security", "find-internet-password", "-a",
                    self.username, "-s", keychain_path, "-w"],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    universal_newlines=True)
            out, err = p.communicate()
            self._password = out.strip()
            if len(self._password) < 1:
                # Password not in keychain; prompt user for it
                self._password = getpass.getpass(prompt="Console password: ")
        return self._password

    @property
    def token(self):
        if self._token:
            # Check if token is valid
            try:
                self.call("user/current", token=self._token)
            except McAuthException as e:
                # Token invalid
                logging.debug("Token has expired; fetching a new one")
                self._token = None

        if not self._token:
            try:
                r = requests.post("https://{0}/api/v1/login".format(self.host),
                              json={"username": self.username, "password": self.password})
                self._token = r.json()["token"]
            except Exception as e:
                raise McAuthException("Failed to log in to MC \"{0}\" as user \"{1}\": {2}".format(
                    self.host, self.username, e))

        return self._token

    def call(self, api, method="POST", token=None, data={}, **kwargs):
        if not data:
            data = kwargs
        if not token:
            token = self.token
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
        }
        r = requests.request(method, "https://{0}/api/v1/auth/{1}".format(
                                        self.host, api),
                             headers=headers,
                             json=data)
        logging.debug("Response: {0}".format(r.text))
        if r.status_code != requests.codes.ok:
            raise Exception("API call failed: {0}: {1} {2}".format(
                api, r.status_code, r.text))

        def load_json(text):
            d = json.loads(text)
            if len(d) == 1 and 'data' in d:
                d = [ d["data"] ]
            return d

        resp = []
        if r.text:
            try:
                resp = load_json(r.text)
            except Exception as e:
                # Check if response is a JSON stream
                try:
                    for line in r.text.splitlines():
                        resp.extend(load_json(line))
                except Exception:
                    # Throw the original exception
                    raise e
        return resp

    @property
    def regions(self):
        if not self._regions:
            self._regions = {}
            for ctrl in self.call("controller/show"):
                self._regions[ctrl["Region"]] = ctrl["Address"]
        return self._regions

    @property
    def orgs(self):
        if not self._orgs:
            self._orgs = {}
            for org in self.call("org/show"):
                self._orgs[org["Name"]] = org["Type"]
        return self._orgs

    @property
    def roles(self):
        if not self._roles:
            self._roles = self.call("role/assignment/show")
        return self._roles

    @property
    def location_defaults(self):
        """Use IP geolocation to determine defaults for lat-long"""
        if not self._location_defaults:
            try:
                r = requests.get("http://ipinfo.io/geo", timeout=2)
                self._location_defaults = r.json()
            except Exception as e:
                self._location_defaults = {}
        return self._location_defaults

    @property
    def location_name(self):
        if not self._location_name:
            locdefs = self.location_defaults
            self._location_name = "{0}, {1}".format(locdefs["city"], locdefs["country"])
        return self._location_name

    @property
    def latitude(self):
        key = "latitude"
        default = self._revalidate(key)
        if not self.params[key]:
            prompt_str = "Latitude"
            if not default:
                locdefs = self.location_defaults
                if "loc" in locdefs:
                    latlong = locdefs["loc"].split(',')
                    default = latlong[0]
                else:
                    default = "33.01"
            self.params[key] = prompt(prompt_str, default,
                                      validate=lambda x: validate_float(x, -90, 90))
            self.params[key] = float(self.params[key])
        return self.params[key]

    @property
    def longitude(self):
        key = "longitude"
        default = self._revalidate(key)
        if not self.params[key]:
            prompt_str = "Longitude"
            if not default:
                locdefs = self.location_defaults
                if "loc" in locdefs:
                    latlong = locdefs["loc"].split(',')
                    default = latlong[1]
                else:
                    default = "-96.61"
            self.params[key] = prompt(prompt_str, default,
                                      validate=lambda x: validate_float(x, -180, 180))
            self.params[key] = float(self.params[key])
        return self.params[key]

    @property
    def region(self):
        key = "region"
        default = self._revalidate(key)
        if key not in self.params or not self.params[key]:
            self.params[key] = prompt("Region", choices=sorted(self.regions.keys()),
                                      default=default)
            self.params["controller"] = None
        return self.params[key]

    @property
    def controller(self):
        key = "controller"
        self._revalidate(key)
        if key not in self.params or not self.params[key]:
            self.params[key] = self.regions[self.region].split(":")[0]
        return self.params[key]

    @property
    def cloudlet(self):
        key = "cloudlet"
        default = self._revalidate(key)
        if key not in self.params or not self.params[key]:
            if not default:
                default = "hackathon-" + getpass.getuser()
            self.params[key] = prompt("Cloudlet", default=default)
        return self.params[key]

    def validate_org(self, org):
        if org.lower() in RESERVED_CLOUDLET_ORGS:
            print("{0} is a reserved org. Please pick another.".format(org))
            return False
        if org not in self.orgs:
            print("Org does not exist or is not accessible: {0}".format(org))
            return False
        if self.orgs[org] != "operator":
            print("Not an operator org: {0}".format(org))
            return False

        for r in self.roles:
            if r["org"] == org and r["username"] == self.username \
                    and r["role"] == "OperatorManager":
                # Valid role
                return True

        print("User \"{0}\" not OperatorManager in org \"{1}\"".format(
            self.username, org))
        return False

    @property
    def cloudlet_org(self):
        key = "cloudlet-org"
        default = self._revalidate(key)
        corg = self.params.get(key)
        if corg and not self.validate_org(corg):
            corg = None
        if not corg:
            corg = prompt("Cloudlet Org", default=default,
                          validate=lambda x: self.validate_org(x))
            self.params[key] = corg
        return self.params[key]

    @property
    def deploy_env(self):
        key = "deploy-env"
        default = self._revalidate(key)
        if key not in self.params or not self.params[key]:
            m = re.match(r'console([^\.]*)\.', self.host)
            if not m:
                raise Exception("Unable to determine vault address for MC: " + self.host)
            d = m.group(1)
            self.params[key] = d.lstrip("-") if d else "main"
        return self.params[key]

    @property
    def outdir(self):
        return self.params.get("outputdir")

    def get_access_key(self):
        r = self.call("ctrl/GenerateAccessKey",
                      data={
                          "cloudletkey": {
                              "name": self.cloudlet,
                              "organization": self.cloudlet_org,
                          },
                          "region": self.region,
                      })
        return r["message"]

    def get_cluster_instances(self):
        return self.call("ctrl/ShowClusterInst",
                         data={
                             "clusterinst": {
                                 "key": {
                                     "cloudlet_key": {
                                         "name": self.cloudlet,
                                         "organization": self.cloudlet_org,
                                     }
                                 }
                             },
                             "region": self.region,
                         })

    def get_app_instances(self, cluster, cluster_org):
        return self.call("ctrl/ShowAppInst",
                         data={
                             "appinst": {
                                 "key": {
                                     "cluster_inst_key": {
                                         "cloudlet_key": {
                                             "name": self.cloudlet,
                                             "organization": self.cloudlet_org,
                                         },
                                         "cluster_key": {
                                             "name": cluster,
                                         },
                                         "organization": cluster_org,
                                     },
                                 },
                             },
                             "region": self.region,
                         })

    def delete_app_instance(self, cluster, cluster_org, app_name, app_org, app_vers):
        return self.call("ctrl/DeleteAppInst",
                         data={
                             "appinst": {
                                 "key": {
                                     "app_key": {
                                         "name": app_name,
                                         "organization": app_org,
                                         "version": app_vers,
                                     },
                                     "cluster_inst_key": {
                                         "cloudlet_key": {
                                             "name": self.cloudlet,
                                             "organization": self.cloudlet_org,
                                         },
                                         "cluster_key": {
                                             "name": cluster,
                                         },
                                         "organization": cluster_org,
                                     },
                                 },
                             },
                             "region": self.region,
                         })

    def delete_cluster_instance(self, cluster, cluster_org):
        return self.call("ctrl/DeleteClusterInst",
                         data={
                             "clusterinst": {
                                 "key": {
                                     "cloudlet_key": {
                                         "name": self.cloudlet,
                                         "organization": self.cloudlet_org,
                                     },
                                     "cluster_key": {
                                         "name": cluster,
                                     },
                                     "organization": cluster_org,
                                 }
                             },
                             "region": self.region,
                         })

    def delete_cloudlet(self):
        return self.call("ctrl/DeleteCloudlet",
                         data={
                             "cloudlet": {
                                 "key": {
                                     "name": self.cloudlet,
                                     "organization": self.cloudlet_org,
                                 },
                             },
                             "region": self.region,
                         })

    def validate(self):
        self.revalidate = set()
        for param in ("host", "region", "cloudlet_org", "cloudlet", "latitude",
                      "longitude"):
            getattr(self, param)
        self.revalidate = False

    def save(self):
        # Load all computed parameters
        for p in ("host", "controller", "region", "deploy_env", "cloudlet",
                  "cloudlet_org", "latitude", "longitude"):
            getattr(self, p)

        if os.path.exists(self.varsfile):
            # Back up existing vars file
            bakfile = self.varsfile + "." \
                + datetime.now().strftime("%Y-%m-%d-%H%M%S")
            shutil.copy(self.varsfile, bakfile)

        params = self.params.copy()
        for p in params:
            if not params[p]:
                params[p] = "UNSET"

        with open(self.varsfile, "w") as f:
            dump(params, f, default_flow_style=False, sort_keys=True)

    def banner(self, msg):
        print("\n*** {} ***".format(msg))

    def confirm_continue(self, prompt="Continue?"):
        while True:
            reply = input(prompt + " (yn) ").lower().strip()
            if reply.startswith("y"):
                return True
            if reply.startswith("n"):
                return False

    def __str__(self):
        return """    MC: {mc}
    Console user: {username}
    Region: {region}
    Controller: {controller}
    Cloudlet Org: {cloudlet-org}
    Cloudlet: {cloudlet}
    Latitude: {latitude}
    Longitude: {longitude}
    Output Dir: {outputdir}
""".format(**self.params, username=self._username)

if __name__ == "__main__":
    varsfile = sys.argv[1] if len(sys.argv) > 1 else "e2e-tests/edgebox/edgebox_vars.yml"
    mc = MC(varsfile)
    print("Config:")
    print(mc)
    print(mc.host)
    for c in mc.get_cluster_instances():
        print(c)
        cluster = c["key"]["cluster_key"]["name"]
        cluster_org = c["key"]["organization"]
        for a in mc.get_app_instances(cluster, cluster_org):
            print(a)
            app_name = a["key"]["app_key"]["name"]
            app_vers = a["key"]["app_key"]["version"]
            app_org = a["key"]["app_key"]["organization"]

            print(app_name)
            print(app_vers)
            print(app_org)
