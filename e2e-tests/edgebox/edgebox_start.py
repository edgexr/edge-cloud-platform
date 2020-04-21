#!/usr/bin/env python

import re
import sys
import os
import shutil
import subprocess
import getpass
import requests

from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

Mcuser = os.getenv("MC_USER", "")
Mcpass = os.getenv("MC_PASSWORD", "")
Region = None
CloudletOrg = None
Cloudlet = None
Mc = None
Controller = None
Latitude = None
Longitude = None
OutputDir = "/tmp/edgebox_out"
DefaultLatitude = 33.01
DefaultLongitude = -96.61
Vault = None
Orgs = None
Roles = None
CloudletOrgRoleReqd = "OperatorManager"

Edgectl = None
Varsfile = "./edgebox_vars.yml"
Setupfile = "../setups/edgebox.yml"
CreateTestfile = "../testfiles/edgebox_create.yml"
DeployTestfile = "../testfiles/edgebox_deploy.yml"

EdgevarData = None

# Reserved cloudlet names (lowercase)
ReservedCloudletOrgs = ( "edgebox" )

# Handle incompatibility between Pythons 2 and 3
try:
    input = raw_input
except NameError:
    pass

def checkPrereqs():
    ldapid = os.getenv("LDAP_ID", "")
    vaultRole = os.getenv("VAULT_ROLE_ID", "")
    vaultSecret = os.getenv("VAULT_SECRET_ID", "")
    if ldapid == "":
       print("LDAP_ID env var not set")
       if vaultRole != "" and vaultSecret != "":
           print("Using VAULT_ROLE_ID and VAULT_SECRET env vars")
       else:
           print("No appropriate Vault auth found, please set LDAP_ID or VAULT_ROLE_ID and VAULT_SECRET_ID")
           return False
    return True 

def getMcToken(mc, user, password):
    try:
        r = requests.post("https://{0}/api/v1/login".format(mc),
                              json={"username": user, "password": password})
        token = r.json()["token"]
    except Exception as e:
        sys.exit("Failed to log in to MC with provided credentials")

    return token

def getMc(mc, token):
    headers = {
        "Accept": "application/json",
        "Authorization": "Bearer " + token,
    }
    mcapibase = "https://{0}/api/v1/auth/".format(mc)

    def mcapi(path, method="POST", data={}, **kwargs):
        if not data:
            data = kwargs
        r = requests.request(method, mcapibase + path,
                             headers=headers,
                             json=data)
        return r

    return mcapi

def getRegions(mcapi):
    try:
        r = mcapi("controller/show")
        regions = {}
        for ctrl in r.json():
            regions[ctrl["Region"]] = ctrl["Address"]
    except Exception as e:
        sys.exit("Failed to load regions: {0}".format(e))

    return regions

def getOrgs(mcapi):
    try:
        orgs = {}
        r = mcapi("org/show")
        for org in r.json():
            orgs[org["Name"]] = org["Type"]
    except Exception as e:
        sys.exit("Failed to load orgs: {0}".format(e))

    return orgs

def getRoles(mcapi):
    try:
        r = mcapi("role/assignment/show")
    except Exception as e:
        sys.exit("Failed to load roles: {0}".format(e))

    return r.json()

def getLocDefaults():
    try:
        r = requests.get("http://ipinfo.io/geo", timeout=2)
        return r.json()
    except Exception as e:
        return {}

def getLdapPassFromKeychain(vault, user):
    keychain_path = vault + "/ldap"
    p = subprocess.Popen(["security", "find-internet-password", "-a", user,
            "-s", keychain_path, "-w"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            universal_newlines=True)
    out, err = p.communicate()
    out = out.strip()
    if len(out) < 1:
        print("\nConsole password for user \"{0}\" not found in Keychain".format(user))
        print("To add password to keychain, do the following:")
        print("  security add-internet-password -a \"{0}\" -s {1} -T \"\" -w".format(
            user, keychain_path))
        sys.exit(2)

    return out

def readConfig():
    global Mc
    global Mcuser
    global Mcpass
    global Region
    global CloudletOrg 
    global Controller
    global Cloudlet
    global Controller
    global Latitude
    global Longitude
    global EdgevarData
    global OutputDir
    global Vault

    with open(Varsfile, 'r') as stream:
       EdgevarData = load(stream, Loader=Loader)
       Mc = EdgevarData['mc']
       CloudletOrg = EdgevarData['cloudlet-org']
       Cloudlet = EdgevarData['cloudlet']
       Controller = EdgevarData['controller']
       Region = EdgevarData['region']
       Latitude = EdgevarData['latitude']
       Longitude = EdgevarData['longitude']
       OutputDir = EdgevarData['outputdir']
       Vault = EdgevarData['vault']

def yesOrNo(question):
    reply = str(input(question+' (y/n): ')).lower().strip()
    if len(reply) < 1:
       return yesOrNo("please enter")
    if reply[0] == 'y':
        return True
    if reply[0] == 'n':
        return False
    else:
        return yesOrNo("please enter")

def prompt(text, defval, lowercase=False, validate=None, errmsg=None):
    prompttxt = text
    if defval:
        prompttxt += " ({})".format(defval)
    prompttxt += ": "

    reply = None
    while not reply:
        reply = str(input(prompttxt)).strip()
        if lowercase:
            reply = reply.lower()
        if not reply and defval:
            reply = defval
        if validate:
            vresp = validate(reply)
            if vresp is not True:
                reply = None
                if vresp:
                    print(vresp)
    return reply

def saveConfig():
    global Mc
    global Controller
    global Region
    global CloudletOrg
    global Cloudlet
    global Controller
    global Latitude
    global Longitude
    global EdgevarData
    global OutputDir
    global Vault

    os.environ["MC_USER"] = Mcuser
    os.environ["MC_PASSWORD"] = Mcpass
    EdgevarData['mc'] = Mc
    EdgevarData['cloudlet-org'] = CloudletOrg
    EdgevarData['cloudlet'] = Cloudlet
    EdgevarData['controller'] = Controller
    EdgevarData['region'] = Region
    EdgevarData['latitude'] = float(Latitude)
    EdgevarData['longitude'] = float(Longitude)
    EdgevarData['outputdir'] = OutputDir
    EdgevarData['vault'] = Vault

    bakfile = Varsfile+".bak"
    print("Backing up to %s" % bakfile) 
    shutil.copy(Varsfile, bakfile)
    print("Saving to %s" % Varsfile)  
    with open(Varsfile, 'w') as varsfile:
        dump(EdgevarData, varsfile, default_flow_style=False, sort_keys=True)
    varsfile.close()

def getConfig():
   global Mc
   global Mcuser
   global Mcpass
   global Controller
   global Region
   global CloudletOrg
   global Cloudlet
   global Controller
   global Latitude
   global Longitude
   global EdgevarData
   global OutputDir
   global Vault
   global Orgs
   global Roles

   done = False
   while not done:
     print("\n")
     Mc = prompt("Enter Master controller address", Mc, lowercase=True)

     # Compute vault path from MC
     m = re.match(r'console([^\.]*)\.', Mc)
     if not m:
         sys.exit("Failed to determine vault for MC: " + Mc)
     deploy_env = m.group(1)
     if not deploy_env:
         deploy_env = "-main"
     Vault = "https://vault{0}.mobiledgex.net".format(deploy_env)

     Mcuser = os.environ["LDAP_ID"]
     Mcpass = getLdapPassFromKeychain(Vault, Mcuser)

     print("Logging in to MC...")
     token = getMcToken(Mc, Mcuser, Mcpass)
     mcapi = getMc(Mc, token)

     print("Loading regions...")
     regions = getRegions(mcapi)
     region_codes = sorted(regions.keys())

     print("Loading orgs...")
     Orgs = getOrgs(mcapi)

     print("Loading roles...")
     Roles = getRoles(mcapi)

     if Region == "UNSET":
         Region = ''

     while True:
         Region = prompt("Pick region (one of: {0})".format(", ".join(region_codes)), Region)
         if Region in region_codes:
             break
         print("Unknown region: " + Region)
         Region = ''

     Controller = regions[Region].split(':')[0]

     def role_match(role, org, user):
         if role["org"] == org and role["username"] == user \
                 and role["role"] == "OperatorManager":
             return True
         return False


     def validate_cloudlet_org(corg):
         if corg.lower() in ReservedCloudletOrgs:
             return "Sorry, {0} is a reserved org. Please pick another.".format(corg)
         if corg not in Orgs:
             return "Org does not exist: {0}".format(corg)
         if Orgs[corg] != "operator":
             return "Not an operator org: {0}".format(corg)

         found_role = False
         for r in Roles:
             if r["org"] == corg \
                     and r["username"] == Mcuser \
                     and r["role"] == CloudletOrgRoleReqd:
                 found_role = True
                 break
         if not found_role:
             return "User \"{0}\" not {1} in org \"{2}\"".format(
                 Mcuser, CloudletOrgRoleReqd, corg)

         return True

     CloudletOrg = prompt("Enter cloudlet org", CloudletOrg, validate=validate_cloudlet_org)

     if Cloudlet == "UNSET":
         Cloudlet = "hackathon-" + re.sub(r'\W+', '-', getpass.getuser())
     Cloudlet = prompt("Enter cloudlet", Cloudlet)

     if Latitude == "UNSET":
         locdefs = getLocDefaults()
         if "loc" in locdefs:
             locname = "{0}, {1}".format(locdefs["city"], locdefs["country"])
             latlong = locdefs["loc"].split(',')
             Latitude = "{0} \"{1}\"".format(latlong[0], locname)
             Longitude = "{0} \"{1}\"".format(latlong[1], locname)
         else:
             Latitude = DefaultLatitude
             Longitude = DefaultLongitude

     Latitude = prompt("Enter latitude from -90 to 90", str(Latitude)).split(" ")[0]
     Longitude = prompt("Enter longitude from -180 to 180", str(Longitude)).split(" ")[0]
     OutputDir = prompt("Enter output dir", OutputDir)

     print("\nYou entered:")
     print("   MC addr: %s" % Mc)
     print("   MC user: %s" % Mcuser)
     print("   MC password: %s" % "*******")
     print("   Region: %s" % Region)
     print("   Controller: %s" % Controller)
     print("   Cloudlet Org: %s\n" % CloudletOrg)
     print("   Cloudlet: %s" % Cloudlet)
     print("   Latitude: %s" % Latitude)
     print("   Longitude: %s" % Longitude)
     print("   OutputDir: %s" % OutputDir)
     done = yesOrNo("Is this correct?")
   
def startCloudlet():
   global CreateTestfile
   global Setupfile
   global Varsfile

   out = None
   if not yesOrNo("Ready to deploy?"):
      return
   print("*** Running creating provisioning for cloudlet via e2e tests")
   p = subprocess.Popen("e2e-tests -testfile "+CreateTestfile+" -setupfile "+Setupfile+" -varsfile "+Varsfile+" -notimestamp"+" -outputdir "+OutputDir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True)
   out,err = p.communicate()
   print("Done create cloudlet: %s" % out)
   if err != "":
      print("Error: %s" % err)
      return
   if "Failed Tests" in out:
      print ("Failed to create provisioning")
      return

   print("*** Running create deploy local CRM via e2e tests")
   p = subprocess.Popen("e2e-tests -testfile "+DeployTestfile+" -setupfile "+Setupfile+" -varsfile "+Varsfile+" -notimestamp"+" -outputdir "+OutputDir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True)
   out,err = p.communicate()
   print("Done deploy cloudlet: %s" % out)
   if err != "":
      print("Error: %s" % err)
   if "Failed Tests" in out:
      print ("Failed to deploy CRM")

if __name__ == "__main__":
   if not checkPrereqs():
      print("Quitting due to prereqs")
      os._exit(1)
   readConfig()
   getConfig()
   saveConfig() 
   startCloudlet()
