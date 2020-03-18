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

Edgectl = None
Varsfile = "./edgebox_vars.yml"
Setupfile = "../setups/edgebox.yml"
CreateTestfile = "../testfiles/edgebox_create.yml"
DeployTestfile = "../testfiles/edgebox_deploy.yml"

EdgevarData = None

# Handle incompatibility between Pythons 2 and 3
try:
    input = raw_input
except NameError:
    pass

def checkPrereqs():
    gitid = os.getenv("GITHUB_ID", "")
    vaultRole = os.getenv("VAULT_ROLE_ID", "")
    vaultSecret = os.getenv("VAULT_SECRET_ID", "")
    if gitid == "":
       print("GITHUB_ID env var not set")
       if vaultRole != "" and vaultSecret != "":
           print("Using VAULT_ROLE_ID and VAULT_SECRET env vars")
       else:
           print("No appropriate Vault auth found, please set GITHUB_ID or VAULT_ROLE_ID and VAULT_SECRET_ID")
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

def getRegions(mc, token):
    try:
        r = requests.post("https://{0}/api/v1/auth/controller/show".format(mc),
                          headers={"Authorization": "Bearer " + token})
        regions = {}
        for ctrl in r.json():
            regions[ctrl["Region"]] = ctrl["Address"]
    except Exception as e:
        sys.exit("Failed to load regions: {0}".format(e))

    return regions

def getLocDefaults():
    try:
        r = requests.get("http://ipinfo.io/geo", timeout=2)
        return r.json()
    except Exception as e:
        return {}

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

def prompt(text, defval):
   prompttxt = text
   if defval != "":
      prompttxt += " ("+str(defval)+")"
   reply = str(input(prompttxt+": ")).lower().strip()

   if reply == "":
      if defval == "":
        return prompt(text, defval)
      return defval      
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

    # Compute vault path from MC
    m = re.match(r'console([^\.]*)\.', Mc)
    if not m:
        sys.exit("Failed to determine vault for MC: " + Mc)
    deploy_env = m.group(1)
    if not deploy_env:
        deploy_env = "-main"
    EdgevarData['vault'] = "https://vault{0}.mobiledgex.net".format(deploy_env)
 
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

   done = False
   while not done:
     print("\n")
     Mc = prompt("Enter Master controller address", Mc)
     Mcuser = prompt("Enter MC userid for console/mc login", Mcuser)
     Mcpass = getpass.getpass(prompt="Enter MC password for console/mc login: ", stream=None)

     print("Logging in to MC...")
     token = getMcToken(Mc, Mcuser, Mcpass)

     print("Loading regions...")
     regions = getRegions(Mc, token)
     region_codes = sorted(regions.keys())

     if Region == "UNSET":
         Region = ''

     while True:
         Region = prompt("Pick region (one of: {0})".format(", ".join(region_codes)), Region).upper()
         if Region in region_codes:
             break
         print("Unknown region: " + Region)
         Region = ''

     Controller = regions[Region].split(':')[0]
     CloudletOrg = prompt("Enter cloudlet org", CloudletOrg)

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
