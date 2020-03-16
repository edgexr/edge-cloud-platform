#!/usr/bin/env python


import re
import sys
import os
import shutil
import subprocess
import getpass
import string

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

Edgectl = None
Varsfile = os.environ["GOPATH"]+"/src/github.com/mobiledgex/edge-cloud-infra/e2e-tests/edgebox/edgebox_vars.yml"
Setupfile = os.environ["GOPATH"]+"/src/github.com/mobiledgex/edge-cloud-infra/e2e-tests/setups/edgebox.yml"
CreateTestfile = os.environ["GOPATH"]+"/src/github.com/mobiledgex/edge-cloud-infra/e2e-tests/testfiles/edgebox_create.yml"
DeployTestfile = os.environ["GOPATH"]+"/src/github.com/mobiledgex/edge-cloud-infra/e2e-tests/testfiles/edgebox_deploy.yml"


EdgevarData = None

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
    reply = str(raw_input(question+' (y/n): ')).lower().strip()
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
   reply = str(raw_input(prompttxt+": ")).strip()

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
 
    bakfile = Varsfile+".bak"
    print("Backing up to %s" % bakfile) 
    shutil.copy(Varsfile, bakfile)
    print("Saving to %s" % Varsfile)  
    with open(Varsfile, 'w') as varsfile:
        dump(EdgevarData, varsfile)
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
     Mc = prompt("Enter Master controller address", Mc)
     Mcuser = prompt("Enter MC userid for console/mc login", Mcuser)
     Mcpass = getpass.getpass(prompt="Enter MC password for console/mc login: ", stream=None)
     Region = prompt("Enter region, e.g. US, EU, JP", Region)
     Region = string.upper(Region)
     CloudletOrg = prompt("Enter cloudlet org", CloudletOrg)
     Controller = prompt("Enter controller", Controller)
     Cloudlet = prompt("Enter cloudlet", Cloudlet)
     Latitude = prompt("Enter latitude from -90 to 90", Latitude)
     Longitude = prompt("Enter longitude from -180 to 180", Longitude)
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
   p = subprocess.Popen("e2e-tests -testfile "+CreateTestfile+" -setupfile "+Setupfile+" -varsfile "+Varsfile+" -notimestamp"+" -outputdir "+OutputDir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
   out,err = p.communicate()
   print("Done create cloudlet: %s" % out)
   if err != "":
      print("Error: %s" % err)
      return
   if "Failed Tests" in out:
      print ("Failed to create provisioning")
      return

   print("*** Running create deploy local CRM via e2e tests")
   p = subprocess.Popen("e2e-tests -testfile "+DeployTestfile+" -setupfile "+Setupfile+" -varsfile "+Varsfile+" -notimestamp"+" -outputdir "+OutputDir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
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
        
