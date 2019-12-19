#!/usr/bin/python
import re
import sys
import os
import shutil
import subprocess
import getpass

from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

Mcuser = os.getenv("MC_USER", "")
Mcpass = os.getenv("MC_PASSWORD", "")
Region = None
Operator = None
Cloudlet = None
Mc = None
Controller = None
Latitude = None
Longitude = None

Edgectl = None
Varsfile = os.environ["GOPATH"]+"/src/github.com/mobiledgex/edge-cloud-infra/e2e-tests/edgebox/edgebox_vars.yml"
Setupfile = os.environ["GOPATH"]+"/src/github.com/mobiledgex/edge-cloud-infra/e2e-tests/setups/edgebox.yml"
CreateTestfile = os.environ["GOPATH"]+"/src/github.com/mobiledgex/edge-cloud-infra/e2e-tests/testfiles/edgebox_create.yml"
DeployTestfile = os.environ["GOPATH"]+"/src/github.com/mobiledgex/edge-cloud-infra/e2e-tests/testfiles/edgebox_deploy.yml"


EdgevarData = None

def readConfig():
    global Mc
    global Mcuser
    global Mcpass
    global Region
    global Operator
    global Controller
    global Cloudlet
    global Controller
    global Latitude
    global Longitude
    global EdgevarData

    with open(Varsfile, 'r') as stream:
       EdgevarData = load(stream, Loader=Loader)
       Mc = EdgevarData['mc']
       Operator = EdgevarData['operator']
       Cloudlet = EdgevarData['cloudlet']
       Controller = EdgevarData['controller']
       Region = EdgevarData['region']
       Latitude = EdgevarData['latitude']
       Longitude = EdgevarData['longitude']
    
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
   reply = str(raw_input(prompttxt+": ")).lower().strip()

   if reply == "":
      if defval == "":
        return prompt(text, defval)
      return defval      
   return reply

def saveConfig():
    global Mc
    global Controller
    global Region
    global Operator
    global Cloudlet
    global Controller
    global Latitude
    global Longitude
    global EdgevarData

    os.environ["MC_USER"] = Mcuser
    os.environ["MC_PASSWORD"] = Mcpass
    EdgevarData['mc'] = Mc
    EdgevarData['operator'] = Operator
    EdgevarData['cloudlet'] = Cloudlet
    EdgevarData['controller'] = Controller
    EdgevarData['region'] = Region
    EdgevarData['latitude'] = float(Latitude)
    EdgevarData['longitude'] = float(Longitude)
 
    bakfile = Varsfile+".bak"
    print("Backing up to %s" % bakfile) 
    shutil.copy(Varsfile, bakfile)
    print("Saving to %s" % Varsfile)  
    with open(Varsfile, 'w') as varsfile:
        dump(EdgevarData, varsfile)

def getConfig():
   global Mc
   global Mcuser
   global Mcpass
   global Controller
   global Region
   global Operator
   global Cloudlet
   global Controller
   global Latitude
   global Longitude
   global EdgevarData

   done = False
   while not done:
     Mc = prompt("Enter Master controller address", Mc)
     Mcuser = prompt("Enter MC userid for console/mc login", Mcuser)
     Mcpass = getpass.getpass(prompt="Enter MC password for console/mc login: ", stream=None)
     Region = prompt("Enter region, e.g. US, EU, JP", Region)
     Controller = prompt("Enter controller", Controller)
     Cloudlet = prompt("Enter cloudlet", Cloudlet)
     Latitude = prompt("Enter latitude from -90 to 90", Latitude)
     Longitude = prompt("Enter longitude from -180 to 180", Longitude)

     print("\nYou entered:")
     print("   MC addr: %s" % Mc)
     print("   MC user: %s" % Mcuser)
     print("   MC password: %s" % "*******")
     print("   Region: %s" % Region)
     print("   Controller: %s" % Controller)
     print("   Operator: %s\n" % Operator)
     print("   Cloudlet: %s" % Cloudlet)
     print("   Latitude: %s" % Latitude)
     print("   Longitude: %s" % Longitude)
     done = yesOrNo("Is this correct?")
   
def startCloudlet():
   global CreateTestfile
   global Setupfile
   global Varsfile

   out = None
   if not yesOrNo("Ready to deploy?"):
      return
   print("*** Running creating provisioning for cloudlet via e2e tests")
   p = subprocess.Popen("e2e-tests -testfile "+CreateTestfile+" -setupfile "+Setupfile+" -varsfile "+Varsfile+" -notimestamp", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
   out,err = p.communicate()
   print("Done create cloudlet: %s" % out)
   if err != "":
      print("Error: %s" % err)


   print("*** Running create deploy local CRM via e2e tests")
   p = subprocess.Popen("e2e-tests -testfile "+DeployTestfile+" -setupfile "+Setupfile+" -varsfile "+Varsfile+" -notimestamp", stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
   out,err = p.communicate()
   print("Done deploy cloudlet: %s" % out)
   if err != "":
      print("Error: %s" % err)


if __name__ == "__main__":
   readConfig()
   getConfig()
   saveConfig() 
   startCloudlet()
        
