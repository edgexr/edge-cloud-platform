#!/usr/bin/env python

import re
import sys
import os
import subprocess
from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

# Handle incompatibility between Pythons 2 and 3
try:
    input = raw_input
except NameError:
    pass

Debug = False
CloudletOrg = None
Cloudlet = None
Appinsts = None
Controller = None
Clusterinsts = None
Edgectl = None
TlsDir = "tlsout"

Varsfile = "./edgebox_vars.yml"


def readConfig():
    global CloudletOrg
    global Controller
    global Cloudlet
    global Controller
    global Edgectl

    with open(Varsfile, 'r') as stream:
       data = load(stream, Loader=Loader)
       CloudletOrg = data['cloudlet-org']
       Cloudlet = data['cloudlet']
       Controller = data['controller']
       Edgectl = "edgectl --addr %s:55001 --tls %s/mex-client.crt" % (Controller, TlsDir)
    
def getAppClusterInsts():
        global Appinsts
        global Clusterinsts

        print("getAppInsts")
        if not CloudletOrg:
                sys.exit("CloudletOrg")

        if not Cloudlet:
                sys.exit("missing cloudlet")
                
        p = subprocess.Popen([Edgectl+" controller ShowAppInst cloudlet-org=\""+CloudletOrg+"\"   cloudlet=\""+Cloudlet+"\""], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True)
       
        out,err = p.communicate()
        Appinsts = load(out, Loader=Loader)
        print ("\nFound APPINST %s\n" % Appinsts)
        if not Appinsts or len(Appinsts) == 0:
           print("ERROR: no data\n")


        p = subprocess.Popen([Edgectl+" controller ShowClusterInst cloudlet-org=\""+CloudletOrg+"\" cloudlet=\""+Cloudlet+"\""], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True)
       
        out,err = p.communicate()
        Clusterinsts = load(out, Loader=Loader)
        print ("\nFound CLUSTERINST %s]n" % Clusterinsts)
        if not Clusterinsts or len(Clusterinsts) == 0:
           print("ERROR: no data\n")

def deleteAppInsts():
     print("\n\ndeleteAppInsts\n")

     if not Appinsts or len(Appinsts) == 0:
           print("nothing to delete\n")
           return

     for appinst in Appinsts:
         appname = appinst['key']['appkey']['name']
         apporg = appinst['key']['appkey']['organization']
         appvers = appinst['key']['appkey']['version']
         cloudletname = appinst['key']['clusterinstkey']['cloudletkey']['name']
         cloudletorg = appinst['key']['clusterinstkey']['cloudletkey']['organization']
         clustername = appinst['key']['clusterinstkey']['clusterkey']['name']
         
         if cloudletorg != CloudletOrg:
             sys.exit("Mismatched cloudlet org -- this is a bug")
         
         command = (Edgectl+" controller DeleteAppInst app-org=\""+apporg+"\" appname=\""+appname+"\" appvers=\""+appvers+"\""
               " cloudlet=\""+cloudletname+"\"  cluster=\""+clustername+"\""
               " app-org=\""+apporg+"\""+ " cloudlet-org=\""+cloudletorg+"\" crmoverride=IgnoreCrmAndTransientState")

         print ("DELETE COMMAND: "+command)
         p = subprocess.Popen([command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True)
       
         out,err = p.communicate()
         print ("Command Out:"+out)
         if err:
           print("Error: "+err)

def deleteClusterInsts():
     print("\n\ndeleteClusterInsts\n")

     if not Clusterinsts or len(Clusterinsts) == 0:
           print("nothing to delete\n")
           return

     for clinst in Clusterinsts:
         devname = ""
         clustername = clinst['key']['clusterkey']['name']
         if 'organization' in  clinst['key']:
            clusterorg = clinst['key']['organization']
         cloudletname = clinst['key']['cloudletkey']['name']
         cloudletorg = clinst['key']['cloudletkey']['organization']
         
         if cloudletorg != CloudletOrg:
             sys.exit("Mismatched cloudletorg -- this is a bug")        
 
         command = (Edgectl+" controller DeleteClusterInst cluster-org=\""+clusterorg+"\""
               " cloudlet=\""+Cloudlet+"\" cluster=\""+clustername+"\""
               " cloudlet-org=\""+CloudletOrg+"\" crmoverride=IgnoreCrmAndTransientState")

         print ("DELETE COMMAND: "+command)
         p = subprocess.Popen([command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True)
       
         out,err = p.communicate()
         print ("Command Out:"+out)
         if err:
             print("Error: "+err)

def deleteCloudlet():
    command = (Edgectl+" controller DeleteCloudlet name=\""+Cloudlet+"\" cloudlet-org=\""+CloudletOrg+"\" crmoverride=IgnoreCrmAndTransientState")  
    print ("DELETE COMMAND: "+command)
    p = subprocess.Popen([command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, universal_newlines=True)

    out,err = p.communicate()
    print ("Command Out:"+out)


def dockerCleanup():
   print ("Cleaning up docker containers")
   subprocess.call('docker stop $(docker ps -a -q)', shell=True)
   subprocess.call('docker rm $(docker ps -a -q)', shell=True)
   print ("Cleaning up docker networks")
   subprocess.call('docker network list --format {{.Name}}|grep kubeadm|xargs docker network rm', shell=True)
def yesOrNo(question):
    reply = str(input(question+' (y/n): ')).lower().strip()
    if reply[0] == 'y':
        return True
    if reply[0] == 'n':
        return False
    else:
        return yesOrNo("please enter")

def crmCleanup():
     print ("Killing CRM process")
     subprocess.call('pkill -9 crmserver', shell=True)


if __name__ == "__main__":
   readConfig()
   print("\n")
   if yesOrNo("CONFIRM: Delete cloudlet org: %s cloudlet: %s from controller: %s ?\n" % (CloudletOrg, Cloudlet, Controller)):
     getAppClusterInsts()
     deleteAppInsts()
     deleteClusterInsts()
     deleteCloudlet()
     dockerCleanup()        
     crmCleanup()   

        
