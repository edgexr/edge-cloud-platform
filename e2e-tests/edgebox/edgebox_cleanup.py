#!/usr/bin/python
import re
import sys
import os
import subprocess
from yaml import load, dump
try:
    from yaml import CLoader as Loader, CDumper as Dumper
except ImportError:
    from yaml import Loader, Dumper

Debug = False
Operator = None
Cloudlet = None
Appinsts = None
Controller = None
Clusterinsts = None
Edgectl = None
TlsDir = os.environ["GOPATH"]+"/src/github.com/mobiledgex/edge-cloud/tls/out"
Varsfile = os.environ["GOPATH"]+"/src/github.com/mobiledgex/edge-cloud-infra/e2e-tests/edgebox/edgebox_vars.yml"

def readConfig():
    global Operator
    global Controller
    global Cloudlet
    global Controller
    global Edgectl

    with open(Varsfile, 'r') as stream:
       data = load(stream, Loader=Loader)
       Operator = data['operator']
       Cloudlet = data['cloudlet']
       Controller = data['controller']
       Edgectl = "/usr/local/bin/edgectl --addr %s:55001 --tls %s/mex-client.crt" % (Controller, TlsDir)
    
def getAppClusterInsts():
        global Appinsts
        global Clusterinsts

        print("getAppInsts")
        if not Operator:
                sys.exit("Missing Operator")

        if not Cloudlet:
                sys.exit("missing cloudlet")
                
        p = subprocess.Popen([Edgectl+" controller ShowAppInst operator=\""+Operator+"\"   cloudlet=\""+Cloudlet+"\""], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
       
        out,err = p.communicate()
        Appinsts = load(out, Loader=Loader)
        print ("\nFound APPINST %s\n" % Appinsts)
        if not Appinsts or len(Appinsts) == 0:
           print "ERROR: no data\n"


        p = subprocess.Popen([Edgectl+" controller ShowClusterInst operator=\""+Operator+"\" cloudlet=\""+Cloudlet+"\""], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
       
        out,err = p.communicate()
        Clusterinsts = load(out, Loader=Loader)
        print ("\nFound CLUSTERINST %s]n" % Clusterinsts)
        if not Clusterinsts or len(Clusterinsts) == 0:
           print "ERROR: no data\n"

def deleteAppInsts():
     print("\n\ndeleteAppInsts\n")

     if not Appinsts or len(Appinsts) == 0:
           print "nothing to delete\n"
           return

     for appinst in Appinsts:
         appname = appinst['key']['appkey']['name']
         devname = appinst['key']['appkey']['developerkey']['name']
         appvers = appinst['key']['appkey']['version']
         cloudletname = appinst['key']['clusterinstkey']['cloudletkey']['name']
         operator = appinst['key']['clusterinstkey']['cloudletkey']['operatorkey']['name']
         clustername = appinst['key']['clusterinstkey']['clusterkey']['name']
         
         if operator != Operator:
             sys.exit("Mismatched operator -- this is a bug")
         
         command = (Edgectl+" controller DeleteAppInst developer=\""+devname+"\" appname=\""+appname+"\" appvers=\""+appvers+"\""
               " cloudlet=\""+cloudletname+"\"  cluster=\""+clustername+"\""
               " developer=\""+devname+"\""+ " operator=\""+operator+"\" crmoverride=IgnoreCrmAndTransientState")

         print ("DELETE COMMAND: "+command)
         p = subprocess.Popen([command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
       
         out,err = p.communicate()
         print ("Command Out:"+out)
         if err:
           print("Error: "+err)

def deleteClusterInsts():
     print("\n\ndeleteClusterInsts\n")

     if not Clusterinsts or len(Clusterinsts) == 0:
           print "nothing to delete\n"
           return

     for clinst in Clusterinsts:
         devname = ""
         clustername = clinst['key']['clusterkey']['name']
         if 'developer' in  clinst['key']:
            devname = clinst['key']['developer']
         cloudletname = clinst['key']['cloudletkey']['name']
         operator = clinst['key']['cloudletkey']['operatorkey']['name']
         
         if operator != Operator:
             sys.exit("Mismatched operator -- this is a bug")
         if cloudletname != Cloudlet:
             sys.exit("Mismatched cloudlet -- this is a bug")        
 
         command = (Edgectl+" controller DeleteClusterInst developer=\""+devname+"\""
               " cloudlet=\""+Cloudlet+"\" cluster=\""+clustername+"\""
               " operator=\""+Operator+"\" crmoverride=IgnoreCrmAndTransientState")

         print ("DELETE COMMAND: "+command)
         p = subprocess.Popen([command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
       
         out,err = p.communicate()
         print ("Command Out:"+out)
         if err:
             print("Error: "+err)

def deleteCloudlet():
    command = (Edgectl+" controller DeleteCloudlet name=\""+Cloudlet+"\" operator=\""+Operator+"\" crmoverride=IgnoreCrmAndTransientState")  
    print ("DELETE COMMAND: "+command)
    p = subprocess.Popen([command], stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

    out,err = p.communicate()
    print ("Command Out:"+out)


def dockerCleanup():
   print ("Cleaning up docker containers")
   subprocess.call('docker stop $(docker ps -a -q)', shell=True)
   subprocess.call('docker rm $(docker ps -a -q)', shell=True)
   print ("Cleaning up docker networks")
   subprocess.call('docker network list --format {{.Name}}|grep kubeadm|xargs docker network rm', shell=True)
def yesOrNo(question):
    reply = str(raw_input(question+' (y/n): ')).lower().strip()
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
   if yesOrNo("CONFIRM: Delete operator: %s cloudlet: %s from controller: %s ?\n" % (Operator, Cloudlet, Controller)):
     getAppClusterInsts()
     deleteAppInsts()
     deleteClusterInsts()
     deleteCloudlet()
     dockerCleanup()        
     crmCleanup()   

        
