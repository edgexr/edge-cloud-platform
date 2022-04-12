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


import subprocess
import sys
import numpy as np
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.animation as animation
import time
import argparse

num_minutes = .1

parser = argparse.ArgumentParser(description = 'collect network data')
parser.add_argument('--latency', action='store_true', help='collect latency data')
parser.add_argument('--udp', action='store_true', help='collect udp data')
parser.add_argument('--tcp', action='store_true', help='collect tcp data')
parser.add_argument('--minutes', type=float, default=1, help='number of minutes to run. default=1min')
args = parser.parse_args()

if not args.latency and not args.udp and not args.tcp:
    print('must include 1 or more of \'--latency\' or \'--udp\' or \'--tcp\'\n')
    parser.print_help()
    sys.exit(1)

num_minutes = args.minutes
#print(args)
#print(args.latency)
#sys.exit(1)
stamp = str(int(time.time()))

outfileVm_tcp = 'iperf_tcp_vm_data_' + str(int(num_minutes)) + 'mins_' + stamp + '.txt'
outfileDocker_tcp = 'iperf_tcp_docker_data_' + str(int(num_minutes)) + 'mins_' + stamp + '.txt'
outfileK8s_tcp = 'iperf_tcp_k8s_data_' + str(int(num_minutes)) + 'mins_' + stamp + '.txt'

outfileVm_udp = 'iperf_udp_vm_data_'  + str(int(num_minutes)) + 'mins_' + stamp + '.txt'
outfileDocker_udp = 'iperf_udp_docker_data_'  + str(int(num_minutes)) + 'mins_' + stamp + '.txt'
outfileK8s_udp = 'iperf_udp_k8s_data_'  + str(int(num_minutes)) + 'mins_' + stamp + '.txt'

logfileVm_tcp = 'iperf_tcp_vm_' + str(int(num_minutes)) + 'mins_' + stamp + '.log'
logfileDocker_tcp = 'iperf_tcp_docker_' + str(int(num_minutes)) + 'mins_' + stamp + '.log'
logfileK8s_tcp = 'iperf_tcp_k8s_' + str(int(num_minutes)) + 'mins_' + stamp + '.log'

logfileVm_udp = 'iperf_udp_vm_' + str(int(num_minutes)) + 'mins_' + stamp + '.log'
logfileDocker_udp = 'iperf_udp_docker_' + str(int(num_minutes)) + 'mins_' + stamp + '.log'
logfileK8s_udp = 'iperf_udp_k8s_' + str(int(num_minutes)) + 'mins_' + stamp + '.log'

outfileVm_ping = 'piping_vm_data_' + str(int(num_minutes)) + 'mins_' + stamp + '.txt'
outfileDocker_ping = 'piping_docker_data_' + str(int(num_minutes)) + 'mins_' + stamp + '.txt'
outfileK8s_ping = 'piping_k8s_data_' + str(int(num_minutes)) + 'mins_' + stamp + '.txt'
logfileVm_ping = 'piping_vm_' + str(int(num_minutes)) + 'mins_' + stamp + '.log'
logfileDocker_ping = 'piping_docker_' + str(int(num_minutes)) + 'mins_' + stamp + '.log'
logfileK8s_ping = 'piping_k8s_' + str(int(num_minutes)) + 'mins_' + stamp + '.log'

graphfile = 'iperf_vm_docker_k8s_' + str(int(num_minutes)) + 'mins_' + stamp

#t = [1, 2, 3]
#print(t)
#print(','.join(map(str,t)))
#sys.exit(1)

pingcmdVm = './client_latency.py ' + str(int(num_minutes*60)) + ' 40.113.219.126 2015'
pingcmdDocker = './client_latency.py ' + str(int(num_minutes*60)) + ' 40.113.219.126 2014' 
pingcmdK8s = './client_latency.py ' + str(int(num_minutes*60)) + ' 40.122.69.206 2014'

#iperfcmdVm = 'iperf -c 40.113.219.126 -p 2012 -w 10M -t ' + str(int(num_minutes*60)) + ' | tail -1 | awk \'{print $8\" \"$9}\''
iperfcmdVm_tcp = 'iperf -c 40.113.219.126 -p 2012 -w 10M -t ' + str(int(num_minutes*60))
iperfcmdDocker_tcp = 'iperf -c 40.113.219.126 -p 2013 -w 10M -t ' + str(int(num_minutes*60))
iperfcmdK8s_tcp = 'iperf -c 23.99.250.40 -p 2011 -w 10M -t ' + str(int(num_minutes*60))
#iperfcmdVmUdp = 'iperf -c 40.113.219.126 -p 2010 -u -l 1000 -t ' + str(int(num_minutes*60)) + ' | grep \" ms \" | awk \'{print $7\" \"$8\" \"$9\" \"$10\" \"$NF}\''
iperfcmdVmUdp = 'iperf -c 40.113.219.126 -p 2010 -u -l 1000 -t ' + str(int(num_minutes*60))
iperfcmdDockerUdp = 'iperf -c 40.113.219.126 -p 2011 -u -l 1000 -t ' + str(int(num_minutes*60))
iperfcmdK8sUdp = 'iperf -c 40.122.36.17 -p 2011 -u -l 1000 -t ' + str(int(num_minutes*60))

print('runtime={} mins'.format(num_minutes))
print('vm tcp -    ', iperfcmdVm_tcp)
print('docker tcp -', iperfcmdDocker_tcp)
print('k8s tcp -   ', iperfcmdK8s_tcp)
print('vm udp -    ', iperfcmdVmUdp)
print('docker udp -', iperfcmdDockerUdp)
print('k8s udp -   ', iperfcmdK8sUdp)
print('vm ping-    ', pingcmdVm)
print('docker ping-', pingcmdDocker)
print('k8s ping-   ', pingcmdK8s)

#pingcmd = 'ls'
#out = subprocess.run(pingcmd, stdout=subprocess.PIPE, shell=True, check=True)
#print(out)
#for l in out.stdout:
#    print(l)

#fig = plt.figure()
#ax1 = fig.add_subplot(1,1,1)
#ax1.set_ylim([0,100])
#
#plt.subplot(1,2,1)
fig, axarr = plt.subplots(2,2)
#print(axarr)
#sys.exit(1)

def run_tcp(cmd, outfile_name, logfile_name):
    print('running', cmd)

    process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout = process.stdout.decode("utf-8")
    #print('stdout',stdout)
    with open(logfile_name, 'w') as outfile:
        outfile.write(stdout)

    lines = stdout.split('\n')
    words = lines[-2].split(' ')
    rate = words[-2]
    unit = words[-1]
    #rate,unit = stdout.split(' ')
    #rateVm,unitVm = ('200','mbs')
    print(rate, unit)
    
    with open(outfile_name, 'w') as outfile:
        outfile.write(rate + ' ' + unit)

    return rate, unit

def run_ping(cmd, outfile_name, logfile_name):
    print('running', cmd)

    process = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)

    logfile = open(logfile_name, 'w')

    xar = []
    yar = []
    count = 1

    while True:
        out = process.stdout.readline().decode()
        p = process.poll()
        if out == '' and p is not None:
            break
        if out:
            line = out.strip()
            logfile.write(line + '\n')
            if 'latency' in line:
                time = out.strip().split(' ')[1]
                #print('latency:',time)
                xar.append(count)
                yar.append(float(time))
                count = count + 1
            else:
                print('error')
                sys.exit(1)
    rc = process.poll()
    print(xar,yar)
    with open(outfile_name, 'w') as outfile:
        outfile.write(', '.join(map(str,xar)) + '\n')
        outfile.write(', '.join(map(str,yar)) + '\n')

    logfile.close()
    return xar, yar


def graph_tcp(rateVm=0, rateDocker=0, rateK8s=0, unit='noUnit'):
    barlist = axarr[0,0].bar([1,2,3], [int(float(rateVm)),int(float(rateDocker)),int(float(rateK8s))], align='center')
    #r1 = ax.var(1, int(float(rateVm)), color='blue'
    axarr[0,0].set_xticks([1,2,3])
    axarr[0,0].set_xticklabels(['vm','docker','k8s'])
    axarr[0,0].set_ylabel(unit)
    axarr[0,0].set_ylim([0,1.3*barlist[0].get_height()])
    #print(barlist[0].get_height() + barlist[0].get_width()/2, 1.05*barlist[0].get_height(), rateVm)

    axarr[0,0].text(barlist[0].get_x() + barlist[0].get_width()/2, 1.05*barlist[0].get_height(), rateVm, ha='center', va='bottom')
    axarr[0,0].text(barlist[1].get_x() + barlist[1].get_width()/2, 1.05*barlist[1].get_height(), rateDocker, ha='center', va='bottom')
    axarr[0,0].text(barlist[2].get_x() + barlist[2].get_width()/2, 1.05*barlist[2].get_height(), rateK8s, ha='center', va='bottom')
    #axarr[0,0].text(0,1.05*barlist[0].get_height(),'andy',ha='center', va='bottom')
    barlist[0].set_color('blue')
    barlist[1].set_color('red')
    barlist[2].set_color('green')

    axarr[0,0].set_title('TCP Bandwidth')

def graph_ping(xar_vm, yar_vm, xar_docker, yar_docker, xar_k8s, yar_k8s):
    latency_vm_plot = axarr[1,1].plot(xar_vm,yar_vm, color='blue', label='vm')
    latency_docker_plot = axarr[1,1].plot(xar_docker,yar_docker, color='red', label='docker')
    latency_k8s_plot = axarr[1,1].plot(xar_k8s,yar_k8s, color='green', label='k8s')

    axarr[1,1].legend(handles=[latency_vm_plot[0], latency_docker_plot[0], latency_k8s_plot[0]])

    mean_vm = np.mean(yar_vm, axis=0)
    mean_docker = np.mean(yar_docker, axis=0)
    mean_k8s = np.mean(yar_k8s, axis=0)

    axarr[1,1].axhline(y=mean_vm, color='blue')
    axarr[1,1].axhline(y=mean_docker, color='red')
    axarr[1,1].axhline(y=mean_k8s, color='green')

    axarr[1,1].set_title('Latency')
    axarr[1,1].set_ylabel('ms')
    axarr[1,1].set_xlabel('time(sec)')

def run_tcp_orig():
    processVm = subprocess.run(iperfcmdVm, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    rateVm,unitVm = processVm.stdout.decode("utf-8").split(' ')
    #rateVm,unitVm = ('200','mbs')
    print(rateVm, unitVm)
    outfile = open(outfileVm, 'w')
    outfile.write(rateVm + ' ' + unitVm)

    processDocker = subprocess.run(iperfcmdDocker, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    rateDocker,unitDocker = processDocker.stdout.decode("utf-8").split(' ')
    print(rateDocker, unitDocker)
    outfileD = open(outfileDocker, 'w')
    outfileD.write(rateDocker + ' ' + unitDocker)

    barlist = axarr[0,0].bar([1,2], [int(float(rateVm)),int(float(rateDocker))], align='center')
    #r1 = ax.var(1, int(float(rateVm)), color='blue'
    axarr[0,0].set_xticks([1,2])
    axarr[0,0].set_xticklabels(['vm','docker'])
    axarr[0,0].set_ylabel(unitVm)
    axarr[0,0].set_ylim([0,1.3*barlist[0].get_height()])
    print(barlist[0].get_height() + barlist[0].get_width()/2, 1.05*barlist[0].get_height(), rateVm)
    
    axarr[0,0].text(barlist[0].get_x() + barlist[0].get_width()/2, 1.05*barlist[0].get_height(), rateVm, ha='center', va='bottom')
    axarr[0,0].text(barlist[1].get_x() + barlist[1].get_width()/2, 1.05*barlist[1].get_height(), rateDocker, ha='center', va='bottom')
    #axarr[0,0].text(0,1.05*barlist[0].get_height(),'andy',ha='center', va='bottom')
    barlist[0].set_color('blue')
    barlist[1].set_color('red')
    axarr[0,0].set_title('TCP Bandwidth')

def run_udp(cmd, outfile_name, logfile_name):
    print('running', cmd)
    process = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    stdout = process.stdout.decode("utf-8")
    #print('stdout',stdout)
    with open(logfile_name, 'w') as outfile:
        outfile.write(stdout)

    lines = stdout.split('\n')
    line_to_process = None
    for l in lines:
        if '%' in l:
            line_to_process = l
    words = line_to_process.split(' ')
    loss = words[-1]
    jitter_unit = None
    jitter = None
    rate = None
    unit = None
    for index,word in enumerate(words):
        if word == 'ms':
            print('jitter')
            jitter_unit = 'ms'
            jitter = words[index-1]
        if '/sec' in word:
            unit = word
            rate = words[index-1]
    print(rate, unit,jitter,jitter_unit,loss)
    #rate,unit,jitter,jitter_unit,loss = process.stdout.decode("utf-8").split(' ')
    with open(outfile_name, 'w') as outfile:
        outfile.write(rate + ' ' + unit + ' ' + jitter + ' ' + jitter_unit + ' ' + loss)

    return rate, jitter, loss 

def graph_udp(jitterVm=0, jitterDocker=0, jitterK8s=0, jitter_unit='ms', lossVm='(0%)', lossDocker='(0%)', lossK8s='(0%)'):
    barlist_jitter = axarr[0,1].bar([1,2,3], [float(jitterVm),float(jitterDocker),float(jitterK8s)], align='center')
    axarr[0,1].set_xticks([1,2,3])
    axarr[0,1].set_xticklabels(['vm','docker','k8s'])
    axarr[0,1].set_ylabel(jitter_unit)
    axarr[0,1].set_title('UDP Jitter')
    barlist_jitter[0].set_color('blue')
    barlist_jitter[1].set_color('red')
    barlist_jitter[2].set_color('green')

    axarr[0,1].set_ylim([0,1])

    axarr[0,1].text(barlist_jitter[0].get_x() + barlist_jitter[0].get_width()/2, 1.05*barlist_jitter[0].get_height(), jitterVm, ha='center', va='bottom')
    axarr[0,1].text(barlist_jitter[1].get_x() + barlist_jitter[1].get_width()/2, 1.05*barlist_jitter[1].get_height(), jitterDocker, ha='center', va='bottom')
    axarr[0,1].text(barlist_jitter[2].get_x() + barlist_jitter[2].get_width()/2, 1.05*barlist_jitter[2].get_height(), jitterK8s, ha='center', va='bottom')

    #lossVm_percent = int(lossVm.split('/')[0])/int(lossVm.split('/')[1])
    #lossDocker_percent = int(lossDocker.split('/')[0])/int(lossDocker.split('/')[1])
    #lossK8s_percent = int(lossK8s.split('/')[0])/int(lossK8s.split('/')[1])
    lossVm_percent = float(lossVm.split('%')[0].split('(')[1])
    lossDocker_percent = float(lossDocker.split('%')[0].split('(')[1])
    lossK8s_percent = float(lossK8s.split('%')[0].split('(')[1])

    barlist_loss = axarr[1,0].bar([1,2,3], [lossVm_percent,lossDocker_percent,lossK8s_percent], align='center')
    axarr[1,0].set_xticks([1,2,3])
    axarr[1,0].set_xticklabels(['vm','docker','k8s'])
    axarr[1,0].set_ylabel('%')
    axarr[1,0].set_title('UDP Loss %')
    barlist_loss[0].set_color('blue')
    barlist_loss[1].set_color('red')
    barlist_loss[2].set_color('green')

    axarr[1,0].set_ylim(0,100)

    axarr[1,0].text(barlist_loss[0].get_x() + barlist_loss[0].get_width()/2, 1.05*barlist_loss[0].get_height(), lossVm_percent, ha='center', va='bottom')
    axarr[1,0].text(barlist_loss[1].get_x() + barlist_loss[1].get_width()/2, 1.05*barlist_loss[1].get_height(), lossDocker_percent, ha='center', va='bottom')
    axarr[1,0].text(barlist_loss[2].get_x() + barlist_loss[2].get_width()/2, 1.05*barlist_loss[2].get_height(), lossK8s_percent, ha='center', va='bottom')

def run_udp_orig():
    processVm_udp = subprocess.run(iperfcmdVmUdp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    print(processVm_udp.stdout.decode("utf-8"))
    rateVm_udp,unitVm_udp,jitterVm,jitterVm_unit,lossVm = processVm_udp.stdout.decode("utf-8").split(' ')
    print(rateVm_udp, unitVm_udp,jitterVm,jitterVm_unit,lossVm)
    outfileVm = open(outfileVm_udp, 'w')
    outfileVm.write(rateVm_udp + ' ' + unitVm_udp + ' ' + jitterVm + ' ' + jitterVm_unit + ' ' + lossVm)

    processDocker_udp = subprocess.run(iperfcmdDockerUdp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    print(processDocker_udp.stdout.decode("utf-8"))
    rateDocker_udp,unitDocker_udp,jitterDocker,jitterDocker_unit,lossDocker = processDocker_udp.stdout.decode("utf-8").split(' ')
    print(rateDocker_udp, unitDocker_udp,jitterDocker,jitterDocker_unit,lossDocker)
    outfileDocker = open(outfileDocker_udp, 'w')
    outfileDocker.write(rateDocker_udp + ' ' + unitDocker_udp + ' ' + jitterDocker + ' ' + jitterDocker_unit + ' ' + lossDocker)

    processK8s_udp = subprocess.run(iperfcmdK8sUdp, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True)
    print(processK8s_udp.stdout.decode("utf-8"))
    rateK8s_udp,unitK8s_udp,jitterK8s,jitterK8s_unit,lossDocker = processDocker_udp.stdout.decode("utf-8").split(' ')
    print(rateDocker_udp, unitDocker_udp,jitterDocker,jitterDocker_unit,lossDocker)
    outfileDocker = open(outfileDocker_udp, 'w')
    outfileDocker.write(rateDocker_udp + ' ' + unitDocker_udp + ' ' + jitterDocker + ' ' + jitterDocker_unit + ' ' + lossDocker)

    barlist_jitter = axarr[0,1].bar([1,2], [float(jitterVm),float(jitterDocker)], align='center')
    axarr[0,1].set_xticks([1,2])
    axarr[0,1].set_xticklabels(['vm','docker'])
    axarr[0,1].set_ylabel(jitterVm_unit)
    axarr[0,1].set_title('UDP Jitter')
    barlist_jitter[0].set_color('blue')
    barlist_jitter[1].set_color('red')
    axarr[0,1].set_ylim([0,1])

    axarr[0,1].text(barlist_jitter[0].get_x() + barlist_jitter[0].get_width()/2, 1.05*barlist_jitter[0].get_height(), jitterVm, ha='center', va='bottom')
    axarr[0,1].text(barlist_jitter[1].get_x() + barlist_jitter[1].get_width()/2, 1.05*barlist_jitter[1].get_height(), jitterDocker, ha='center', va='bottom')

    lossVm_percent = int(lossVm.split('/')[0])/int(lossVm.split('/')[1])
    lossDocker_percent = int(lossDocker.split('/')[0])/int(lossDocker.split('/')[1])
    barlist_loss = axarr[1,0].bar([1,2], [lossVm_percent,lossDocker_percent], align='center')
    axarr[1,0].set_xticks([1,2])
    axarr[1,0].set_xticklabels(['vm','docker'])
    axarr[1,0].set_ylabel('%')
    axarr[1,0].set_title('UDP Loss %')
    barlist_loss[0].set_color('blue')
    barlist_loss[1].set_color('red')
    axarr[1,0].set_ylim([0,100])

    axarr[1,0].text(barlist_loss[0].get_x() + barlist_loss[0].get_width()/2, 1.05*barlist_loss[0].get_height(), lossVm_percent, ha='center', va='bottom')
    axarr[1,0].text(barlist_loss[1].get_x() + barlist_loss[1].get_width()/2, 1.05*barlist_loss[1].get_height(), lossDocker_percent, ha='center', va='bottom')
 
#xar_docker, yar_docker = draw_ping(processDocker, outfileDocker)
#docker_plot = plt.plot(xar_docker,yar_docker, color='red', label='docker')
#mean_docker = np.mean(yar_docker, axis=0)
#plt.axhline(y=mean_docker, color='red')

#plt.legend(handles=[vm_plot[0], docker_plot[0]])

#run_tcp()
#run_udp(cmd=iperfcmdK8s, outfile_name=outfileK8s_udp)

if args.latency:
    xar_ping_vm, yar_ping_vm = run_ping(cmd=pingcmdVm, outfile_name = outfileVm_ping, logfile_name = logfileVm_ping)
    xar_ping_docker, yar_ping_docker = run_ping(cmd=pingcmdDocker, outfile_name = outfileDocker_ping, logfile_name = logfileDocker_ping)
    xar_ping_k8s, yar_ping_k8s = run_ping(cmd=pingcmdK8s, outfile_name = outfileK8s_ping, logfile_name = logfileK8s_ping)
    graph_ping(xar_ping_vm, yar_ping_vm, xar_ping_docker, yar_ping_docker, xar_ping_k8s, yar_ping_k8s)

if args.tcp:
    rate_tcp_vm, unit_tcp_vm = run_tcp(cmd=iperfcmdVm_tcp, outfile_name=outfileVm_tcp, logfile_name=logfileVm_tcp)
    rate_tcp_docker, unit_tcp_docker = run_tcp(cmd=iperfcmdDocker_tcp, outfile_name=outfileDocker_tcp, logfile_name=logfileDocker_tcp)
    rate_tcp_k8s, unit_tcp_k8s = run_tcp(cmd=iperfcmdK8s_tcp, outfile_name=outfileK8s_tcp, logfile_name=logfileK8s_tcp)
    graph_tcp(rateVm=rate_tcp_vm, rateDocker=rate_tcp_docker, rateK8s=rate_tcp_k8s, unit=unit_tcp_vm)

if args.udp:
    rate_vm, jitter_vm, loss_vm = run_udp(cmd=iperfcmdVmUdp, outfile_name=outfileVm_udp, logfile_name=logfileVm_udp)
    rate_docker, jitter_docker, loss_docker = run_udp(cmd=iperfcmdDockerUdp, outfile_name=outfileDocker_udp, logfile_name=logfileDocker_udp)
    rate_k8s, jitter_k8s, loss_k8s = run_udp(cmd=iperfcmdK8sUdp, outfile_name=outfileK8s_udp, logfile_name=logfileK8s_udp)
    graph_udp(jitterVm=jitter_vm, jitterDocker=jitter_docker, jitterK8s=jitter_k8s, lossVm=loss_vm, lossDocker=loss_docker, lossK8s=loss_k8s)

#plt.suptitle(str(num_minutes) + ' minutes dutation')
plt.tight_layout()
plt.savefig(graphfile)

