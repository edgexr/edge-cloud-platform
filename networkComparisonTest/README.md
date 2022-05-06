This contains the tools and data to run network tests for latency, iperf udp, and iperf tcp.
This was used to compare normal process, docker, and kubernetes network performance.

It will generate log files and graphs.

This main directory contains pngs of graphs for 1 minute, 5 minutes, 10 minutes, and 30 minutes of data collection.
Also contains a network diagram and network configuration info.

The data directory contains the data and log files for each run.
The scripts directory contains scripts that were used.
The configFiles directory contains docker and kubernetes config files.

python3 iperf_save_vmdockerk8s.py -h
usage: iperf_save_vmdockerk8s.py [-h] [--latency] [--udp] [--tcp]
                                 [--minutes MINUTES]

collect network data

optional arguments:
  -h, --help         show this help message and exit
  --latency          collect latency data
  --udp              collect udp data
  --tcp              collect tcp data
  --minutes MINUTES  number of minutes to run. default=1min

to run all tests for ten minutes:
./iperf_save_vmdockerk8s.py --latency --tcp --udp --minutes 10

or give --latency or --tcp or --udp flag to just run that test(s)

Must install python3

Must install these python modules:
pip3 install numpy
pip3 install matplotlib