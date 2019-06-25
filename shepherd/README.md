# Shepherd service 

`Shepherd` service collects prometheus metrics on a cluster and writes them into an influxDB.

The service collects cluster-wide as well as per-pod metrics. Service will create database `clusterstats` in the influxDB if one doesn't exist.
Cluster metrics are collected and stored in `crm-cluster` measurement in `clusterstats` database. It includes the following metrics:
   - `cpu` - cluster CPU utilization percentage
   - `mem` - cluster memory utilization percentage
   - `disk` - cluster filesystem utilization percentage
   - `sendBytes` - cluster tx traffic rate averaged over 1 minute
   - `recvBytes` - cluster rx traffic rate averaged over 1 minute
   - `tcpConns` - total number of established TCP connections on this cluster
   - `tcpRetrans` - total number of TCP retransmissions on this cluster
   - `udpRecv` - total number of rx UDP datagrams on this cluster
   - `udpSend` - total number of tx UDP datagrams on this cluster
   - `udpRecvErr` - tatal number of UDP errors received on this cluster
In addition to the above values `cluster` tag is added to each measurement with the name of a cluster.
Per-pod metrics are collected and stored in `crm-appinst` measurement in `clusterstats` database. The following metrics are collected:
   - `cpu` - CPU utilization of this pod as a percentage of total available CPU
   - `mem` - current memory footprint of a given pod in bytes
   - `disk` - filesystem usage for a given pod
   - `sendBytes` - tx traffic rate averaged over 1 minute for a given pod
   - `recvBytes` - rx traffic rate averaged over 1 minute for a given pod
In addition to the above values `cluster`, `dev`, and `app` tags are added to the measurement to uniquely identify a particular time series.

The collection of the above metrics happens every set interval by running queries against a prometheus running in a cluster. See Usage section for addition details of how to configure interval/influxDB address/Prometheus address.

## Usage

This service is meant to run as a process (similar to crm) that can be started locally with the following usage.

```
$ shepherd -h
Usage of shepherd:
  -cloudletKey string
    	Json or Yaml formatted cloudletKey for the cloudlet in which this CRM is instantiated; e.g. '{"operator_key":{"name":"DMUUS"},"name":"tmocloud1"}'
  -d string
    	comma separated list of [etcd api notify dmedb dmereq locapi mexos metrics upgrade]
  -influxdb string
    	InfluxDB address to export to (default "http://0.0.0.0:8086")
  -interval duration
    	Metrics collection interval (default 15s)
  -notifyAddrs string
    	CRM notify listener addresses (default "127.0.0.1:51001")
  -physicalName string
    	Physical infrastructure cloudlet name, defaults to cloudlet name in cloudletKey
  -platform string
    	Platform type of Cloudlet
  -tls string
    	server9 tls cert file.  Keyfile and CA file mex-ca.crt must be in same directory
  -vaultAddr string
    	Address to vault
```

## Docker Image

Currently not available, will be soon


## TODO

1. Need to find a better way to organize metrics being sent to influxdb. It is currently too rigid to provide configurable
metrics and adding in a new one later would be a hassle.
2. Register shepherd with the country controller to be able to send metrics through the notify framework so that controller writes to influxdb instead of shepherd.
3. Azure support
