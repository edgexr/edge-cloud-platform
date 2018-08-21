TLS certs can be generated here with certstrap.

Both client and server certs must be signed by the private Certificate Authority mex-ca.crt

Generating CA File:
$ certstrap  init --common-name mex-ca
Enter passphrase (empty for no passphrase): 
<leave blank>
Enter same passphrase again: 
<leave blank>
Created out/mex-ca.key
Created out/mex-ca.crt
Created out/mex-ca.crl

The CA file can be re-used for every deployment.  It is included for every server and client.

Generating Server Certs:

Domain based, can be wildcard or FQDN:
$ certstrap request-cert --domain dme.xyz.mobiledgex.net
Enter passphrase (empty for no passphrase): 
<leave blank>
Enter same passphrase again: 
<leave blank>

Created out/dme.xyz.mobiledgex.net.key
Created out/dme.xyz.mobiledgex.net.csr

$ certstrap sign --CA mex-ca dme.xyz.mobiledgex.net
$ certstrap sign --CA mex-ca dme.xyx.mobiledgex.net

Created out/dme.xyz.mobiledgex.net.crt from out/dme.xyx.mobiledgex.net.csr signed by out/mex-ca.key

The DME can now be run with --tls ./out/dme.xyz.mobiledgex.net.crt

IP address based:
$ certstrap request-cert --ip 127.0.0.1
Enter passphrase (empty for no passphrase): 
<leave blank>
Enter same passphrase again: 
<leave blank>
Created out/127.0.0.1.key
Created out/127.0.0.1.csr

$ certstrap sign --CA mex-ca 127.0.0.1

The DME can now be run with --tls ./out/127.0.0.1.crt


Server certs must be generated for every IP or domain through which clients will access.

Generating Client Certs:

Client certs can be shared for all clients.

$ certstrap request-cert --domain mex-client

Enter passphrase (empty for no passphrase): 
<leave blank>
Enter same passphrase again: 
<leave blank>

Created out/mex-client.key
Created out/mex-client.csr

$ certstrap sign --CA mex-ca mex-client
Created out/mex-client.crt from out/mex-client.csr signed by out/mex-ca.key 


Running DME example:
dme-server   --tls ./out/dme.xyz.mobiledgex.net.crt
2018-08-19T22:09:57.386-0500    INFO    dme-server/dme-notify.go:36     notify client to        {"addrs": "127.0.0.1:50001"}
Loading certfile ./out/dme.xyz.mobiledgex.net.crt cafile out/mex-ca.crt keyfile ./out/dme.xyz.mobiledgex.net.key

Running edgectl client example:
$ edgectl --addr  dme.xyz.mobiledgex.net:50051 dme RegisterClient --tls ./out/mex-client.crt                        
using TLS credentials server dme.xyz.mobiledgex.net certfile ./out/mex-client.crt keyFile ./out/mex-client.key
status: ME_SUCCESS
sessioncookie: "***"

