# edge-cloud-infra
This is the code for provisioning a VM based tenant in cloudlet. 
1) Deploy a VM based application with a specified VLAN, public-IP, cpu, memory, etc
	(maybe based on couple of predefined templates like vm-lite, vm-med, vm-hi)
2) Deploy a VM based application that requires a pool of VM fronted by a LB hosting a public IP
3) Deploy a set of VM capable of taking a K8s cluster on per developer basis. The CRM
	specifies the intent (i.e. for k8s cluster), VLAN, public IP, CPU/Mem/Storage resources
	and the cloudlet-manager does it

