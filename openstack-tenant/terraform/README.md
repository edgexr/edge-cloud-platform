# terraform example on openstack

Create VM instance(s) on openstack via terraform.

Download openrc file from openstack.  Make sure to unset some existing environment variables and source openrc.

```
export OS_TENANT_ID=
export OS_DOMAIN_ID=
. openrc
```

Then find out the external_gatway UUID from Openstack (in the shell of the machine capable of running openstack CLI):

```
openstack network list
+--------------------------------------+---------+----------------------------------------------------------------------------+
| ID                                   | Name    | Subnets                                                                    |
+--------------------------------------+---------+----------------------------------------------------------------------------+
| 3157d3c6-c68d-417b-8856-61ae89e2b34a | public  | 50b795e7-84e7-4fe5-ad9a-5a09ead7db22, e478ea98-bf12-45f5-a6c1-eeeee33fc5c3 |
| 3e5a287d-ea96-4b90-b86a-fc3cff5db8c7 | private | 4fd2f01f-1a29-448d-ace2-7376d6a7a96a, 87cad4f9-933e-4f32-b65d-ce35953b1a32 |
+--------------------------------------+---------+----------------------------------------------------------------------------+
```
Pick network ID and use as external_gateway variable for terraform. In the shell of the machine running terraform:

```
$ terraform plan -var external_gateway=3157d3c6-c68d-417b-8856-61ae89e2b34a
```

Then, if everything looks good,

```
$ terraform apply -var external_gateway=3157d3c6-c68d-417b-8856-61ae89e2b34a
```

you will be prompted, answer yes.
