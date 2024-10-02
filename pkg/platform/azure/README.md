## Azure Kubernetes Service

This platform supports AKS (Azure Kubernetes Service) as a platform.
It only supports kubernetes deployments.

To create a cloudlet for AKS, you will need:
- Your subscription ID
- Your tenant ID
- An existing resource group
- An existing service principal for authentication
- An AKS location, i.e. "westus"

The cloudlet will create AKS managed clusters in the specified
resource group and location.

### Creating a Service Principal

The service principal allows for scoped access to AKS APIs.
It should be scoped to the target resource group, and have the
"Reader" and "Azure Kubernetes Service Contributor" roles.
The following script will create/update a service prinicpal.
This script requires the az cli installed locally.
Reference: https://learn.microsoft.com/en-us/azure/aks/kubernetes-service-principal?tabs=azure-cli.

```bash
#!/bin/bash
servicePrincipalName="<sp-name>"
# Azure Kubernetes Service Contributor role: ed7f3fbd-7b88-4dd4-9017-9adb7ce333f8
roleName="ed7f3fbd-7b88-4dd4-9017-9adb7ce333f8"
subscriptionID=$(az account show --query id --output tsv)
# Verify the ID of the active subscription
echo "Using subscription ID $subscriptionID"
resourceGroup="<my-resource-group>"

echo "Creating SP for RBAC with name $servicePrincipalName, with role $roleName and in scopes /subscriptions/$subscriptionID/resourceGroups/$resourceGroup"
az ad sp create-for-rbac --name $servicePrincipalName --role $roleName --scopes /subscriptions/$subscriptionID/resourceGroups/$resourceGroup

# Also add ability to list vm flavors
# Reader role: acdd72a7-3385-48ef-bd42-f606fba81ae7
roleName="acdd72a7-3385-48ef-bd42-f606fba81ae7"
# get object id
id=`az ad sp list --display-name $servicePrincipalName | jq -r '.[].id'`
# add role
az role assignment create --assignee $id --role $roleName --scope /subscriptions/$subscriptionID/resourceGroups/$resourceGroup
```

The script will return the client ID and secret.

### Creating a Cloudlet

Create cloudlet must have the following parameters set:
- platform: azure
- accessvars:
   - AZURE_SUBSCRIPTION_ID
   - AZURE_TENANT_ID
   - AZURE_CLIENT_ID
   - AZURE_CLIENT_SECRET
   - AZURE_RESOURCE_GROUP
- envvar:
   - AZURE_LOCATION
