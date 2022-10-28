# Configuring Privileged Identity Management in Azure

This repository contains a script to configure Privileged Identity Management (PIM) in Azure.

## Background

I was recently asked to automate the onboarding of Azure Resource Groups to PIM via Azure DevOps.  This involved configuring the role management policy, and assigning the role as eligible to a group.

After looking into this, there wasn't an easy way to do it as terraform does not yet support PIM, and neither does Azure PowerShell or the AZ CLI.  This meant I had use the API.

The API wasn't fully documented, and after working through the different options available I decided to capture them all in the comments so if I needed to revisit this in the future everything would be ready to go.

## Running The Script

Running the script is fairly simple, you just need to authenicate via the `Connect-AzAccount` cmdlet the run the command below:

```powershell
PIMConfigureEligibleAzureResource.ps1 -subscriptionName {subscriptionName} -resourceGroupName {ResourceGroupName} -roleNameToBeAssigned {azureRoleName} -memberObjectId {AADObjectID} -deleteAssignmentOnly -exportFiles
```

The `deleteAssignmentOnly` switch is used when you want to destroy the resource group to ensure the role assignment is removed before the resource group is deleted.

The `exportFiles ` switch is only used when running the script locally and you want to output the json configuration before and after the changes.
