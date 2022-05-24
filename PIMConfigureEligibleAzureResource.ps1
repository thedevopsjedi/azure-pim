<#
    .SYNOPSIS
    This script will use Azure's REST APIs to configure an Azure Privileged Identity Management Policy for an Azure Resource Group and grant an Eligible Role Assignment to a specified Azure Role for a specified AAD User/Group.

    .DESCRIPTION
    This script will use Azure's REST APIs to configure an Azure Privileged Identity Management Policy for an Azure Resource Group and grant an Eligible Role Assignment to a specified Azure Role for a specified AAD User/Group.
    If an existing Eligible Role Assignment exists at the same Resource Group scope for the same roleNameToBeAssigned and memberObjectId it will be deleted, ensuring this script is idempotent.
    Finally it will then grant an Eligible Role Assignment to a specified roleNameToBeAssigned for a specified memberObjectId.

    .PARAMETER subscriptionName
    The Azure Subscription Name where the Resource Group resides.

    .PARAMETER resourceGroupName
    The Azure Resource Group Name where the role will be assigned.

    .PARAMETER roleNameToBeAssigned
    The name of the Azure Role to be assigned.

    .PARAMETER memberObjectId
    The Azure Active Directory Object ID of the User or Group to be assigned the role.

    .PARAMETER deleteAssignmentOnly
    A switch that tells the script to only delete existing matching role assignments. Required when deleting and re-creating the Azure Active Directory User or Group, as when re-created they receive a different Object ID.

    .PARAMETER exportFiles
    A switch that tells the script to export the JSON configuration before and after the changes so they can be compared. Designed for testing and auditing purposes not Azure DevOps pipelines.

    .INPUTS
    None. You cannot pipe objects to PIMConfigureEligibleAzureResource.ps1.

    .OUTPUTS
    None. PIMConfigureEligibleAzureResource.ps1 does not generate any output objects.

    .EXAMPLE
    PIMConfigureEligibleAzureResource.ps1 -subscriptionName {subscriptionName} -resourceGroupName {ResourceGroupName} -roleNameToBeAssigned "Storage Account Contributor" -memberObjectId {AADObjectID}

    .EXAMPLE
    PIMConfigureEligibleAzureResource.ps1 -subscriptionName {subscriptionName} -resourceGroupName {ResourceGroupName} -roleNameToBeAssigned "Storage Account Contributor" -memberObjectId {AADObjectID} -deleteAssignmentOnly

    .EXAMPLE
    PIMConfigureEligibleAzureResource.ps1 -subscriptionName "My Company Subscription" -resourceGroupName "my-resource-group" -roleNameToBeAssigned "Storage Account Contributor" -memberObjectId "a111bb22-cccc-3333-44d5-e66f777gg9h0"

    .EXAMPLE
    PIMConfigureEligibleAzureResource.ps1 -subscriptionName {subscriptionName} -resourceGroupName {ResourceGroupName} -roleNameToBeAssigned "Storage Account Contributor" -memberObjectId {AADObjectID} -exportFiles

    .LINK
    https://github.com/thedevopsjedi/azure-pim

    .NOTES
        Author: Darren Johnson
        Last Edit: 21-05-2022
        Version 1.0 - Initial Release
#>

[CmdletBinding()]
Param(
    [Parameter(Mandatory = $true)]
    [ValidateLength(1, 64)]
    [string] $subscriptionName = $null,

    [Parameter(Mandatory = $true)]
    [ValidateLength(1, 64)]
    [string] $resourceGroupName = $null,

    [Parameter(Mandatory = $true)]
    [ValidateLength(1, 90)]
    [string] $roleNameToBeAssigned = $null,

    [Parameter(Mandatory = $true)]
    [ValidateLength(36,36)]
    [string] $memberObjectId = $null,
    
    [switch] $deleteAssignmentOnly,

    [switch] $exportFiles
)

# Configure Email Notification Recipients Array (Addresses In Double Quotes & Separated By A Comma)
$notificationRecipients = "shared.mailbox@companydomain.co.uk"

# Configure The Role Eligibility Justification Message That Will Be Sent On All Alert Emails
$roleEligibilityJustificationMessage = "Company Standard Assigned By PowerShell"

# Get The Subscription Id
$subscriptionId = (Get-AzSubscription -SubscriptionName $subscriptionName).Id

# Get The Id Of The Role To Be Assigned
$roleIdToBeAssigned = (Get-AzRoleDefinition -Name $roleNameToBeAssigned).Id

# Build The Role Assignment Scope Used In The Different API URIs
$roleAssignmentScope = "subscriptions/$subscriptionId/resourcegroups/$resourceGroupName"

# Build The PIM Role Definition Id Used In The Role Eligibility Schedule Request Body
$pimRoleDefinitionId = "/subscriptions/$subscriptionId/providers/Microsoft.Authorization/roleDefinitions/$roleIdToBeAssigned"

# Set The API Version So It Is Consistent Within The Script
$apiVersion = "2020-10-01"

# Get The Access Token Required As A Header For Authentication
$accessToken = (Get-AzAccessToken -Resource 'https://management.azure.com').Token

# Set The Request Headers To Be Used For All API Operations
$headers = @{ 
    'Content-Type' = 'application/json'
    'Authorization' = 'Bearer ' + $accessToken
}

############### Query Role Management Policy Starts ###############
    # Query The Role Management Policy For The Specified Azure Resource And Role To Get Its Unique Name And Export The Policy Before Any Changes Are Made
    # Requires Microsoft.Authorization/roleAssignments/read Permissions At The Specified Scope
    # https://docs.microsoft.com/en-us/rest/api/authorization/privileged-role-policy-rest-sample#list-role-management-policies-for-a-resource
    # GET https://management.azure.com/{scope}/providers/Microsoft.Authorization/roleManagementPolicies?api-version=2020-10-01&$filter={filter}

    # Build The List Role Management Policy URI
    $roleDefinitionIdFilter = "roleDefinitionId%20eq%20`'$roleAssignmentScope/providers/Microsoft.Authorization/roleDefinitions/$roleIdToBeAssigned`'"
    $listResourceRoleManagementPolicyUri = "https://management.azure.com/$roleAssignmentScope/providers/Microsoft.Authorization/roleManagementPolicies?api-version=$apiVersion&`$filter=$roleDefinitionIdFilter"

    # Invoke The Query Request
    $queryResourceRoleManagementPolicy = Invoke-RestMethod -Method 'Get' -Uri $listResourceRoleManagementPolicyUri -Headers $headers

    # Retrieve The Unique Role Management Policy Name
    $roleManagementPolicyId = $queryResourceRoleManagementPolicy.value.name

    # Export Current Configuration As A Json File
    If ($exportFiles -eq $true) {
        # Set Role Management Policy Output Before Change File Name
        $outputRoleManagementPolicyFileNameBeforeChange = $roleNameToBeAssigned.Replace(" ","-") + "-roleManagementPoliciesBefore.json"

        # If The Output File Already Exists Delete It
        If(Test-Path $outputRoleManagementPolicyFileNameBeforeChange) {
            Write-Host "Deleting Existing Output File" $outputRoleManagementPolicyFileNameBeforeChange`n
            Remove-Item -Path $outputRoleManagementPolicyFileNameBeforeChange -Force
            }
        
        # Output The Role Management Policy Output Before Change File
        $queryResourceRoleManagementPolicy | ConvertTo-Json -Depth 100 | Out-File $outputRoleManagementPolicyFileNameBeforeChange
    }
################ Query Role Management Policy Ends ################

############### Update Role Management Policy Starts ###############
    # Update The Role Management Policy For The Specified Azure Resource And Role To Company Standards
    # Permissions Required Missing From The Documentation
    # https://docs.microsoft.com/en-us/rest/api/authorization/privileged-role-policy-rest-sample#update-a-role-management-policy
    # PATCH https://management.azure.com/{scope}/providers/Microsoft.Authorization/roleManagementPolicies/{roleManagementPolicyId}?api-version=2020-10-01

    # Configure Activation Rules
    $activationRules = @(
        # Configure Activation - Activation Maximum Duration (Hours)
        @{
            isExpirationRequired = "false"
            maximumDuration = "PT8H" # Options Are From 1 Hour To 24 Hours With 30 Minute Intervals So For 23.5 Hours The Syntax Would Be "PT23H30M"
            id = "Expiration_EndUser_Assignment"
            ruleType = "RoleManagementPolicyExpirationRule"
            "target" = @{
                caller = "EndUser"
                operations = @(
                    "All"
                    )
                level = "Assignment"
            }
        }
        # Configure Activation - On Activation Require
        @{
            enabledRules = @(
                "MultiFactorAuthentication" # Azure MFA (Remove If Not Needed)
                "Justification" # Require Justification On Activation (Remove If Not Needed)
                # "Ticketing" # Require Ticket Information On Activation (Remove If Not Needed)
            )
            id = "Enablement_EndUser_Assignment"
            ruleType = "RoleManagementPolicyEnablementRule"
            "target" = @{
                caller = "EndUser"
                operations = @(
                    "All"
                    )
                level = "Assignment"
            }
        }
        # Configure Activation - Require Approval To Activate
        @{
            setting = @{
                isApprovalRequired = "false" # "true"
                isApprovalRequiredForExtension = "false"
                isRequestorJustificationRequired = "true"
                approvalMode = "SingleStage"
                approvalStages = @(
                    @{
                        approvalStageTimeOutInDays = "1"
                        isApproverJustificationRequired = "true"
                        escalationTimeInMinutes = "0"
                        primaryApprovers = @(
                            # @{
                            #     id = "Group Or User AAD ObjectId"
                            #     description = "Approval Group Or User Display Name" # This Is The Display Name Of The Approver Which Appears In Lowercase Text In The Portal When Using The API - When Configuring Via The Portal it Correctly Resolves To The AAD Display Name & UPN
                            #     isBackup = "false"
                            #     userType = "Group" # "User"
                            # }
                        )
                        isEscalationEnabled = "false"
                    }
                )
            }
            id = "Approval_EndUser_Assignment"
            ruleType = "RoleManagementPolicyApprovalRule"
            "target" = @{
                caller = "EndUser"
                operations = @(
                    "All"
                    )
                level = "Assignment"
            }
        }
    )

    # Configure Assignment Rules
    $assignmentRules = @(
        # Configure Assignment - Allow Permanent Eligible Assignment
        @{
            isExpirationRequired = "false" # "true"
            maximumDuration = "P365D" # "P180D", "P90D", "P30D", "P15D" - Expire Eligible Assignments After - Not Required When Enabling 'Allow Permanent Eligible Assignment' But Left In To Mirror The Portal Behaviour
            id = "Expiration_Admin_Eligibility"
            ruleType = "RoleManagementPolicyExpirationRule"
            "target" = @{
                caller = "Admin"
                operations = @(
                    "All"
                    )
                level = "Eligibility"
            }
        }
        # Configure Assignment - Allow Permanent Active Assignment
        @{
            isExpirationRequired = "false" # "true"
            maximumDuration = "P180D" # "P365D", "P90D", "P30D", "P15D" - Expire Active Assignments After - Not Required When Enabling 'Allow Permanent Active Assignment' But Left In To Mirror The Portal Behaviour
            id = "Expiration_Admin_Assignment"
            ruleType = "RoleManagementPolicyExpirationRule"
            "target" = @{
                caller = "Admin"
                operations = @(
                    "All"
                    )
                level = "Assignment"
            }
        }
        # Configure Assignment - Require Azure Multi-Factor Authentication On Active Assignment & Require Justification On Active Assignment
        @{
            enabledRules = @(
                "MultiFactorAuthentication" # Require Azure Multi-Factor Authentication On Active Assignment (Remove If Not Needed)
                "Justification" # Require Justification On Active Assignment (Remove If Not Needed)
            )
            id = "Enablement_Admin_Assignment"
            ruleType = "RoleManagementPolicyEnablementRule"
            "target" = @{
                caller = "Admin"
                operations = @(
                    "All"
                    )
                level = "Assignment"
            }
        }
    )

    # Configure Notification Rules
    $notificationRules = @(
        # Configure Notification - Send Notifications When Members Are Assigned As Eligible To This Role - Admin
        @{
            notificationType = "Email"
            recipientType = "Admin"
            isDefaultRecipientsEnabled = "true" # "false"
            notificationLevel = "All" # "Critical"
            notificationRecipients = @(
                $notificationRecipients
            )
            id = "Notification_Admin_Admin_Eligibility"
            ruleType = "RoleManagementPolicyNotificationRule"
            "target" = @{
                caller = "Admin"
                operations = @(
                    "All"
                    )
                level = "Eligibility"
            }
        }
        # Configure Notification - Send Notifications When Members Are Assigned As Eligible To This Role - Assignee
        @{
            notificationType = "Email"
            recipientType = "Requestor"
            isDefaultRecipientsEnabled = "true" # "false"
            notificationLevel = "All" # "Critical"
            notificationRecipients = @(
                $notificationRecipients
            )
            id = "Notification_Requestor_Admin_Eligibility"
            ruleType = "RoleManagementPolicyNotificationRule"
            "target" = @{
                caller = "Admin"
                operations = @(
                    "All"
                    )
                level = "Eligibility"
            }
        }
        # Configure Notification - Send Notifications When Members Are Assigned As Eligible To This Role - Approver
        @{
            notificationType = "Email"
            recipientType = "Approver"
            isDefaultRecipientsEnabled = "true" # "false"
            notificationLevel = "All" # "Critical"
            notificationRecipients = @(
                $notificationRecipients
            )
            id = "Notification_Approver_Admin_Eligibility"
            ruleType = "RoleManagementPolicyNotificationRule"
            "target" = @{
                caller = "Admin"
                operations = @(
                    "All"
                    )
                level = "Eligibility"
            }
        }
        # Configure Notification - Send Notifications When Members Are Assigned As Active To This Role - Admin
        @{
            notificationType = "Email"
            recipientType = "Admin"
            isDefaultRecipientsEnabled = "true" # "false"
            notificationLevel = "All" # "Critical"
            notificationRecipients = @(
                $notificationRecipients
            )
            id = "Notification_Admin_Admin_Assignment"
            ruleType = "RoleManagementPolicyNotificationRule"
            "target" = @{
                caller = "Admin"
                operations = @(
                    "All"
                    )
                level = "Assignment"
            }
        }
        # Configure Notification - Send Notifications When Members Are Assigned As Active To This Role - Assignee
        @{
            notificationType = "Email"
            recipientType = "Requestor"
            isDefaultRecipientsEnabled = "true" # "false"
            notificationLevel = "All" # "Critical"
            notificationRecipients = @(
                $notificationRecipients
            )
            id = "Notification_Requestor_Admin_Assignment"
            ruleType = "RoleManagementPolicyNotificationRule"
            "target" = @{
                caller = "Admin"
                operations = @(
                    "All"
                    )
                level = "Assignment"
            }
        }
        # Configure Notification - Send Notifications When Members Are Assigned As Active To This Role - Approver
        @{
            notificationType = "Email"
            recipientType = "Approver"
            isDefaultRecipientsEnabled = "true" # "false"
            notificationLevel = "All" # "Critical"
            notificationRecipients = @(
                $notificationRecipients
            )
            id = "Notification_Approver_Admin_Assignment"
            ruleType = "RoleManagementPolicyNotificationRule"
            "target" = @{
                caller = "Admin"
                operations = @(
                    "All"
                    )
                level = "Assignment"
            }
        }
        # Configure Notification - Send Notifications When Eligible Members Activate This Role - Admin
        @{
            notificationType = "Email"
            recipientType = "Admin"
            isDefaultRecipientsEnabled = "true" # "false"
            notificationLevel = "All" # "Critical"
            notificationRecipients = @(
                $notificationRecipients
            )
            id = "Notification_Admin_EndUser_Assignment"
            ruleType = "RoleManagementPolicyNotificationRule"
            "target" = @{
                caller = "EndUser"
                operations = @(
                    "All"
                    )
                level = "Assignment"
            }
        }
        # Configure Notification - Send Notifications When Eligible Members Activate This Role - Requestor
        @{
            notificationType = "Email"
            recipientType = "Requestor"
            isDefaultRecipientsEnabled = "true" # "false"
            notificationLevel = "All" # "Critical"
            notificationRecipients = @(
                $notificationRecipients
            )
            id = "Notification_Requestor_EndUser_Assignment"
            ruleType = "RoleManagementPolicyNotificationRule"
            "target" = @{
                caller = "EndUser"
                operations = @(
                    "All"
                    )
                level = "Assignment"
            }
        }
        # Configure Notification - Send Notifications When Eligible Members Activate This Role - Approver
        @{
            notificationType = "Email"
            recipientType = "Approver"
            isDefaultRecipientsEnabled = "true" # Removing Approver As The Default Recipient Means That All Approvers Will Stop Getting Email Notifications Asking Them To Approve Each Request
            notificationLevel = "All" # "Critical"
            # notificationRecipients = @() # This Is Left Intentionally Blank To Mirror The Portal Behaviour As It Is Not Ever Populated
            id = "Notification_Approver_EndUser_Assignment"
            ruleType = "RoleManagementPolicyNotificationRule"
            "target" = @{
                caller = "EndUser"
                operations = @(
                    "All"
                    )
                level = "Assignment"
            }
        }
    )

    # Create The Update Request Body - All The Default Options Below Need To Be Included In The Request To Ensure The Backend Is Populated Correctly Otherwise You May Get Errors When Modifying Via The Portal In Future
    $updateRequestBody = @{
        properties = @{
            rules = @(
                $activationRules
                $assignmentRules
                $notificationRules
            )
        }
    } | ConvertTo-Json -Depth 100

    # Build The Role Management Policy Update URI
    $updateResourceRoleManagementPolicyUri = "https://management.azure.com/$roleAssignmentScope/providers/Microsoft.Authorization/roleManagementPolicies/$roleManagementPolicyId`?api-version=$apiVersion"

    # Invoke The Update Role Management Policy Request
    Write-Host "Updating" $roleNameToBeAssigned "Role Management Policy At Scope /$roleAssignmentScope`n"
    $roleManagementPolicyUpdate = Invoke-RestMethod -Method 'Patch' -Uri $updateResourceRoleManagementPolicyUri -Headers $headers -Body $updateRequestBody

    # Export Current Configuration As A Json File
    If ($exportFiles -eq $true) {
        # Set Role Management Policy Output After Change File Name
        $outputRoleManagementPolicyFileNameAfterChange = $roleNameToBeAssigned.Replace(" ","-") + "-roleManagementPoliciesAfter.json"

        # If The Output File Already Exists Delete It
        If(Test-Path $outputRoleManagementPolicyFileNameAfterChange) {
            Write-Host "Deleting Existing Output File" $outputRoleManagementPolicyFileNameAfterChange`n
            Remove-Item -Path $outputRoleManagementPolicyFileNameAfterChange -Force
            }

        # Output The Role Management Policy Output After Change File
        $queryResourceRoleManagementPolicy = Invoke-RestMethod -Method 'Get' -Uri $listResourceRoleManagementPolicyUri -Headers $headers
        $queryResourceRoleManagementPolicy | ConvertTo-Json -Depth 100 | Out-File $outputRoleManagementPolicyFileNameAfterChange
    }
################ Update Role Management Policy Ends ################

############### List Existing Eligible Role Assignments Starts ###############
    # List Eligible Role Assignments To See If One Already Exists At The Resource Scope
    # Requires Microsoft.Authorization/roleAssignments/read Permissions At The Specified Scope
    # https://docs.microsoft.com/en-us/rest/api/authorization/privileged-role-eligibility-rest-sample#list-eligible-assignments
    # GET https://management.azure.com/{scope}/providers/Microsoft.Authorization/roleEligibilityScheduleInstances?api-version=2020-10-01&$filter={filter}

    # Build The List Eligible Role Assignments URI
    $listEligibleRoleAssignmentsUri = "https://management.azure.com/$roleAssignmentScope/providers/Microsoft.Authorization/roleEligibilityScheduleInstances`?api-version=$apiVersion&`$filter=principalId%20eq%20`'$memberObjectId`'+and+roleDefinitionId%20eq%20`'$pimRoleDefinitionId`'"

    # Invoke The List Eligible Role Assignments Request
    $listEligibleRoleAssignments = Invoke-RestMethod -Method 'Get' -Uri $listEligibleRoleAssignmentsUri -Headers $headers

    # Export Current Configuration As A Json File
    If ($exportFiles -eq $true) {
        # Set Eligible Role Assignments Output Before Change File Name
        $outputEligibleRoleAssignmentsFileNameBeforeChange = $resourceGroupName + "-EligibleRoleAssignmentsBefore.json"

        # If The Output File Already Exists Delete It
        If(Test-Path $outputEligibleRoleAssignmentsFileNameBeforeChange) {
            Write-Host "Deleting Existing Output File" $outputEligibleRoleAssignmentsFileNameBeforeChange`n
            Remove-Item -Path $outputEligibleRoleAssignmentsFileNameBeforeChange -Force
            }

        # Output The Eligible Role Assignments Output Before Change File
        $listEligibleRoleAssignments | ConvertTo-Json -Depth 100 | Out-File $outputEligibleRoleAssignmentsFileNameBeforeChange
    }
################ List Existing Eligible Role Assignments Ends ################

############### Remove Existing Eligible Role Assignment If It Exists So Code Is Idempotent Starts ###############
    # Check If There Is An Existing Role Assignment For The memberObjectId
    If($listEligibleRoleAssignments.value.Count -gt 0){

        # Ensure Only The Existing Eligible Role Assignments At The Resource Scope Are Targeted For Deletion
        ForEach($eligibleRoleAssignment in ($listEligibleRoleAssignments).value.properties) {
            If(($eligibleRoleAssignment.scope.TrimStart("/") -eq $roleAssignmentScope) -and ($eligibleRoleAssignment.principalId -eq $memberObjectId) -and ($eligibleRoleAssignment.expandedProperties.roleDefinition.id -eq $pimRoleDefinitionId)) {
                Write-Host "Deleting Existing" $eligibleRoleAssignment.expandedProperties.roleDefinition.displayName "Role Eligibility For" $eligibleRoleAssignment.expandedProperties.principal.displayName "At Scope" $eligibleRoleAssignment.scope`n

                # Remove Existing Eligible Role Assignment If It Exists So Code Is Idempotent
                # Requires Microsoft.Authorization/roleAssignments/Write Permissions
                # https://docs.microsoft.com/en-us/rest/api/authorization/privileged-role-eligibility-rest-sample#remove-eligible-assignment
                # PUT https://management.azure.com/{scope}/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/{roleEligibilityScheduleRequestName}?api-version=2020-10-01

                # Generate A Unique GUID To Be Used As The Role Eligibility Delete Schedule Request Name
                $roleEligibilityDeleteScheduleRequestName = (New-Guid).Guid

                # Build The Role Eligibility Delete Schedule Request URI
                $roleEligibilityDeleteScheduleRequestUri = "https://management.azure.com/providers/Microsoft.Subscription/$roleAssignmentScope/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/$roleEligibilityDeleteScheduleRequestName`?api-version=$apiVersion"

                # Create The Role Eligibility Schedule Request Body
                $roleEligibilityDeleteScheduleRequestBody = @{
                    properties = @{
                        principalId = $memberObjectId
                        requestType = "AdminRemove"
                        roleDefinitionId = $pimRoleDefinitionId
                    }
                } | ConvertTo-Json -Depth 100

                # Invoke The Delete Existing Eligible Role Assignment Request
                Invoke-RestMethod -Method 'Put' -Uri $roleEligibilityDeleteScheduleRequestUri -Headers $headers -Body $roleEligibilityDeleteScheduleRequestBody | ConvertTo-Json -Depth 100

                # Output Blank Line To Separate Log Sections
                Write-Host ""
            }
        }
    }
################ Remove Existing Eligible Role Assignment If It Exists So Code Is Idempotent Ends ################

############### Grant The Eligible Role Assignment Starts ###############
    # Do Not Grant The Eligible Role Assignment If The 'deleteAssignmentOnly' Switch Is In Use
    If ($deleteAssignmentOnly -eq $false) {
        
        # Grant The Eligible Role Assignment
        # Requires Microsoft.Authorization/roleAssignments/Write Permissions
        # https://docs.microsoft.com/en-us/rest/api/authorization/privileged-role-eligibility-rest-sample#grant-eligible-assignment
        # PUT https://management.azure.com/{scope}/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/{roleEligibilityScheduleRequestName}?api-version=2020-10-01

        # Generate A Unique GUID To Be Used As The Role Eligibility Schedule Request Name
        $roleEligibilityGrantScheduleRequestName = (New-Guid).Guid

        # Build The Role Eligibility Schedule Request URI
        $roleEligibilityScheduleRequestUri = "https://management.azure.com/providers/Microsoft.Subscription/$roleAssignmentScope/providers/Microsoft.Authorization/roleEligibilityScheduleRequests/$roleEligibilityGrantScheduleRequestName`?api-version=$apiVersion"

        # Create The Role Eligibility Schedule Request Body
        $roleEligibilityScheduleRequestBody = @{
            properties = @{
                principalId = $memberObjectId
                requestType = "AdminAssign"
                roleDefinitionId = $pimRoleDefinitionId
                justification = $roleEligibilityJustificationMessage
                scheduleInfo = @{
                    expiration = @{
                        type = "NoExpiration"
                    }
                }
            }
        } | ConvertTo-Json -Depth 100

        Write-Host "Granting Eligible Role Assignment At Scope /$roleAssignmentScope`n"

        # Invoke The Grant Eligible Role Assignment Request
        Invoke-RestMethod -Method 'Put' -Uri $roleEligibilityScheduleRequestUri -Headers $headers -Body $roleEligibilityScheduleRequestBody | ConvertTo-Json -Depth 100

        # Export Current Configuration As A Json File
        If ($exportFiles -eq $true) {
            # Set Eligible Role Assignments Output After Change File Name
            $outputEligibleRoleAssignmentsFileNameAfterChange = $resourceGroupName + "-EligibleRoleAssignmentsAfter.json"

            # If The Output File Already Exists Rename It With A Prefix Of Todays Date In DD-MM-YYYY Format
            If(Test-Path $outputEligibleRoleAssignmentsFileNameAfterChange) {
                Write-Host "`nDeleting Existing Output File" $outputEligibleRoleAssignmentsFileNameAfterChange`n
                Remove-Item -Path $outputEligibleRoleAssignmentsFileNameAfterChange -Force
                }

            # Invoke The Query Request
            $queryResourceRoleManagementPolicy = Invoke-RestMethod -Method 'Get' -Uri $listResourceRoleManagementPolicyUri -Headers $headers
            
            # Output The Eligible Role Assignments Output After Change File
            $listEligibleRoleAssignments | ConvertTo-Json -Depth 100 | Out-File $outputEligibleRoleAssignmentsFileNameAfterChange
        }
    }
################ Grant The Eligible Role Assignment Ends ################