#####################################################
# HelloID-SA-Sync-Exchange-Online-SharedMailbox-To-Products
#
# Version: 1.0.0.0
#####################################################
$VerbosePreference = 'SilentlyContinue'
$informationPreference = 'Continue'
$WarningPreference = 'Continue'

# Make sure to create the Global variables defined below in HelloID
#HelloID Connection Configuration
$portalApiKey = $portalApiKey
$portalApiSecret = $portalApiSecret
$script:BaseUrl = $portalBaseUrl


#Target Connection Configuration     # Needed for accessing the Target System (These variables are also required for the Actions of each product)
$ExchangeAdminUsername = $ExchangeAdminUsername
$ExchangeAdminPassword = $ExchangeAdminPassword
$Filter = "DisplayName -like 'SharedMailbox*'" # Optional, when no filter is provided ($Filter = $null), all mailboxes will be queried


#HelloID Product Configuration
$ProductAccessGroup = 'Users'           # If not found, the product is created without extra Access Group
$ProductCategory = 'Shared Mailboxes'   # If the category is not found, it will be created
$SAProductResourceOwner = ''            # If left empty the groupname will be: "Resource owners [target-systeem] - [Product_Naam]")
$SAProductWorkflow = $null              # If empty. The Default HelloID Workflow is used. If specified Workflow does not exist the Product creation will raise an error.
$FaIcon = 'inbox'
$removeProduct = $true                  # If False product will be disabled
$overwriteExistingProduct = $false       # If True existing product will be overwritten with the input from this script (e.g. the approval worklow or icon). Only use this when you actually changed the product input
$overwriteExistingProductAction = $false # If True existing product actions will be overwritten with the input from this script. Only use this when you actually changed the script or variables for the action(s)
$productVisibility = 'All'

#Target System Configuration
# Dynamic property invocation
$uniqueProperty = 'GUID'              # The vaule of the property will be used as CombinedUniqueId

# [ValidateLength(4)]
$SKUPrefix = 'EXOM'                   # The prefix will be used as CombinedUniqueId. Max. 4 characters
$TargetSystemName = 'Exchange SharedMailbox'

# [validateSet('SendAs', 'FullAccess', 'SendOnBehalf')]
$PermissionTypes = 'SendAs', 'FullAccess', 'SendOnBehalf'

$includeEmailAction = $true
$defaultFromAddress = "no-reply@helloid.com"
$defaultToAddress = "j.doe@eyoi.org"

#region HelloID
function Get-HIDDefaultAgentPool {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003036494-GET-Get-agent-pools
    #>
    [CmdletBinding()]
    param ()

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'GET'
            Uri    = 'agentpools'
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-HIDSelfServiceProduct {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003027353-GET-Get-products
    #>
    [CmdletBinding()]
    param ()

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'GET'
            Uri    = 'selfservice/products'
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-HIDSelfServiceProductAction {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003027353-GET-Get-products
    #>
    [CmdletBinding()]
    param ()

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'GET'
            Uri    = 'automationtasks'
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-HIDSelfServiceCategory {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003036194-GET-Get-self-service-categories
    #>
    [CmdletBinding()]
    param ()

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'GET'
            Uri    = 'selfservice/categories'
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Set-HIDSelfServiceProduct {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003038854-POST-Create-or-update-a-product
    #>
    [CmdletBinding()]
    param (
        $ProductJson
    )
    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Body   = $ProductJson
            Method = 'POST'
            uri    = 'selfservice/products'
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function New-HIDSelfServiceCategory {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003024773-POST-Create-self-service-category
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $Name,

        [string]
        $SelfServiceCategoryGUID,

        [bool]
        $IsEnabled
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $category = [ordered]@{
            "name"                    = $Name
            "SelfServiceCategoryGUID" = $SelfServiceCategoryGUID
            "isEnabled"               = $IsEnabled
        } | ConvertTo-Json

        $splatParams = @{
            Method = 'POST'
            Uri    = 'selfservice/categories'
            Body   = $category
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Remove-HIDSelfServiceProduct {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003038654-DELETE-Delete-product
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $ProductGUID
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'DELETE'
            Uri    = "selfservice/products/$ProductGUID"
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Add-HIDPowerShellAction {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/360013035680-POST-Create-or-update-PowerShell-task
    #>
    [CmdletBinding()]
    param(
        $body
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"

        $splatParams = @{
            Method = 'POST'
            Uri    = 'automationtasks/powershell'
            Body   = $body
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Add-HIDEmailAction {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003036854-POST-Create-e-mail-action
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $ProductGUID,

        [Parameter(Mandatory)]
        $body
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"

        $splatParams = @{
            Method = 'POST'
            Uri    = "selfservice/products/$($ProductGUID)/emailaction"
            Body   = $body
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Remove-HIDAction {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003037034-DELETE-Delete-action
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $ActionGUID
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"

        $splatParams = @{
            Method = 'DELETE'
            Uri    = "selfservice/actions/$ActionGUID"
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}


function New-HIDGroup {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115003038654-DELETE-Delete-product
    #>
    [Cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $GroupName,

        [bool]
        $isEnabled
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $groupBody = @{
            name      = "$GroupName Resource Owners"
            isEnabled = $isEnabled
            userNames = ''
        } | ConvertTo-Json

        $splatParams = @{
            Method = 'POST'
            Uri    = 'groups'
            Body   = $groupBody
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $Pscmdlet.ThrowTerminatingError($_)
    }
}


function Get-HIDGroup {
    <#
    .DESCRIPTION
       https://docs.helloid.com/hc/en-us/articles/115002981813-GET-Get-specific-group
    #>
    [Cmdletbinding()]
    param(
        [Parameter(Mandatory)]
        [string]
        $GroupName,

        [switch]
        $resourceGroup
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        if ($resourceGroup) {
            $groupname = "$GroupName Resource Owners"
        }
        $splatParams = @{
            Method = 'GET'
            Uri    = "groups/$groupname"
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        if ($_.ErrorDetails.Message -match 'Group not found') {
            return $null
        }
        $Pscmdlet.ThrowTerminatingError($_)
    }
}
function Add-HIDProductMember {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115002954633-POST-Link-member-to-group
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $selfServiceProductGUID,

        [Parameter(Mandatory)]
        [string]
        $MemberGUID
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'POST'
            Uri    = "selfserviceproducts/$selfServiceProductGUID/groups"
            Body   = @{
                groupGUID = $MemberGUID
            } | ConvertTo-Json
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $Pscmdlet.ThrowTerminatingError($_)
    }
}

function Add-HIDGroupMember {
    <#
    .DESCRIPTION
        https://docs.helloid.com/hc/en-us/articles/115002954633-POST-Link-member-to-group
    #>
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]
        $GroupGUID,

        [Parameter(Mandatory)]
        [string]
        $MemberGUID
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatParams = @{
            Method = 'POST'
            Uri    = "groups/$GroupGUID"
            Body   = @{
                UserGUID = $MemberGUID
            } | ConvertTo-Json
        }
        Invoke-HIDRestMethod @splatParams
    } catch {
        $Pscmdlet.ThrowTerminatingError($_)
    }
}

function Add-HIDUserGroup {
    <#
    .DESCRIPTION
    #>
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $UserName,

        [Parameter()]
        [String]
        $GroupName
    )

    try {
        Write-Verbose "Invoking command '$($MyInvocation.MyCommand)'"
        $splatRestParameters = @{
            Method = 'POST'
            Uri    = "users/$UserName/groups"
            Body   = @{
                name = $GroupName
            } | ConvertTo-Json
        }
        Invoke-HIDRestMethod @splatRestParameters
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}


function Invoke-HIDRestmethod {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Method,

        [Parameter(Mandatory)]
        [ValidateNotNullOrEmpty()]
        [string]
        $Uri,

        [object]
        $Body,

        [string]
        $ContentType = 'application/json'
    )

    try {
        Write-Verbose 'Switching to TLS 1.2'
        [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor [System.Net.SecurityProtocolType]::Tls12

        Write-Verbose 'Setting authorization headers'
        $apiKeySecret = "$($portalApiKey):$($portalApiSecret)"
        $base64 = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($apiKeySecret))
        $headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
        $headers.Add("Authorization", "Basic $base64")
        $headers.Add("Content-Type", $ContentType)

        $splatParams = @{
            Uri     = "$($script:BaseUrl)/api/v1/$Uri"
            Headers = $headers
            Method  = $Method
        }

        if ($Body) {
            Write-Verbose 'Adding body to request'
            $splatParams['Body'] = $Body
        }

        Write-Verbose "Invoking '$Method' request to '$Uri'"
        Invoke-RestMethod @splatParams
    } catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Write-HidStatus {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]
        $Message,

        [Parameter()]
        [String]
        $Event
    )
    if ([String]::IsNullOrEmpty($portalBaseUrl)) {
        Write-Information $Message
    } else {
        Hid-Write-Status -Message $Message -Event $Event
    }
}

function Write-HidSummary {
    [CmdletBinding()]
    param(
        [Parameter()]
        [string]
        $Message,

        [Parameter()]
        [String]
        $Event
    )

    if ([String]::IsNullOrEmpty($portalBaseUrl) -eq $true) {
        Write-Output ($Message)
    } else {
        Hid-Write-Summary -Message $Message -Event $Event
    }
}

function Compare-Join {
    [OutputType([array], [array], [array])]
    param(
        [parameter()]
        [string[]]$ReferenceObject,

        [parameter()]
        [string[]]$DifferenceObject
    )
    if ($null -eq $DifferenceObject) {
        $Left = $ReferenceObject
    } elseif ($null -eq $ReferenceObject ) {
        $right = $DifferenceObject
    } else {
        $left = [string[]][Linq.Enumerable]::Except($ReferenceObject, $DifferenceObject )
        $right = [string[]][Linq.Enumerable]::Except($DifferenceObject, $ReferenceObject)
        $common = [string[]][Linq.Enumerable]::Intersect($ReferenceObject, $DifferenceObject)
    }
    Write-Output $Left , $Right, $common
}

#endregion HelloID

#region HelloId_Actions_Variables
#region SendAsRights
$AddSendAsRights = @'
#region functions
function Add-SendAsRights {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $GroupName,

        [Parameter()]
        [String]
        $groupmember
    )
    try {
        Hid-Write-Status -Event Information -Message "Connecting to Exchange Online"

        # Connect to Exchange Online in an unattended scripting scenario using user credentials (MFA not supported).
        $securePassword = ConvertTo-SecureString $ExchangeAdminPassword -AsPlainText -Force
        $credential = [System.Management.Automation.PSCredential]::new($ExchangeAdminUsername, $securePassword)
        $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -ErrorAction Stop

        Hid-Write-Status -Event Success -Message "Successfully connected to Exchange Online"

        # Add Send As Permissions
        $parameters = @{
            Identity        = $groupName
            Trustee         = $groupmember
            AccessRights    = "SendAs"
        }

        $addPermission = Add-RecipientPermission @parameters -Confirm:$false -ErrorAction Stop
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
    finally {
        Hid-Write-Status -Event Information -Message "Disconnecting from Exchange Online"
        Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
        Hid-Write-Status -Event Success -Message "Successfully disconnected from Exchange Online"
    }
}
#endregion functions

try {
    Hid-Write-Status -Event Information -Message "Adding Send As Permissions for user [$groupmember] to mailbox [$groupName]"
    $null = Add-SendAsRights -GroupName ($groupname.Split("-")[0].trim(" ")) -GroupMember $GroupMember
    Hid-Write-Status -Event Success -Message "Succesfully added Send As Permissions for user [$groupmember] to mailbox [$groupName]"
    Hid-Write-Summary -Event Success -Message "Succesfully added Send As Permissions for user [$groupmember] to mailbox [$groupName]"
}
catch {
    Hid-Write-Status -Message  "Could not add Send As Permissions for user [$groupmember] to mailbox [$groupName]. Error: $($_.Exception.Message)" -Event Error
    Hid-Write-Summary -Message "Could not add Send As Permissions for user [$groupmember] to mailbox [$groupName]" -Event Failed
}
'@
$AddSendAsRightsAction = @{
    name                = 'Add-SendAsRights'
    automationContainer = 2
    objectGUID          = $null
    metaData            = '{"executeOnState":3}'
    useTemplate         = $false
    powerShellScript    = $AddSendAsRights
    variables           = @(
        @{
            "name"           = "GroupName"
            "value"          = "{{product.name}}"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "GroupMember"
            "value"          = "{{requester.username}}"
            "typeConstraint" = "string"
            "secure"         = $false
        }
    )
}

$RemoveSendAsRights = @'
#region functions
function Remove-SendAsRights {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $GroupName,

        [Parameter()]
        [String]
        $groupmember
    )
    try {
        Hid-Write-Status -Event Information -Message "Connecting to Exchange Online"

        # Connect to Exchange Online in an unattended scripting scenario using user credentials (MFA not supported).
        $securePassword = ConvertTo-SecureString $ExchangeAdminPassword -AsPlainText -Force
        $credential = [System.Management.Automation.PSCredential]::new($ExchangeAdminUsername, $securePassword)
        $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -ErrorAction Stop

        Hid-Write-Status -Event Success -Message "Successfully connected to Exchange Online"

        # Add Send As Permissions
        $parameters = @{
            Identity        = $groupName
            Trustee         = $groupmember
            AccessRights    = "SendAs"
        }

        $removePermission = Remove-RecipientPermission @parameters -Confirm:$false -ErrorAction Stop
    }
    catch {
        if($_ -like "*object '*' couldn't be found*"){
            Hid-Write-Status -Event Warning -Message "Mailbox $($parameters.Identity) couldn't be found. Possibly no longer exists. Skipping action"
        }elseif($_ -like "*User or group ""*"" wasn't found*"){
            Hid-Write-Status -Event Warning -Message "User $($parameters.Trustee) couldn't be found. Possibly no longer exists. Skipping action"
        }else{
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }
    finally {
        Hid-Write-Status -Event Information -Message "Disconnecting from Exchange Online"
        Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
        Hid-Write-Status -Event Success -Message "Successfully disconnected from Exchange Online"
    }
}
#endregion functions

try {
    Hid-Write-Status -Event Information -Message "Removing Send As Permissions for user [$groupmember] to mailbox [$groupName]"
    $null = Remove-SendAsRights -GroupName ($groupname.Split("-")[0].trim(" ")) -GroupMember $GroupMember
    Hid-Write-Status -Event Success -Message "Succesfully removed Send As Permissions for user [$groupmember] to mailbox [$groupName]"
    Hid-Write-Summary -Event Success -Message "Succesfully removed Send As Permissions for user [$groupmember] to mailbox [$groupName]"
}
catch {
    Hid-Write-Status -Message  "Could not remove Send As Permissions for user [$groupmember] to mailbox [$groupName]. Error: $($_.Exception.Message)" -Event Error
    Hid-Write-Summary -Message "Could not remove Send As Permissions for user [$groupmember] to mailbox [$groupName]" -Event Failed
}
'@
$RemoveSendAsRightsAction = @{
    name                = 'Remove-SendAsRights'
    automationContainer = 2
    objectGUID          = $null
    metaData            = '{"executeOnState":11}'
    useTemplate         = $false
    powerShellScript    = $RemoveSendAsRights
    variables           = @(
        @{
            "name"           = "GroupName"
            "value"          = "{{product.name}}"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "GroupMember"
            "value"          = "{{requester.username}}"
            "typeConstraint" = "string"
            "secure"         = $false
        }
    )
}
#endregion SendAsRights

#region FullAccessRights
$AddFullAccessRights = @'
#region functions
function Add-FullAccessRights {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $GroupName,

        [Parameter()]
        [String]
        $groupmember
    )
    try {
        Hid-Write-Status -Event Information -Message "Connecting to Exchange Online"

        # Connect to Exchange Online in an unattended scripting scenario using user credentials (MFA not supported).
        $securePassword = ConvertTo-SecureString $ExchangeAdminPassword -AsPlainText -Force
        $credential = [System.Management.Automation.PSCredential]::new($ExchangeAdminUsername, $securePassword)
        $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -ErrorAction Stop

        Hid-Write-Status -Event Success -Message "Successfully connected to Exchange Online"

        # Add Full Access Permissions
        $parameters = @{
            Identity        = $groupName
            User            = $groupmember
            InheritanceType = "All"
            AccessRights    = "FullAccess"
            AutoMapping     = $false
        }

        $addPermission = Add-MailboxPermission @parameters -Confirm:$false -ErrorAction Stop
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
    finally {
        Hid-Write-Status -Event Information -Message "Disconnecting from Exchange Online"
        Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
        Hid-Write-Status -Event Success -Message "Successfully disconnected from Exchange Online"
    }
}
#endregion functions

try {
    Hid-Write-Status -Event Information -Message "Adding Full Access Permissions for user [$groupmember] to mailbox [$groupName]"
    $null = Add-FullAccessRights -GroupName ($groupname.Split("-")[0].trim(" ")) -GroupMember $GroupMember
    Hid-Write-Status -Event Success -Message "Succesfully added Full Access Permissions for user [$groupmember] to mailbox [$groupName]"
    Hid-Write-Summary -Event Success -Message "Succesfully added Full Access Permissions for user [$groupmember] to mailbox [$groupName]"
}
catch {
    Hid-Write-Status -Message  "Could not add Full Access Permissions for user [$groupmember] to mailbox [$groupName]. Error: $($_.Exception.Message)" -Event Error
    Hid-Write-Summary -Message "Could not add Full Access Permissions for user [$groupmember] to mailbox [$groupName]" -Event Failed
}
'@
$AddFullAccessRightsAction = @{
    name                = 'Add-FullAccessRights'
    automationContainer = 2
    objectGUID          = $null
    metaData            = '{"executeOnState":3}'
    useTemplate         = $false
    powerShellScript    = $AddFullAccessRights
    variables           = @(
        @{
            "name"           = "GroupName"
            "value"          = "{{product.name}}"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "GroupMember"
            "value"          = "{{requester.username}}"
            "typeConstraint" = "string"
            "secure"         = $false
        }
    )
}

$RemoveFullAccessRights = @'
#region functions
function Remove-FullAccessRights {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $GroupName,

        [Parameter()]
        [String]
        $groupmember
    )
    try {
        Hid-Write-Status -Event Information -Message "Connecting to Exchange Online"

        # Connect to Exchange Online in an unattended scripting scenario using user credentials (MFA not supported).
        $securePassword = ConvertTo-SecureString $ExchangeAdminPassword -AsPlainText -Force
        $credential = [System.Management.Automation.PSCredential]::new($ExchangeAdminUsername, $securePassword)
        $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -ErrorAction Stop

        Hid-Write-Status -Event Success -Message "Successfully connected to Exchange Online"

        # Remove Full Access Permissions
        $parameters = @{
            Identity        = $groupName
            User            = $groupmember
            InheritanceType = "All"
            AccessRights    = "FullAccess"
        }
        $removePermission = Remove-MailboxPermission @parameters -Confirm:$false -ErrorAction Stop
    }
    catch {
        if($_ -like "*object '*' couldn't be found*"){
            Hid-Write-Status -Event Warning -Message "Mailbox $($parameters.Identity) couldn't be found. Possibly no longer exists. Skipping action"
        }elseif($_ -like "*User or group ""*"" wasn't found*"){
            Hid-Write-Status -Event Warning -Message "User $($parameters.Trustee) couldn't be found. Possibly no longer exists. Skipping action"
        }else{
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }
    finally {
        Hid-Write-Status -Event Information -Message "Disconnecting from Exchange Online"
        Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
        Hid-Write-Status -Event Success -Message "Successfully disconnected from Exchange Online"
    }
}
#endregion functions

try {
    Hid-Write-Status -Event Information -Message "Removing Full Access Permissions for user [$groupmember] to mailbox [$groupName]"
    $null = Remove-FullAccessRights -GroupName ($groupname.Split("-")[0].trim(" ")) -GroupMember $GroupMember
    Hid-Write-Status -Event Success -Message "Succesfully removed Full Access Permissions for user [$groupmember] to mailbox [$groupName]"
    Hid-Write-Summary -Event Success -Message "Succesfully removed Full Access Permissions for user [$groupmember] to mailbox [$groupName]"
}
catch {
    Hid-Write-Status -Message  "Could not remove Full Access Permissions for user [$groupmember] to mailbox [$groupName]. Error: $($_.Exception.Message)" -Event Error
    Hid-Write-Summary -Message "Could not remove Full Access Permissions for user [$groupmember] to mailbox [$groupName]" -Event Failed
}
'@
$RemoveFullAccessRightsAction = @{
    name                = 'Remove-FullAccessRights'
    automationContainer = 2
    objectGUID          = $null
    metaData            = '{"executeOnState":11}'
    useTemplate         = $false
    powerShellScript    = $RemoveFullAccessRights
    variables           = @(
        @{
            "name"           = "GroupName"
            "value"          = "{{product.name}}"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "GroupMember"
            "value"          = "{{requester.username}}"
            "typeConstraint" = "string"
            "secure"         = $false
        }
    )
}
#endregion FullAccessRights

#region SendOnBehalfRights
$AddSendOnBehalfRights = @'
#region functions
function Add-SendOnBehalfRights {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $GroupName,

        [Parameter()]
        [String]
        $groupmember
    )

    try {
        Hid-Write-Status -Event Information -Message "Connecting to Exchange Online"

        # Connect to Exchange Online in an unattended scripting scenario using user credentials (MFA not supported).
        $securePassword = ConvertTo-SecureString $ExchangeAdminPassword -AsPlainText -Force
        $credential = [System.Management.Automation.PSCredential]::new($ExchangeAdminUsername, $securePassword)
        $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -ErrorAction Stop

        Hid-Write-Status -Event Success -Message "Successfully connected to Exchange Online"

        # Add Send On Behalf Permissions
        $parameters = @{
            Identity            = $groupName
            GrantSendOnBehalfTo = @{Add = "$($GroupMember)" }
        }

        $addPermission = Set-Mailbox @parameters -Confirm:$false -ErrorAction Stop
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
    finally {
        Hid-Write-Status -Event Information -Message "Disconnecting from Exchange Online"
        Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
        Hid-Write-Status -Event Success -Message "Successfully disconnected from Exchange Online"
    }
}
#endregion functions

try {
    Hid-Write-Status -Event Information -Message "Adding Send On Behalf Permissions for user [$groupmember] to mailbox [$groupName]"
    $null = Add-SendOnBehalfRights -GroupName ($groupname.Split("-")[0].trim(" ")) -GroupMember $GroupMember
    Hid-Write-Status -Event Success -Message "Succesfully added Send On Behalf Permissions for user [$groupmember] to mailbox [$groupName]"
    Hid-Write-Summary -Event Success -Message "Succesfully added Send On Behalf Permissions for user [$groupmember] to mailbox [$groupName]"
}
catch {
    Hid-Write-Status -Message  "Could not add Send On Behalf Permissions for user [$groupmember] to mailbox [$groupName]. Error: $($_.Exception.Message)" -Event Error
    Hid-Write-Summary -Message "Could not add Send On Behalf Permissions for user [$groupmember] to mailbox [$groupName]" -Event Failed
}
'@
$AddSendOnBehalfRightsAction = @{
    name                = 'Add-SendOnBehalfRights'
    automationContainer = 2
    objectGUID          = $null
    metaData            = '{"executeOnState":3}'
    useTemplate         = $false
    powerShellScript    = $AddSendOnBehalfRights
    variables           = @(
        @{
            "name"           = "GroupName"
            "value"          = "{{product.name}}"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "GroupMember"
            "value"          = "{{requester.username}}"
            "typeConstraint" = "string"
            "secure"         = $false
        }
    )
}

$RemoveSendOnBehalfRights = @'
#region functions
function Remove-SendOnBehalfRights {
    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $GroupName,

        [Parameter()]
        [String]
        $groupmember
    )
    try {
        Hid-Write-Status -Event Information -Message "Connecting to Exchange Online"

        # Connect to Exchange Online in an unattended scripting scenario using user credentials (MFA not supported).
        $securePassword = ConvertTo-SecureString $ExchangeAdminPassword -AsPlainText -Force
        $credential = [System.Management.Automation.PSCredential]::new($ExchangeAdminUsername, $securePassword)
        $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -ErrorAction Stop

        Hid-Write-Status -Event Success -Message "Successfully connected to Exchange Online"

        # Remove Send On Behalf Permissions
        $parameters = @{
            Identity            = $groupName
            GrantSendOnBehalfTo = @{Remove = "$($GroupMember)" }
        }
        $removePermission = Set-Mailbox @parameters -Confirm:$false -ErrorAction Stop
    }
    catch {
        if($_ -like "*object '*' couldn't be found*"){
            Hid-Write-Status -Event Warning -Message "Mailbox $($parameters.Identity) couldn't be found. Possibly no longer exists. Skipping action"
        }elseif($_ -like "Couldn't find object ""$($parameters.Trustee)""*"){
            Hid-Write-Status -Event Warning -Message "User $($parameters.Trustee) couldn't be found. Possibly no longer exists. Skipping action"
        }else{
            $PSCmdlet.ThrowTerminatingError($_)
        }
    }
    finally {
        Hid-Write-Status -Event Information -Message "Disconnecting from Exchange Online"
        Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
        Hid-Write-Status -Event Success -Message "Successfully disconnected from Exchange Online"
    }
}
#endregion functions

try {
    Hid-Write-Status -Event Information -Message "Removing Send On Behalf Permissions for user [$groupmember] to mailbox [$groupName]"
    $null = Remove-SendOnBehalfRights -GroupName ($groupname.Split("-")[0].trim(" ")) -GroupMember $GroupMember
    Hid-Write-Status -Event Success -Message "Succesfully removed Send On Behalf Permissions for user [$groupmember] to mailbox [$groupName]"
    Hid-Write-Summary -Event Success -Message "Succesfully removed Send On Behalf Permissions for user [$groupmember] to mailbox [$groupName]"
}
catch {
    Hid-Write-Status -Message  "Could not remove Send On Behalf Permissions for user [$groupmember] to mailbox [$groupName]. Error: $($_.Exception.Message)" -Event Error
    Hid-Write-Summary -Message "Could not remove Send On Behalf Permissions for user [$groupmember] to mailbox [$groupName]" -Event Failed
}
'@
$RemoveSendOnBehalfRightsAction = @{
    name                = 'Remove-SendOnBehalfRights'
    automationContainer = 2
    objectGUID          = $null
    metaData            = '{"executeOnState":11}'
    useTemplate         = $false
    powerShellScript    = $RemoveSendOnBehalfRights
    variables           = @(
        @{
            "name"           = "GroupName"
            "value"          = "{{product.name}}"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "GroupMember"
            "value"          = "{{requester.username}}"
            "typeConstraint" = "string"
            "secure"         = $false
        }
    )
}

#endregion SendOnBehalfRights

#region Emails
$ApproveEmailContent = '
Dear Servicedesk,

The product {{product.name}} has sucesfully been granted to {{requester.fullName}}.

Kind regards,
HelloID
'
$ApproveEmailAction = @{
    executeOnState      = 3
    variables           = @(
        @{
            "name"           = "to"
            "value"          = "$defaultToAddress"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "from"
            "value"          = "$defaultFromAddress"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "subject"
            "value"          = "HelloID - Successfully granted product {{product.name}} to {{requester.fullName}}"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "content"
            "value"          = $ApproveEmailContent
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "isHtmlContent"
            "value"          = $true
            "typeConstraint" = "boolean"
            "secure"         = $false
        }
    )
}

$ReturnEmailContent = '
Dear Servicedesk,

The product {{product.name}} has sucesfully been revoked for {{requester.fullName}}.

Kind regards,
HelloID
'
$ReturnEmailAction = @{
    executeOnState      = 11
    variables           = @(
        @{
            "name"           = "to"
            "value"          = "$defaultToAddress"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "from"
            "value"          = "$defaultFromAddress"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "subject"
            "value"          = "HelloID - Successfully revoked product {{product.name}} for {{requester.fullName}}"
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "content"
            "value"          = $ReturnEmailContent
            "typeConstraint" = "string"
            "secure"         = $false
        },
        @{
            "name"           = "isHtmlContent"
            "value"          = $true
            "typeConstraint" = "boolean"
            "secure"         = $false
        }
    )
}
#endregion Emails

#endregion HelloId_Actions_Variables

#region script
try {
    try{
        Write-HidStatus -Event Information -Message "Connecting to Exchange Online"

        # Connect to Exchange Online in an unattended scripting scenario using user credentials (MFA not supported).
        $securePassword = ConvertTo-SecureString $ExchangeAdminPassword -AsPlainText -Force
        $credential = [System.Management.Automation.PSCredential]::new($ExchangeAdminUsername, $securePassword)
        $exchangeSession = Connect-ExchangeOnline -Credential $credential -ShowBanner:$false -ShowProgress:$false -ErrorAction Stop

        Write-HidStatus -Event Success -Message "Successfully connected to Exchange Online"

        # Only get Exchange Shared Mailboxes (can be changed easily to get all mailboxes)
        Write-HidStatus -Event Information -Message "Querying Exchange Shared Mailboxes"

        $parameters = @{
            RecipientTypeDetails = "SharedMailbox"
            ResultSize           = "Unlimited"
        }
        # Add Filter when provided
        if($null -ne $Filter){
            $parameters += @{
                Filter  = $Filter
            }
        }

        $mailboxes = Get-EXOMailbox @parameters -ErrorAction Stop

        $TargetGroups = $mailBoxes
        # $TargetGroups = $null              #easy way to remove all products

        Write-HidStatus -Event Success -Message "Succesfully queried Exchange Shared Mailboxes. Result count: $($mailboxes.id.Count)"
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
    finally {
        Write-HidStatus -Event Information -Message "Disconnecting from Exchange Online"
        Disconnect-ExchangeOnline -Confirm:$false -Verbose:$false -ErrorAction Stop
        Write-HidStatus -Event Success -Message "Successfully disconnected from Exchange Online"
    }

    Write-HidStatus -Message 'Starting synchronization of TargetSystem groups to HelloID products' -Event Information
    Write-HidStatus -Message "------[$TargetSystemName]-----------" -Event Information
    if ($TargetGroups.count -gt 0) {
        if ($null -eq $TargetGroups.$uniqueProperty) {
            throw "The specified unique property [$uniqueProperty] for the target system does exist as property in the groups"
        }
    }

    if ($TargetGroups.Count -eq 0) {
        Write-HidStatus -Message 'No Target Groups have been found' -Event Information
    } else {
        Write-HidStatus -Message "[$($TargetGroups.Count)] Target group(s)" -Event Information
    }

    $targetGroupsList = [System.Collections.Generic.List[Object]]::New()
    foreach ($group in $TargetGroups) {
        foreach ($PermissionType in $PermissionTypes) {
            $tempGroup = $group | Select-Object *
            $type = switch ( $PermissionType.tolower()) {
                'sendas' { 'SA' }
                'fullaccess' { 'FA' }
                'sendonbehalf' { 'SO' }
            }
            # SA FA SO
            $tempGroup | Add-Member @{
                CombinedUniqueId = $SKUPrefix + "$($group.$uniqueProperty)".Replace('-', '') + $type
                TypePermission   = $PermissionType
            }
            $targetGroupsList.Add($tempGroup)
        }
    }
    $TargetGroups = $targetGroupsList
    $TargetGroupsGrouped = $TargetGroups | Group-Object -Property CombinedUniqueId -AsHashTable -AsString

    Write-HidStatus -Message '------[HelloID]-----------------------' -Event Information
    Write-HidStatus -Message 'Getting default agent pool' -Event Information
    $defaultAgentPool = (Get-HIDDefaultAgentPool) | Where-Object { $_.options -eq '1' }

    Write-HidStatus -Message "Gathering the self service product category '$ProductCategory'" -Event Information
    $selfServiceCategory = (Get-HIDSelfServiceCategory) | Where-Object { $_.name -eq "$ProductCategory" }

    if ($selfServiceCategory.isEnabled -eq $false) {
        Write-HidStatus -Message "Found a disabled ProductCategory '$ProductCategory', will enable the current category" -Event Information
        $selfServiceCategory = New-HIDSelfServiceCategory -Name "$ProductCategory" -IsEnabled $true -SelfServiceCategoryGUID  $selfServiceCategory.selfServiceCategoryGUID
    } elseif ($null -eq $selfServiceCategory) {
        Write-HidStatus -Message "No ProductCategory Found will Create a new category '$ProductCategory'" -Event Information
        $selfServiceCategory = New-HIDSelfServiceCategory -Name "$ProductCategory" -IsEnabled $true
    }

    Write-HidStatus -Message 'Gathering Self service products from HelloID' -Event Information
    $selfServiceProduct = Get-HIDSelfServiceProduct
    $selfServiceProductGrouped = $selfServiceProduct | Group-Object -Property 'code' -AsHashTable -AsString


    Write-HidStatus -Message 'Gathering Self service product actions from HelloID' -Event Information
    $selfServiceProductAction = Get-HIDSelfServiceProductAction
    $selfServiceProductActionGrouped = $selfServiceProductAction | Group-Object -Property 'objectGuid' -AsHashTable -AsString

    Write-HidStatus -Message '------[Summary]-----------------------' -Event Information
    Write-HidStatus -Message "Total HelloID Self Service Product(s) found [$($selfServiceProduct.Count)]" -Event Information

    # Making sure we only manage the products of Target System
    $currentProducts = $selfServiceProduct | Where-Object { $_.code.ToLower().startswith("$($SKUPrefix.tolower())") }

    Write-HidStatus -Message "HelloID Self Service Product(s) of Target System [$TargetSystemName] found [$($currentProducts.Count)]" -Event Information

    # Null Check Reference before compare
    $currentProductsChecked = if ($null -ne $currentProducts.code) { $currentProducts.code.tolower() } else { $null }
    $targetGroupsChecked = if ($null -ne $TargetGroups.CombinedUniqueId) { $TargetGroups.CombinedUniqueId.ToLower() } else { $null }

    $productToCreateInHelloID , $productToRemoveFromHelloID, $productExistsInHelloID = Compare-Join -ReferenceObject $targetGroupsChecked -DifferenceObject $currentProductsChecked
    Write-HidStatus "[$($productToCreateInHelloID.count)] Products will be Created " -Event Information
    Write-HidStatus "[$($productExistsInHelloID.count)] Products already exist in HelloId" -Event Information
    if ($removeProduct) {
        Write-HidStatus "[$($productToRemoveFromHelloID.count)] Products will be Removed " -Event Information
    } else {
        Write-HidStatus 'Verify if there are products found which are already disabled.' -Event Information
        $productToRemoveFromHelloID = [array]($currentProducts | Where-Object { ( $_.code.ToLower() -in $productToRemoveFromHelloID) -and $_.visibility -ne 'Disabled' }).code
        Write-HidStatus "[$($productToRemoveFromHelloID.count)] Products will be disabled " -Event Information
    }

    Write-HidStatus -Message '------[Processing]------------------' -Event Information
    foreach ($productToCreate in $productToCreateInHelloID) {
        $product = $TargetGroupsGrouped[$productToCreate]
        Write-HidStatus "Creating Product [$($product.name)]" -Event Information
        $resourceOwnerGroupName = if ([string]::IsNullOrWhiteSpace($SAProductResourceOwner) ) { $product.name } else { $SAProductResourceOwner }

        $resourceOwnerGroup = Get-HIDGroup -GroupName $resourceOwnerGroupName  -ResourceGroup
        if ($null -eq $resourceOwnerGroup ) {
            Write-HidStatus "Creating a new resource owner group for Product [$($resourceOwnerGroupName ) Resource Owners]" -Event Information
            $resourceOwnerGroup = New-HIDGroup -GroupName $resourceOwnerGroupName -isEnabled $true
        }
        $productBody = @{
            Name                       = "$($product.name) - $($product.TypePermission)"
            Description                = "$TargetSystemName - $($product.name) - $($product.TypePermission)"
            ManagedByGroupGUID         = $($resourceOwnerGroup.groupGuid)
            Categories                 = @($selfServiceCategory.name)
            ApprovalWorkflowName       = $SAProductWorkflow
            AgentPoolGUID              = $defaultAgentPool.agentPoolGUID
            Icon                       = $null
            FaIcon                     = "fa-$FaIcon"
            UseFaIcon                  = $true
            IsAutoApprove              = $false
            IsAutoDeny                 = $false
            MultipleRequestOption      = 1
            IsCommentable              = $true
            HasTimeLimit               = $false
            LimitType                  = 'Fixed'
            ManagerCanOverrideDuration = $true
            ReminderTimeout            = 30
            OwnershipMaxDuration       = 90
            CreateDefaultEmailActions  = $true
            Visibility                 = $productVisibility
            Code                       = $product.CombinedUniqueId
        } | ConvertTo-Json
        $selfServiceProduct = Set-HIDSelfServiceProduct -ProductJson $productBody

        $sAAccessGroup = Get-HIDGroup -GroupName $ProductAccessGroup
        if (-not $null -eq $sAAccessGroup) {
            Write-HidStatus -Message  "Adding ProductAccessGroup [$ProductAccessGroup] to Product " -Event Information
            $null = Add-HIDProductMember -selfServiceProductGUID $selfServiceProduct.selfServiceProductGUID -MemberGUID $sAAccessGroup.groupGuid
        } else {
            Write-HidStatus -Message  "The Specified ProductAccessGroup [$ProductAccessGroup] does not exist. We will continue without adding the access Group" -Event Warning
        }

        $PowerShellActions = [System.Collections.Generic.list[object]]@()
        switch ($product.TypePermission.tolower()) {
            'sendas' {
                $PowerShellActions.Add($AddSendAsRightsAction)
                $PowerShellActions.Add($RemoveSendAsRightsAction)
                break
            }
            'fullaccess' {
                $PowerShellActions.Add($AddFullAccessRightsAction)
                $PowerShellActions.Add($RemoveFullAccessRightsAction)
            }
            'sendonbehalf' {
                $PowerShellActions.Add($AddSendOnBehalfRightsAction)
                $PowerShellActions.Add($RemoveSendOnBehalfRightsAction)
            }
        }

        foreach ($PowerShellAction in $PowerShellActions) {
            Write-HidStatus -Message  "Adding PowerShell action [$($PowerShellAction.Name)] to Product" -Event Information
            $PowerShellAction.objectGUID = $selfServiceProduct.selfServiceProductGUID
            $null = Add-HIDPowerShellAction -Body ($PowerShellAction | ConvertTo-Json)
        }

        if($true -eq $includeEmailAction){
            $EmailActions = [System.Collections.Generic.list[object]]@(
                $ApproveEmailAction
                $ReturnEmailAction
            )

            foreach ($EmailAction in $EmailActions) {
                Write-HidStatus -Message  "Adding Email action to Product" -Event Information
                $null = Add-HIDEmailAction -ProductGUID $selfServiceProduct.selfServiceProductGUID -Body ($EmailAction | ConvertTo-Json)
            }
        }
    }

    foreach ($productToRemove in $ProductToRemoveFromHelloID) {
        $product = $selfServiceProductGrouped[$productToRemove] | Select-Object -First 1
        if ($removeProduct) {
            Write-HidStatus "Removing Product [$($product.name)]" -Event Information
            $null = Remove-HIDSelfServiceProduct -ProductGUID  $product.selfServiceProductGUID
        } else {
            Write-HidStatus "Disabling Product [$($product.name)]" -Event Information
            $product.visibility = 'Disabled'
            $disableProductBody = ConvertTo-Json ($product | Select-Object -Property * -ExcludeProperty Code)
            $null = Set-HIDSelfServiceProduct -ProductJson $disableProductBody
        }
    }

    foreach ($productToUpdate in $productExistsInHelloID) {
        $product = $selfServiceProductGrouped[$productToUpdate] | Select-Object -First 1
        if($true -eq $overwriteExistingProduct){
            Write-HidStatus "Overwriting existing Product [$($product.name)]" -Event Information
            $overwriteProductBody = ConvertTo-Json ($product | Select-Object -Property *)
            $null = Set-HIDSelfServiceProduct -ProductJson $overwriteProductBody

            if($true -eq $overwriteExistingProductAction){
                $productActions = $selfServiceProductActionGrouped[$($product.selfServiceProductGUID)]
                foreach($productAction in $productActions){
                    $overwritePowerShellAction = $null
                    switch ($productAction.name.tolower()) {
                        'add-sendasrights' {
                            Write-HidStatus "Overwriting existing Product PowerShell Action [$($productAction.name)]" -Event Information
                            $tempAddSendAsRightsAction = $AddSendAsRightsAction.psobject.copy()
                            $overwritePowerShellAction = $tempAddSendAsRightsAction

                            $overwritePowerShellAction.objectGUID = $product.selfServiceProductGUID
                            $overwritePowerShellAction.automationTaskGuid = $productAction.automationTaskGuid
                            $null = Add-HIDPowerShellAction -Body ($overwritePowerShellAction | ConvertTo-Json)
                            break
                        }
                        'remove-sendasrights' {
                            Write-HidStatus "Overwriting existing Product PowerShell Action [$($productAction.name)]" -Event Information
                            $tempRemoveSendAsRightsAction = $RemoveSendAsRightsAction.psobject.copy()
                            $overwritePowerShellAction = $tempRemoveSendAsRightsAction

                            $overwritePowerShellAction.objectGUID = $product.selfServiceProductGUID
                            $overwritePowerShellAction.automationTaskGuid = $productAction.automationTaskGuid
                            $null = Add-HIDPowerShellAction -Body ($overwritePowerShellAction | ConvertTo-Json)
                            break
                        }
                        'add-fullaccessrights' {
                            Write-HidStatus "Overwriting existing Product PowerShell Action [$($productAction.name)]" -Event Information
                            $tempAddFullAccessRightsAction = $AddFullAccessRightsAction.psobject.copy()
                            $overwritePowerShellAction = $tempAddFullAccessRightsAction

                            $overwritePowerShellAction.objectGUID = $product.selfServiceProductGUID
                            $overwritePowerShellAction.automationTaskGuid = $productAction.automationTaskGuid
                            $null = Add-HIDPowerShellAction -Body ($overwritePowerShellAction | ConvertTo-Json)
                            break
                        }
                        'remove-fullaccessrights' {
                            Write-HidStatus "Overwriting existing Product PowerShell Action [$($productAction.name)]" -Event Information
                            $tempRemoveFullAccessRightsAction = $RemoveFullAccessRightsAction.psobject.copy()
                            $overwritePowerShellAction = $tempRemoveFullAccessRightsAction

                            $overwritePowerShellAction.objectGUID = $product.selfServiceProductGUID
                            $overwritePowerShellAction.automationTaskGuid = $productAction.automationTaskGuid
                            $null = Add-HIDPowerShellAction -Body ($overwritePowerShellAction | ConvertTo-Json)
                            break
                        }
                        'add-sendonbehalfrights' {
                            Write-HidStatus "Overwriting existing Product PowerShell Action [$($productAction.name)]" -Event Information
                            $tempAddSendOnBehalfAction = $AddSendOnBehalfRightsAction.psobject.copy()
                            $overwritePowerShellAction = $tempAddSendOnBehalfAction

                            $overwritePowerShellAction.objectGUID = $product.selfServiceProductGUID
                            $overwritePowerShellAction.automationTaskGuid = $productAction.automationTaskGuid
                            $null = Add-HIDPowerShellAction -Body ($overwritePowerShellAction | ConvertTo-Json)
                            break
                        }
                        'remove-sendonbehalfrights' {
                            Write-HidStatus "Overwriting existing Product PowerShell Action [$($productAction.name)]" -Event Information
                            $tempRemoveRemoveSendOnBehalfAction = $RemoveSendOnBehalfRightsAction.psobject.copy()
                            $overwritePowerShellAction = $tempRemoveRemoveSendOnBehalfAction

                            $overwritePowerShellAction.objectGUID = $product.selfServiceProductGUID
                            $overwritePowerShellAction.automationTaskGuid = $productAction.automationTaskGuid
                            $null = Add-HIDPowerShellAction -Body ($overwritePowerShellAction | ConvertTo-Json)
                            break
                        }
                    }
                }
            }

        }else{
            # Make sure existing products are enabled
            if ($product.visibility -eq 'Disabled') {
                Write-HidStatus "Enabling existing Product [$($product.name)]" -Event Information
                $product.visibility = $productVisibility
                $product.isEnabled = $true
                $enableProductBody = ConvertTo-Json ($product | Select-Object -Property *)
                $null = Set-HIDSelfServiceProduct -ProductJson $enableProductBody
            }
            Write-HidStatus "No Changes Needed. Product [$($product.name)]" -Event Information
        }
    }

    Write-HidStatus -Message "Successfully synchronized [$TargetSystemName] to HelloID products" -Event Success
    Write-HidSummary -Message "Successfully synchronized [$TargetSystemName] to HelloID products" -Event Success
} catch {
    Write-HidStatus -Message "Error synchronization of [$TargetSystemName] to HelloID products" -Event Error
    Write-HidStatus -Message "Exception message: $($_.Exception.Message)" -Event Error
    Write-HidStatus -Message "Exception details: $($_.errordetails)" -Event Error
    Write-HidSummary -Message "Error synchronization of [$TargetSystemName] to HelloID products" -Event Failed
}
#endregion
