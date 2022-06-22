| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.       |
<br />

<p align="center">
  <img src="https://user-images.githubusercontent.com/69046642/160915847-b8a72368-931c-45d1-8f93-9cc7bb974ca8.png">
</p>

## Versioning
| Version | Description | Date |
| - | - | - |
| 1.0.0   | Initial release | 2022/06/20  |

<!-- TABLE OF CONTENTS -->
## Table of Contents
- [Versioning](#versioning)
- [Table of Contents](#table-of-contents)
- [Introduction](#introduction)
- [Getting started](#getting-started)
  - [Prerequisites](#prerequisites)
  - [Connection settings](#connection-settings)
- [Remarks](#remarks)
- [Getting help](#getting-help)
- [HelloID Docs](#helloid-docs)

## Introduction
By using this connector, you will have the ability to create HelloId SelfService Products based on Exchange Online Shared Mailboxes. It manages only the products of the target system. The existing and manually created products are unmanaged and excluded from the sync.

The created Self-service Products are intended to manage the permissions of the Exchange Shared Mailboxes. For each mailbox, there will be one or more self-service products created. Depending on the number of permission types you specify.
The name of the products will be Mailbox name + the type of permission. Example : "Accounting Department - FullAccess" or "Accounting Department - SendOnBehalf"
Optionally, you can include an Email action.


## Getting started

### Prerequisites
- [ ] Make sure you have Windows PowerShell 5.1 installed on the server where the HelloID agent and Service Automation agent are running.
  > The connector is compatible with older versions of Windows PowerShell. Although we cannot guarantuee the compatibility.
- [ ] Installed and available [Microsoft Exchange Online PowerShell V2 module](https://docs.microsoft.com/en-us/powershell/exchange/exchange-online-powershell-v2?view=exchange-ps)
- [ ] To manage users, mailboxes and groups, the service account has to have the role "**Exchange Administrator**" assigned.
- [ ] Required to run **On-Premises** since it is not allowed to import a module with the Cloud Agent.
- [ ] Define the Global variables for your Exchange Environment


### Connection settings

The connection settings are defined in the automation variables [user defined variables](https://docs.helloid.com/hc/en-us/articles/360014169933-How-to-Create-and-Manage-User-Defined-Variables). And the Product configuration can be configured in the script


| Variable name                 | Description                                                  | Notes                                               |
| ----------------------------- | ------------------------------------------------------------ | ------------------------------------------------------------ |
| $portalBaseUrl                | HelloID Base Url                        | (Default Global Variable)    |
| $portalApiKey                 | HelloID Api Key                         | (Default Global Variable)    |
| $portalApiSecret              | HelloID Api Secret                      | (Default Global Variable)    |
| $ExchangeAdminUsername        | Exchange BaseUrl/Powershell             | **Define as Global Varaible**  |
| $ExchangeAdminPassword        | Exchange Admin Username                 | **Define as Global Varaible**  |
| $Filter                       | Filter for Exchange Shared Mailboxes    | *Optional, when no filter is provided, all mailboxes will be queried*  |
| $ProductAccessGroup           | HelloID Product Access Group            | *If not found, the product is created without an Access Group* |
| $ProductCategory              | HelloID Product Category                | *If the category is not found, it will be created* |
| $SAProductResourceOwner       | HelloID Product Resource Owner Group    | *If left empty the groupname will be: "Resource owners [target-systeem] - [Product_Naam]")* |
| $SAProductWorkflow            | HelloID Product Approval workflow       | *If empty. The Default HelloID Workflow is used. If specified Workflow does not exist the Product creation will raise an error.* |
| $FaIcon                       | HelloID Product fa-icon name              | |
| $removeProduct                | HelloID Remove Product instead of Disable | |
| $overwriteExistingProduct     | Boolean, set to 'True' to overwrite the Product settings | If True existing product will be overwritten with the input from this script (e.g. the approval worklow or icon). Only use this when you actually changed the product input |
| $overwriteExistingProductAction   | Boolean, set to 'True' to overwrite the PowerShell action(s) | If True existing product actions will be overwritten with the input from this script. Only use this when you actually changed the script or variables for the action(s) |
| $productVisibility            | HelloID Product Visibility                | "ALL" |
| $uniqueProperty               | Target Groups Unique Key                  | The vaule will be used as CombinedUniqueId|
| $SKUPrefix                    | HelloID SKU prefix (Max. 4 characters)    | The prefix will be used as CombinedUniqueId |
| $TargetSystemName             | HelloID Prefix of product description     | |
| $includeEmailAction           | Boolean, set to 'True' to include the Email action(s)     | |
| $defaultFromAddress           | The default sender address for the Email action(s)        | |
| $defaultToAddress             | The default receiving address for the Email action(s)     | |


## Remarks
- The Products are created and disable/deleted and, when configured, updated.
    > The Update take will place for the configured Product settings and PowerShell Actions, but not for the Email actions (since there is no update API for Email actions).
- When the RemoveProduct switch is adjusted to remove the products. The products will be delete from HelloID instead of Disable. This will remove also the previous disabled products (by the sync).
- When the overwriteExistingProduct switch is adjusted to overwrite the existing products, this will be performed for all products created from this sync. This will update also the previous disabled products (by the sync).
- When the overwriteExistingProductAction switch is adjusted to overwrite the existing product actions, this will be performed for all products created from this sync. This will update also the previous disabled products (by the sync).
    > The Update will only take place for PowerShell actions. This will not take place for the Email actions (since there is no update API for Email actions).
- The managers of the sharedmailboxes are not added in the "Resource Owner Group" of the products
- The Unique identifier (CombineduniqueId / SKU)   is builded as follows:
  $SKUPrefix + GUID of the sharedmailboxes without dashes + Abbreviation of the permission Type

## Getting help
> _For more information on how to configure a HelloID PowerShell scheduled task, please refer to our [documentation](https://docs.helloid.com/hc/en-us/articles/115003253294-Create-Custom-Scheduled-Tasks) pages_

> _If you need help, feel free to ask questions on our [forum](https://forum.helloid.com)_

## HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
