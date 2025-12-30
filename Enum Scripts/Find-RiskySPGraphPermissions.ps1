# Find Azure Entra ID service principals with high privileged Graph app role assignments
# Requires Directory.Read.All or Application.Read.All Permissions in Microsoft Graph

$MsGraphAppId = '00000003-0000-0000-c000-000000000000'

$PrivilegedRoles = @(
    'RoleManagement.ReadWrite.Directory'
    'AppRoleAssignment.ReadWrite.All'
    'Application.ReadWrite.All'
    'Directory.ReadWrite.All'
)

$OutCsv = ".\risky-graph-permissions.csv"


$TokenData = az account get-access-token --resource-type ms-graph | ConvertFrom-Json
$AccessToken = $TokenData.accessToken

if (-not $AccessToken) { throw "Run 'az login' first." }

$Headers = @{ 
    Authorization = "Bearer $AccessToken" 
    "Content-Type" = "application/json"
}

function Invoke-GraphApi {
    param([string]$Uri)
    try {
        return Invoke-RestMethod -Uri $Uri -Headers $Headers -Method Get -ErrorAction Stop
    } catch {
        Write-Error "Graph API Error: $($_.Exception.Message)"
        return $null
    }
}

# Fetch Role IDs
$Uri = "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=appId eq '$MsGraphAppId'&`$select=id,appRoles"
$GraphSp = (Invoke-GraphApi $Uri).value[0]
$GraphSpId = $GraphSp.id
$RiskMap = @{}
foreach ($RoleName in $PrivilegedRoles) {
    $RoleDef = $GraphSp.appRoles | Where-Object { $_.value -eq $RoleName }
    if ($RoleDef) { $RiskMap[$RoleDef.id] = $RoleName }
}


$Findings = [System.Collections.Generic.List[PSObject]]::new()

$NextLink = "https://graph.microsoft.com/v1.0/servicePrincipals/$GraphSpId/appRoleAssignedTo?`$top=999"
while ($NextLink) {
    $Page = Invoke-GraphApi $NextLink
    if (-not $Page) { break }

    foreach ($Grant in $Page.value) {
        if ($RiskMap.ContainsKey($Grant.appRoleId)) {
            $Findings.Add([PSCustomObject]@{
                DisplayName       = $Grant.principalDisplayName
                ObjectId          = $Grant.principalId
                GrantedPermission = $RiskMap[$Grant.appRoleId]
            })
        }
    }
    $NextLink = $Page.'@odata.nextLink'
}

Write-Host "Found $($Findings.Count) privileged applications." -ForegroundColor Green
$Findings | Sort-Object DisplayName | Format-Table -AutoSize
$Findings | Export-Csv -Path $OutCsv -NoTypeInformation
Write-Host "Saved to $OutCsv" -ForegroundColor Gray
