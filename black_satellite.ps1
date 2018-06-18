<#
.SYNOPSIS

This script allows to detect identical Active Directory passwords assigned to different accounts.
Imagine sysadmin with the single password for all his admin accounts in different domains.
The only accounts that are checked - the ones with the administrative permissions in a given domain.

Required Dependencies: ActiveDirectory PowerShell module, DSInternals PowerShell module
Required permissions: Replicate Directory changes All

.DESCRIPTION

The script loads the necessary modules, obtains the current Active Directory forest`s root domain and optionally all the trusting forests
(in case you use the management model with the single admin forest). It then pulls administrative accounts from the current forest
and optionally from the trusting forests. For each admin account it obtains the following data:
    - DistinguishedName
    - NTHash
    - LMHash
    - ClearText
    - Enabled
    - LastLogonDate
On the next step, script detects if there are the following violations:
    - password reuse
    - LMHash is not empty (you shouldn't have LMhashes enabled)
    - ClearText is not empty (you shoudn't store passwords of the admin accounts in the decryptable format!)
The results are save to the CSV file which can be processed by any SIEM system.


.PARAMETER OutputFolderPath

[string] UNC path to directory to save the CSV file with the results.

.PARAMETER AdminOUNamePattern

[string] Name of the AD OU which contain admin accounts.

.PARAMETER ProcessTrustingDomains

[switch] Instructs script to get trusts from the current local computer Forest and pull admin accounts from them.

.EXAMPLE

PS C:\GIT\Personal> .\black_satellite.ps1 -OutputFolderPath C:\reports\ -AdminOUNamePattern "Privileged accounts" -Verbose

Description
-----------
Instructs the script to obtain admin accounts from the "Privileged accounts" OU in the current forest and save results to the CSV in C:\reports

.EXAMPLE

PS C:\GIT\Personal> .\black_satellite.ps1 -OutputFolderPath C:\reports\ -AdminOUNamePattern "Privileged accounts" -ProcessTrustingDomains -Verbose

Description
-----------
Instructs the script to obtain admin accounts from the "Privileged accounts" OU in the current forest and all its trusting forests,
 save results to the CSV in C:\reports

.NOTES

This script requires 'Replicate Directory changes All' permissions in all domains that you are going to work with.
All magic with extracting passowrd hashes is performed by the wonderful DSInternals module:
https://www.powershellgallery.com/packages/DSInternals/2.22
#>
Param (
    [Parameter(Mandatory=$true, Position=0)]
	[ValidateScript({Test-Path $_ -PathType Container})]
    [String] $OutputFolderPath,
    
    [Parameter(Mandatory=$true, Position=1)]
    [ValidateScript({!([string]::IsNullOrEmpty($_))})]
    [String] $AdminOUNamePattern,
    
    [Parameter(Mandatory=$false, Position=2)]
	[Switch] $ProcessTrustingDomains
)

Set-StrictMode -Version Latest

# Verifying if ActiveDirectory/DSInternals modules are imported
Write-Verbose -Message "Checking ActiveDirectory/DSInternals module."
try
{
    $adm = Get-Module -Name ActiveDirectory
    $dsi = Get-Module -Name DSInternals
}
catch
{
    throw "Cannot verify ActiveDirectory/DSInternals module $($_.Exception.Message)"
}
if (!$adm)
{
    Write-Output "ActiveDirectory/DSInternals is not present. Will try to import it."
    try
    {
        Import-Module -Name ActiveDirectory
        Import-Module -Name DSInternals
    }
    catch
    {
        throw "Cannot import ActiveDirectory/DSInternals module $($_.Exception.Message)"
    }
    Write-Output "ActiveDirectory/DSInternals module is imported."
}
else
{
    Write-Output "ActiveDirectory/DSInternals module is imported already."
}

# Getting the current forest
try
{
    $curForest = Get-ADForest -Current LocalComputer
}
catch
{
    throw "Cannot get current AD forest $($_.Exception.Message)"
}

# Main logic starts here
# Prepping variables to store the results
$dupHash = @{}
$resArr = @()
$all = @()

# Processing the current forest` root domain
Write-Verbose -Message "Getting Admin accounts from $($curForest.RootDomain)"
try
{
    $admOUs = @(Get-ADOrganizationalUnit -Filter {name -like $AdminOUNamePattern} -Server $curForest.RootDomain)
}
catch
{
    Throw "Cannot get OU from the current forest` root domain $($_.Exception.Message)"
}
Write-Verbose -Message "Located $($admOUs.Count) OUs that may contain admin accounts."
foreach ($ou in $admOUs)
{
    Write-Verbose -Message "Querying $($ou.DistinguishedName)"
    try
    {
        $admsTmp = @(Get-ADUser -Filter {AdminCount -eq 1} -SearchBase $($ou.DistinguishedName) -Server $curForest.RootDomain -Properties name,samaccountname,SID,Enabled,LastLogonDate)
        $ccfalg = $true
    }
    catch
    {
        Write-Error "Cannot get accounts $($_.Exception.Message)"
    }
    if ($ccfalg)
    {
        Write-Verbose -Message "Gathered $($admsTmp.Count) accounts from the OU above."
        Write-Verbose -Message "Prepping arguments for the DCSync"
        try { $dc = Get-ADDomainController -Discover -Domain $curForest.RootDomain; $dcflag = $true }
        catch { Write-Error "Cannot get DC name $($_.Exception.Message)" }
        $dname = [string]($curForest.RootDomain).split(".")[0]
        if ($dcflag) 
        {
            foreach ($admt in $admsTmp)
            {
                Write-Output "-------------------------------------------------------------------------------"
                Write-Output "$($admt.name)`t`t$($admt.SID)"
                try 
                {
                    $repdata = Get-ADReplAccount -SamAccountName $admt.samaccountname -Domain $dname -Server $dc.HostName -Protocol TCP
                    $objAverage = New-Object System.Object
                    $objAverage | Add-Member -type NoteProperty -name DN -value $($repdata.DistinguishedName)
                    $objAverage | Add-Member -type NoteProperty -name NTHash -value $(($repdata.NTHash | ConvertTo-Hex) -join "")
                    $objAverage | Add-Member -type ScriptProperty -name LMHash -value {if($repdata.LMHash){($repdata.LMHash | ConvertTo-Hex) -join ""}}
                    $objAverage | Add-Member -type NoteProperty -name ClearText -value $($repdata.SupplementalCredentials.ClearText)
                    $objAverage | Add-Member -type NoteProperty -name Enabled -value $admt.Enabled
                    $objAverage | Add-Member -type NoteProperty -name LastLogonDate -value $admt.LastLogonDate
                    $resArr += $objAverage
                    Clear-Variable -Name objAverage,repdata
                }
                catch { Write-Error "Cannot get rep data $($_.Exception.Message)" }
            }
        }
    }
}

# Processing trusting forests` root domains, it specified so.
if ($ProcessTrustingDomains)
{
    # Trying to get a list of AD trusts in the current AD Forest
    try
    {
        Write-Verbose -Message "Getting trusts."
        $trusts = Get-ADTrust -InputObject $curForest -Properties *
    }
    catch
    {
        throw "Cannot get trusts from $curForest $($_.Exception.Message)"
    }

    # Validating results and forming the forests set
    $trustsRes = New-Object System.Collections.ArrayList
    foreach ($tobj in $trusts)
    {
        if ($tobj.Source -ne $null)
        {
            [void]$trustsRes.Add($tobj)
        }
    }

    # Processing trusting forests` root domains.
    foreach ($trust in $trustsRes)
    {
        Write-Verbose -Message "Getting Admin accounts from $($trust.CN)"
        try
        {
            $admOUs = @(Get-ADOrganizationalUnit -Filter {name -like $AdminOUNamePattern} -Server $trust.CN)
            $sflag = $true
        }
        catch
        {
            Write-Error "Cannot get OU $($_.Exception.Message)"
        }
        if ($sflag)
        {
            Write-Verbose -Message "Located $($admOUs.Count) OUs that may contain admin accounts."
            foreach ($ou in $admOUs)
            {
                Write-Verbose -Message "Querying $($ou.DistinguishedName)"
                try
                {
                    $admsTmp = @(Get-ADUser -Filter {AdminCount -eq 1} -SearchBase $ou.DistinguishedName -Server $trust.CN -Properties name,samaccountname,SID,Enabled,LastLogonDate)
                    $ccfalg = $true
                }
                catch
                {
                    Write-Error "Cannot get accounts $($_.Exception.Message)"
                }
                if ($ccfalg)
                {
                    Write-Verbose -Message "Gathered $($admsTmp.Count) accounts from the OU above."
                    Write-Verbose -Message "Prepping arguments for the DCSync"
                    try { $dc = Get-ADDomainController -Discover -Domain $trust.CN; $dcflag = $true }
                    catch { Write-Error "Cannot get DC name $($_.Exception.Message)" }
                    $dname = [string]($trust.CN).split(".")[0]
                    if ($dcflag) {
                        foreach ($admt in $admsTmp)
                        {
                            Write-Output "-------------------------------------------------------------------------------"
                            Write-Output "$($admt.name)`t`t$($admt.SID)"
                            try {
                                $repdata = Get-ADReplAccount -SamAccountName $admt.samaccountname -Domain $dname -Server $dc.HostName -Protocol TCP
                                $objAverage = New-Object System.Object
                                $objAverage | Add-Member -type NoteProperty -name DN -value $($repdata.DistinguishedName)
                                $objAverage | Add-Member -type NoteProperty -name NTHash -value $(($repdata.NTHash | ConvertTo-Hex) -join "")
                                $objAverage | Add-Member -type ScriptProperty -name LMHash -value {if($repdata.LMHash){($repdata.LMHash | ConvertTo-Hex) -join ""}}
                                $objAverage | Add-Member -type NoteProperty -name ClearText -value $($repdata.SupplementalCredentials.ClearText)
                                $objAverage | Add-Member -type NoteProperty -name Enabled -value $admt.Enabled
                                $objAverage | Add-Member -type NoteProperty -name LastLogonDate -value $admt.LastLogonDate
                                $resArr += $objAverage
                                Clear-Variable -Name objAverage,repdata
                            }
                            catch { Write-Error "Cannot get rep data $($_.Exception.Message)" }
                        }
                    }
                }
            }
        }
    }
}

# Looking for the repeated hashes
Write-Verbose -Message "Checking for the reused passwords."
$uniqueHashes = @($resArr | select NTHash -Unique)
foreach ($hash in $uniqueHashes) {
    $violators = @($resArr | where {$_.NTHash -eq $hash.NTHash})
    if ($violators.count -gt 1) {
        $id = [guid]::NewGuid()
        foreach ($v in $violators) {
            $obj = New-Object System.Object
            $obj | Add-Member -type NoteProperty -Name Time_Stamp -Value $(Get-Date -Format s)
            $obj | Add-Member -type NoteProperty -Name GUID -Value $id.Guid
            $obj | Add-Member -type NoteProperty -name Violation_Type -value "PasswordRe-Use"
            $obj | Add-Member -type NoteProperty -Name Viol_DN -Value $v.DN
            $obj | Add-Member -type NoteProperty -Name Enabled -Value $v.Enabled
            $obj | Add-Member -type NoteProperty -Name LastLogonDate -Value $v.LastLogonDate
            $all += $obj
            Clear-Variable -Name obj
        }
        Clear-Variable -Name id
    }
}
foreach ($i in $resArr) {
    for ($j=([array]::IndexOf($resArr,$i) + 1); $j -lt $resArr.count; $j++) {
        if ($i.NTHash -eq $resArr[$j].NTHash) {
            Write-Verbose -Message "Hash $($i.NTHash) matched: $j"

            if ($dupHash["$($i.NTHash)"]) {
                if ($dupHash["$($i.NTHash)"] -notlike "*$($resArr[$j].DN)*") {
                    Write-Verbose -Message "Adding $($resArr[$j].DN)"
                    $dupHash["$($i.NTHash)"] += "`n$($resArr[$j].DN)"
                }
                else { Write-Verbose -Message "$($resArr[$j].DN) is already added!" }
            }
            else {
                Write-Verbose -Message "`New hash $($i.NTHash) - $($i.DN)"
                $dupHash["$($i.NTHash)"] = "$($i.DN)"
                $dupHash["$($i.NTHash)"] += "`n$($resArr[$j].DN)"
            }
        }
    }
}

# Looking for the clear-text info
Write-Verbose -Message "Checking for the clear-text passwords."
foreach ($i in $resArr) {
    if ($i.ClearText) {
        $id = [guid]::NewGuid()
        $obj | Add-Member -type NoteProperty -Name Time_Stamp -Value $(Get-Date -Format s)
        $obj | Add-Member -type NoteProperty -Name GUID -Value $id.Guid
        $obj | Add-Member -type NoteProperty -name Violation_Type -value "PasswordInClearText"
        $obj | Add-Member -type NoteProperty -Name Viol_DN -Value $i.DN
        $obj | Add-Member -type NoteProperty -Name Enabled -Value $i.Enabled
        $obj | Add-Member -type NoteProperty -Name LastLogonDate -Value $i.LastLogonDate
        $all += $obj
        Clear-Variable -Name obj
    }
}

# Looking for the LMhashes
Write-Verbose -Message "Checking for the LM hashes."
foreach ($i in $resArr) {
    if ($i.LMHash) {
        $id = [guid]::NewGuid()
        $obj | Add-Member -type NoteProperty -Name Time_Stamp -Value $(Get-Date -Format s)
        $obj | Add-Member -type NoteProperty -Name GUID -Value $id.Guid
        $obj | Add-Member -type NoteProperty -name Violation_Type -value "LMHashPresent"
        $obj | Add-Member -type NoteProperty -Name Viol_DN -Value $i.DN
        $obj | Add-Member -type NoteProperty -Name Enabled -Value $i.Enabled
        $obj | Add-Member -type NoteProperty -Name LastLogonDate -Value $i.LastLogonDate
        $all += $obj
        Clear-Variable -Name obj
    }
}

# Saving results
Write-Verbose -Message "Saving results."
try
{
    $all | ft -AutoSize
    [string]$fileName = $OutputFolderPath + "/violations_" + (Get-Date -Format s).Replace(":","_") + ".csv"
    $all | Export-Csv -Path $fileName -NoTypeInformation
    Write-Verbose -Message "All done! Check: $fileName"
}
catch
{
    throw "Cannot save to CSV $($_.Exception.Message)"
}
