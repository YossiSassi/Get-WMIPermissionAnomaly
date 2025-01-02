<#
Hunt for anomalies|excessive permissions|potential backdoors in WMI namepaces.

Run without parameters for localhost, or with -namespace to check a different namespace than the common 'Root\CIMv2' (e.g. 'root\Microsoft\Windows', or 'root\SecurityCenter2').
Use -Computername to remotely query one or more computers/specific hosts (uses RPC).
Specify the switch -GetAllDomainServersViaWinRM to check on all enabled servers in the Active Directory domain (via WinRM).
Note: when specifying -GetAllDomainServersViaWinRM, the Computername parameter is ignored.

Comments: yossis@protonmail.com
v1.0
#>

param (
[cmdletbinding()]
[string]$namespace = "Root\CIMv2",
[string[]]$Computername = ".",
[switch]$GetAllDomainServersViaWinRM
)

# wrap all main functionality as a, well, function :)
function Get-WMIAnomaly {
param(
    [string[]]$Computername = ".",
    [string]$namespace = "Root\CIMv2"
)

# Set function to convert accessMask to actual permission
function Get-WMIPermission {
    param ($AccessMask)
    $permissions = @()

    if ($AccessMask -band 2) { $permissions += 'Execute Methods' }
    if ($AccessMask -band 4) { $permissions += 'Full Write' }
    if ($AccessMask -band 8) { $permissions += 'Partial Write' }
    if ($AccessMask -band 0x10) { $permissions += 'Provider Write' }
    if ($AccessMask -band 1) { $permissions += 'Enable Account' }
    if ($AccessMask -band 0x20) { $permissions += 'Remote Enable' }
    if ($AccessMask -band 0x20000) { $permissions += 'Read Security' }
    if ($AccessMask -band 0x40000) { $permissions += 'Write Security' }
    if ($AccessMask -band 0x100) { $permissions += 'Special Permissions' }
    
    return $permissions -join ', '
}

# Get the SecurityDescriptor for the specific namespace (default: Root\CIMv2)
$Computername | ForEach-Object {
    $CurrentComputer = $_;
    $wmipath = "\\$CurrentComputer\$($namespace):__SystemSecurity";
    $security = ([WMIClass]$wmipath).GetSecurityDescriptor();

    if (!$?) {
        Write-Output "[!] An error occured while getting the SecurityDescriptor on $($CurrentComputer): $($Error[0].Exception.Message)";
        break
    }

    # Convert to human-readable permissions
    $WMIPermissions = $security.Descriptor.DACL | ForEach-Object {
    [PSCustomObject]@{
	    Trustee = $_.Trustee.Name
	    AccessMask = [int]$_.AccessMask
	    Permissions = Get-WMIPermission $_.AccessMask
	    AceType = [int]$_.AceType
	    AceFlags = [int]$_.AceFlags
        Computername = [string]$CurrentComputer
	    }
    }

    # Display permissions
    write-output $WMIPermissions;

    # Hunt filter -> anything that is not the default ROOT permissions
    $WMIAnomalies = $WMIPermissions | where {$($_.AccessMask -ne 19 -and $_.Trustee -ne 'NETWORK SERVICE') -and $($_.AccessMask -ne 19 -and $_.Trustee -ne 'LOCAL SERVICE') -and $($_.AccessMask -ne 19 -and $_.Trustee -ne 'Authenticated Users') -and $($_.AccessMask -ne 393279 -and $_.Trustee -ne 'Administrators')}

    if ($WMIAnomalies)
	    {
		    Write-Output "[!] Potential Excessive Permission Found!`n"
		    write-warning $WMIAnomalies
	    }
    else
	    {
		    Write-Output "[x] No WMIPermissions anomalies found.`n"
	    }
}
}

## Check if switch specified to get ALL enabled online Servers in the domain, and check permissions anomaly via WinRM
if ($GetAllDomainServersViaWinRM)
    {
        # set function for RPC port ping
        function Invoke-PortPing {
        [cmdletbinding()]
        param(
        [string]$ComputerName,
        [int]$Port,
        [int]$Timeout
        )
        ((New-Object System.Net.Sockets.TcpClient).ConnectAsync($ComputerName,$Port)).Wait($Timeout)
        }

        # Map servers in the domain (LDAP / no dependency)
        # Get all enabled Servers

        $ds = New-Object System.DirectoryServices.DirectorySearcher;
        $ds.Filter = "(&(objectClass=computer)(operatingsystem=*server*)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))";
        $ds.PropertiesToLoad.Add("operatingsystem") | Out-Null;
        $ds.PropertiesToLoad.Add("name") | Out-Null;
        $Servers = $ds.FindAll().Properties.name;

        Write-Output "[x] Checking $($Servers.Count) Servers in the domain...";

        # Check connectivity (Servers are online) through port ping to WinRM, assuming servers are open with WinRM server 2012+ at default port 5985 in Domain environment
        [int]$Port = 5985;
        [int]$Timeout = 250; # set timeout in milliseconds. normally 100ms should be fine, taking extra response time here
        [int]$i = 1;
        [int]$HostCount = $Servers.count;

        $ServersPostPing = New-Object System.Collections.ArrayList;

        $Servers | ForEach-Object {
                $Computer = $_;
                Write-Progress -Activity "Testing for WinRM port connectivity..." -status "host $i of $HostCount" -percentComplete ($i / $HostCount*100);
                if ((Invoke-PortPing -ComputerName $Computer -Port $port -Timeout $timeout -ErrorAction silentlycontinue) -eq "True") {$null = $ServersPostPing.Add($Computer)}
                $i++;
            }

         Write-Output "[x] $($ServersPostPing.Count) Servers responded to connectivity check."; 

         # clear current background jobs
         Get-Job | Remove-Job -Force
         
         # launch jobs in parallel
         $null = Invoke-Command -ScriptBlock ${Function:Get-WMIAnomaly} -ComputerName $ServersPostPing -AsJob
         
         # wait for jobs to finish
         Write-Host "waiting for jobs to complete..." -ForegroundColor Cyan;
         $null = Get-Job | Wait-Job

         # analyze jobs
         $RemoteJobs = Get-Job -IncludeChildJob | where psjobtypename -ne "RemoteJob";
         # show if any jobs contain anomalies
         $RemoteJobs | Foreach-Object {if ($_ | Receive-Job -Keep -ea SilentlyContinue | select-string 'potential excessive' ) {$_.location}}
    }
else
    {
    Get-WMIAnomaly -Computername $Computername -namespace $namespace
}