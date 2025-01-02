# Get-WMIPermissionAnomaly
Hunt for anomalies | excessive permissions | potential backdoors in WMI namepaces.
<br><br>
<b>*The research concept:*</b><br>
 <p>&#x1F608</p> As a red teamer, why would you add yourself to a privileged group, such a noisy and monitored activity?<br>rather, adversaries can add permissions to specific APIs/namespaces/classes and achieve remote code execution, going fairly under the radar...<br><br>
<p>&#x1F607</p> This script helps defenders map & identify such a 'creative' backdoor, which is applying DIRECT execute/remote enable permissions on WMI namespaces.
<br><br>
<b>Parameters:</b> <br>
- Run without parameters for localhost, or,-
- Use the -namespace parameter to check a different namespace than the common 'Root\CIMv2' (e.g. 'root\Microsoft\Windows', or 'root\SecurityCenter2').
- Use the -Computername parameter to remotely query one or more computers/specific hosts (uses RPC).
- Specify the switch -GetAllDomainServersViaWinRM to check on all enabled servers in the Active Directory domain (via WinRM).<br>
Note: when specifying -GetAllDomainServersViaWinRM, the Computername parameter is ignored.
