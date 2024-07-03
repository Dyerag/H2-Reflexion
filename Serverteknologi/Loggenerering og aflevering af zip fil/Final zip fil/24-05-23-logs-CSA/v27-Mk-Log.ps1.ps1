$Version = "Version 26 19:53 03-04-2022"
# Dette er en Powershell script fil der generere log filer og gemmer dem i en mappe der er dato stemplet
#
# til sidst zipper det scriptet og gemmer det på skrivebordet
# Fejl & Rettelser til oliverblackdk@gmail.com



# flyt den til desktop på Elev-DC1 hklick på den og vælg kør powershell
# under kørsel opretter den et bibliotek der hedder dagsDato og Domain navn
# til sidst zipper descriptet og gemmer det på skrivebordet"
# upload den zippede fil til Itslearning"

#############################################
## Konstanter
## navnet der bruges til at oprette et bibliotek
$dato = (Get-Date -Format "yy-MM-dd")
$desktop = $env:userprofile + '\desktop\'
$Userdomain = $env:userdomain


#Hvor gemmer vi
$DumpDir = $env:userprofile + '\desktop\' + $dato
#'Error handeler' - alle errors bliver supressed
$ErrorActionPreference = 'SilentlyContinue'
#################################################### 
cls
write-host ""
write-host "Dette script opretter ca 30 logfiler "
write-host ""
Write-Host "Det kan tage op til 5 min "
write-Host ""
write-host "Der kan være fejl, det er helt nomalt"
write-host ""
write-host "da scriptet er under udvikling"
write-host ""
write-host ""
write-host ""
write-host "Sørg  for at alle dine Virtuelle maskiner køre "
write-host ""
write-host ""
write-host ""
write-host ""
write-host ""
write-host "$version                 Oliver Black"
write-host ""
write-host ""
#write-host "Sidst ændret af: Malthe Poulsen"
write-host ""
write-host ""
Pause
### vict0081 nu virker tiden ###
# $StartMs = (Get-Date).second
$StartMs = [int](Get-Date -UFormat %s -Millisecond 0);
###

 If (!(Test-Path d:)) 
 { Write-Host "Kan ikke finde Drev D: Ret dit drev navn og kør scriptet igen"
   pause
   exit }

function write-prik           #Skriver en prik på skærmen
{  Write-Host -NoNewline "."}

function write-tilde          #Skriver en tilde på skærmen
{  Write-Host -NoNewline "~"}

Function Test-CommandExists       #Use a PowerShell Function to See If a Command Exists Doctor Scripto Dr Scripto February 19th, 2013
#use   If(Test-CommandExists Get-myService){Get-myService}
{
 Param ($command)
 $oldPreference = $ErrorActionPreference
 $ErrorActionPreference = "stop"
 try {if(Get-Command $command){RETURN $true}}
 #Catch {Write-Host "$command does not exist"; RETURN $false}
 Catch {Write-Host -NoNewline "."; RETURN $false} 
 Finally {$ErrorActionPreference=$oldPreference}
} #end function test-CommandExists

Write-Host -NoNewline 

#opret dir hvis
If (!(Test-Path $DumpDir)) {md $DumpDir}

#Dir D:
Write-Host "Dir-D " #-Nonewline
dir d:\*.* -Recurse | Out-file $DumpDir\Dir-D.txt


cls
Write-Host -NoNewline "Arbejder"

$version | out-file $DumpDir\0000Version.txt

#ADDS i CSV
Write-Host "ADDS i CSV " -Nonewline
csvde -f $DumpDir\csvde-f.csv 



###################################### IGDL  Start ############################################
#Export objectclass=group  og (kolonner member,grouptype,name,whenchanged)
csvde -f $DumpDir\group-1.csv -r "(objectclass=group)" -l member,grouptype,name,whenchanged,description -u

cls
write-host "CSV1"
#But om på rækkefølge af kolonner (grouptype, name, member,whenchanged)
(Import-CSV -Path $DumpDir\group-1.csv -Encoding Unicode ) | Select-Object -Property grouptype, name, member,whenchanged  | Export-CSV -Path $DumpDir\group-2.csv  -encoding utf8
#$env:TEMP\group-2.csv
write-host "CSV2"
#Søg/erstat   GruppeNr til GruppeType
((Get-Content -path $DumpDir\group-2.csv -Raw) -replace '-2147483640','Univesal' -replace '-2147483643','Domain local' -replace '-2147483644','Domain Local' -replace '-2147483646','Global' )     | Set-Content -Path $DumpDir\group-3.csv
write-host "CSV3"
#Fjern CN= OU=   OSV.
((Get-Content -path $DumpDir\group-3.csv -Raw) -replace ',(CN|OU|DC)=([a-zA-Z0-9,=]+)' -replace '(CN=)') | Set-Content -Path $DumpDir\group-4.csv -encoding utf8
write-host "CSV4"
#Fjern Grupper uden medlemmer
Import-Csv $DumpDir\group-4.csv | Where-Object { $_.member  -Match "[a-zA-Z0-9]" } | Export-csv  -Path $DumpDir\group-5.csv -encoding utf8
write-host "CSV3"
#Export til txt
Import-Csv $DumpDir\group-4.csv -encoding utf8 | out-file   $DumpDir\0020group-4.txt
Import-Csv $DumpDir\group-5.csv  -encoding utf8| out-file   $DumpDir\0020group-5.txt
write-host "Group5CSV"

########################################################### IGDL Slut ####################################################



#icacls d:\*.* /t | Out-file $DumpDir\Icacls-D.txt
#write-host ""

#Net user
write-host "Net User"
net user | Out-file $DumpDir\net-user.txt

#Dos Localgroup
write-host "DOS Local Group"
net localgroup | Out-file $DumpDir\net-localgroup.txt 

#Dos Global Group
write-host "DOS Global Group"
net group | Out-file $DumpDir\net-GlobalGroups.txt

write-host "Virtual Hostname"
(get-item "HKLM:\SOFTWARE\Microsoft\Virtual Machine\Guest\Parameters").GetValue("HostName") |out-file $DumpDir\host-name.txt

write-host "IP Config"
ipconfig /all | Out-file $DumpDir\0010-ipconfig.txt

write-host "ARP"
arp -a  | Out-file $DumpDir\arp.txt

#Attrib
write-host "Attrib"
attrib c:\windows\*.* | out-file $DumpDir\Attrib.txt

#Domain controller
write-host "DC Diag"
dcdiag | Out-file $DumpDir\dcdiag.txt

# FSMO
write-host "FSMO"
netdom query fsmo | Out-file $DumpDir\FSMO.txt

#OU
write-host "OU"
Get-ADOrganizationalUnit -Filter 'Name -like "*"' | FT Name, DistinguishedName -A | Out-file $DumpDir\ADOrganizationalUnit.txt

#Group
write-host "AD Group"
Get-ADGroup -Filter 'Name -like "*"' | FT Name, DistinguishedName -A | out-file $DumpDir\ADGroup.txt

#DNS

Write-host "Get-DnsServerZone PTR"
Get-DnsServerZone | Get-DnsServerResourceRecord | where {$_.RecordType -like "PTR"}   | Format-Table -Autosize  | Out-file $DumpDir\0042Get-DnsServerResourceRecord-PTR.txt

Get-DnsServerZone | Get-DnsServerResourceRecord | where {$_.RecordType -like "A"}      | Format-Table -Autosize | Out-file $DumpDir\0043Get-DnsServerResourceRecord-A.txt

Get-DnsServerZone | Get-DnsServerResourceRecord | where {$_.RecordType -like "CNAME"}  | Format-Table -Autosize | Out-file $DumpDir\0044Get-DnsServerResourceRecord-CNAME.txt

Get-DnsServerZone | Get-DnsServerResourceRecord | where {$_.RecordType -like "NS"}    | Format-Table -Autosize  | Out-file $DumpDir\0045Get-DnsServerResourceRecord-NS.txt

Get-DnsServerZone | Get-DnsServerResourceRecord | where {$_.RecordType -like "SRV"}   |  Format-Table -Autosize | Out-file $DumpDir\0046Get-DnsServerResourceRecord-SRV.txt

Get-DnsServerZone | Get-DnsServerResourceRecord | where {$_.RecordType -like "SOA"}  | Format-Table -Autosize | Out-file $DumpDir\0046aGet-DnsServerResourceRecord-SOA.txt

Write-host "Get-DnsServerForwarder"
Get-DnsServerForwarder | Out-file $DumpDir\0047Get-DnsServerForwarder.txt







Write-host "Get-DnsServerZone"
Get-DnsServerZone |Format-Table -Autosize | Out-file $DumpDir\0048Get-DnsServerZone.txt

Write-host "Get-DnsServerResourceRecord"
Get-DnsServerResourceRecord -ZoneName $env:UserDnsDomain | Format-Table -Wrap | Out-file $DumpDir\0048a-Get-DnsServerResourceRecord.txt

#Write-host "Get-DnsServerZone PTR2"
#Get-DnsServerZone | Get-DnsServerResourceRecord | findstr.exe "PTR" |Format-Table -Autosize | Out-file $DumpDir\0041-Get-DnsServerResourceRecord-ptr2.txt

#Write-host "Get-DnsServerZone NOT PTR"
#Get-DnsServerZone | Get-DnsServerResourceRecord | where {$_.RecordType  -notlike "PTR" } | where {$_.recordType -notlike "SRV" } | sort Hostname |Format-Table -Autosize | out-file  $DumpDir\0040-Get-DnsServerRecord.txt
#Write-host "DNS slut"


#Domain Info 
write-host "Get-ADDomain"
Get-ADDomain | Out-file $DumpDir\ADDomain.txt

#Domain Users
write-host "Get-ADUser"
Get-ADUser -Filter * | FT DistinguishedName, name | Out-file $DumpDir\ADUser.txt

#Domain Group's
write-host "AD-Group"
Get-ADGroup -Filter 'Name -like "*"' | FT Name, GroupScope, DistinguishedName -A | Out-file $DumpDir\ADGroup2.txt

#GPO 2 HTML. en rapport for hver gpo
write-host "GPO 2 HTML. en rapport for hver gpo"
Get-GPO -All | % {$_.GenerateReport('html') | Out-File "$DumpDir\Get-GPO_$($_.DisplayName).html"}

#Printer Server
write-host "Printer Server"
Get-Printer | Format-Table -Autosize | Out-file $DumpDir\Get-Printer.txt

write-host "Printer Driver"
Get-PrinterDriver | Format-Table -Autosize | Out-file $DumpDir\Get-PrinterDriver.txt

#OU's
write-host "Get OU"
Get-ADOrganizationalUnit -Filter 'Name -like "*"' | FT Name, DistinguishedName -A | Out-file $DumpDir\ADOrganizationalUnit.txt

#Roles
write-host "Get-WindowsFeature"
Get-WindowsFeature * | where installed | Out-file $DumpDir\WindowsFeature.txt

#Disk
write-host "Disk"
Get-disk | Format-Table | Out-file $DumpDir\disk.txt

#Partition
write-host "Partition"
get-disk | Get-Partition | Format-Table | Out-file $DumpDir\Partition.txt

#Quota 
If(Test-CommandExists Get-FSRMQuota){
  write-host "220 Disk Quota"
  Get-FSRMQuota | Out-file $DumpDir\220-Get-FSRMQuota.txt
  Get-FsrmFileScreen | Out-file $DumpDir\220-Get-FsrmFileScreen.txt
  Get-FsrmFileScreenException | Out-file $DumpDir\220-Get-FsrmFileScreenException.txt
  dir C:\StorageReports\ -Recurse |  Out-file $DumpDir\220-StorageReports.txt
}


#DHCP
If(Test-CommandExists Get-DhcpServerv4Scope) { 
  write-host "DHCP"
  Get-DhcpServerv4Scope | Format-Table -Autosize | Out-file $DumpDir\0050DhcpServerv4Scope.txt 
  Get-DhcpServerv4Scope | select scopeid | ForEach-Object {Get-DhcpServerv4optionValue -scopeID $_.ScopeID } | Format-Table -Autosize | Out-file $DumpDir\0050-DhcpServerv4Scope2.txt
}

#SHARE
write-host "Get-SmbShareAccess"
get-smbshare | Get-SmbShareAccess  | Select-Object name ,accountname, AccessRight | Out-file $DumpDir\0030-Get-SMBshare-SMBShareAccess.txt
#get-smbshare | Get-SmbShareAccess  | Out-file $DumpDir\0034get-smbshare-SmbShareAccess.txt
write-host "Get-SmbShare"
Get-SmbShare  | Select-Object  name,path,FolderEnumerationMode,EncryptData | ft | Out-file $DumpDir\0034-get-smbshare.txt
#Get-SmbShare  | Select-Object  name,path,ShareType,FolderEnumerationMode,EncryptData | Out-file $DumpDir\0034-get-smbshare.txt

#Hotfix
write-host "Hotfix"
hotfix | out-file $DumpDir\hotfix.txt

#Installeret Software
write-host "Installeret Software"
Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Format-Table $AutoSize | Out-file $DumpDir\installed-software.txt

#running services
write-host "running services"
Get-Service | where-object {$_.Status -match "Running"} | Out-file $DumpDir\Get-Service-Running.txt

#Stoped Services
write-host "Stoped Services"
Get-Service | where-object {$_.Status -match "Stopped"} | Out-file $DumpDir\Get-Service-Stopped.txt

#Get-StartApps
write-host "Get-StartApps"
Get-StartApps | Out-file $DumpDir\Get-Start-Apps.txt

#firewall
write-host "Firewall"
Show-NetFirewallRule | Out-file $DumpDir\Show-NetFirewallRule.txt
 
#PSO
write-host "PSO"
Get-ADFineGrainedPasswordPolicy -filter * | out-file $DumpDir\0070-ADFineGrainedPasswordPolicy.txt

#ADDS Recycle Bin 
write-host "Recycle Bin"
Get-ADOptionalFeature -Filter 'name -like "Recycle Bin Feature"' | Out-file $DumpDir\0060-Recycle_Bin_Feature.txt

#Drivere tilføjede efter installation 
write-host "Drivers"
pnputil /enum-drivers | Out-file $DumpDir\pnputil-enum-drivers.txt

#Get-Volume		19:34 10-05-2820
write-host "Volumes"
Get-Volume | Out-file $DumpDir\Get-Volume.txt

#Get-ADComputer		19:37 10-05-2820
write-host "AD Computers"
Get-ADComputer  -filter *  |  Select-Object name,dnshostname | Out-file $DumpDir\Get-ADComputer.txt
#Get-ADComputer -Filter * | Out-file $DumpDir\Get-ADComputer.txt

#repadmin /replsummary		13:19 11-05-2820
write-host "AD Replication"
repadmin /replsummary  | Out-file $DumpDir\0100repadmin-replsummary.txt


#repadmin /showrepl		13:19 11-05-2820
write-host "AD Replication"
repadmin /showrepl  | Out-file $DumpDir\0104repadmin-showrepl.txt


#Get-ComputerInfo		10:16 15-05-2820
write-host "Get-ComputerInfo"
Get-ComputerInfo      | Out-file $DumpDir\Get-ComputerInfo.txt


#Ny ICACLS			12:29 18-05-2820
write-host "ICACLS D:"
If ((Test-Path $DumpDir\icacls-new.txt)) {del $DumpDir\icacls-new.txt}
$d = get-childitem "d:\" -recurse -dir | % { $_.FullName }
foreach ($di in $d ) { Icacls $di | find /V "Successfully processed" >> $DumpDir\0025icacls.txt }


#// Get year and month for csv export file
$DateTime = Get-Date -f "yyyy-MM-dd"

#find crypterede filer på hele d:
write-host "crypt files d "
#cipher find crypterede mapper og filer på drev D:           /s:d:\		11:11 2020-10-23
cipher /s:d:\  | Out-file $DumpDir\cipher.txt


#find alle DHCP reservationer		(G) Output all DHCP reservations to file with PowerShell 08:47 2020-10-23
write-host "DHCP Rresevations"
If(Test-CommandExists Get-DhcpServerv4Scope) { 
  Get-DHCPServerV4Scope | ForEach ($ScopeID) {Get-DHCPServerv4Lease -ScopeID $_.ScopeID}|where {$_.AddressState -like "*Reservation"} | Format-Table -Property ScopeId,IPAddress,HostName,ClientID,AddressState -Autosize > $DumpDir\$env:computername-Reservations.txt
  Get-DhcpServerv4Failover   >    $DumpDir\Get-DhcpServerv4Failover.txt

}


#tag en kopi af msc		
write-host "Copy .msc"
Copy-Item -path $desktop'*.*'  -Destination $Dumpdir\ -Filter *.msc

#tag en kopi af ps1
write-host "copy ps1"
Copy-Item -path $desktop'*.*' -Destination $Dumpdir\ -Filter *.ps1

#tag en kopi af txt
write-host "copy ps1"
Copy-Item -path $desktop'*.*' -Destination $Dumpdir\ -Filter *.txt

#tag en kopi af jpg
write-host "copy ps1"
Copy-Item -path $desktop'*.*' -Destination $Dumpdir\ -Filter *.jpg



#tag en kopi af ps history		
#$env:userprofile
#%userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt.

write-host "ps history"
$ps_history = $env:userprofile + '\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\'
Copy-Item -path $ps_history'*.*' -Destination $Dumpdir\ -Filter *.txt


if ($Error.Count -gt 0)
{#    Write-host "Antal af errors " $Error.Count
#    Write-Host "Error log gemt i " $DumpDir "under navnet ErrorLog"
    $Error | Out-file $DumpDir\ErrorLog.txt}


write-host "Get-Acl-Audit"
$acl = Get-Acl C:\Firma\ -Audit
$acl.Audit | Out-file $DumpDir\Audit.txt


write-host "Get-ICACLS-All-Machines"
$exclude = @('PerfLogs', 'Program Files', 'Program Files (x86)', 'Users', 'Windows')
$computers = Get-ADComputer -Filter 'OperatingSystem -Like "*Server*"'
for ($i = 0; $i -lt $computers.Length; ++$i) {
    Write-Output $computers.DNSHostName[$i] >> $DumpDir\0025icacls.txt
    $session = New-PSSession -ComputerName $computers.DNSHostName[$i]
    $drives = Invoke-Command -Session $session -ScriptBlock { Get-PSDrive | Where-Object { $_.Provider -Like '*FileSystem' } }
    for ($j = 0; $j -lt $drives.Length; ++$j) {
        Write-Output $drives.Root[$j] >> $DumpDir\0025icacls.txt
        [string[]]$roots = Invoke-Command -Session $session -ScriptBlock { param($path, $exclude) Get-ChildItem -Path $path* -Attributes Directory | Where-Object { $exclude -notcontains $_.Name } | % { $_.FullName } } -ArgumentList $drives.Root[$j], $exclude
        $items = @()
        for ($k = 0; $k -lt $roots.Length; ++$k) {
        $items += $roots[$k]
        $items += Invoke-Command -Session $session -ScriptBlock { param($path) (Get-ChildItem -Path $path -Recurse -Attributes Directory, Hidden).FullName } -ArgumentList $roots[$k]
        }
        for ($k = 0; $k -lt $items.Length; ++$k) {
            Invoke-Command -Session $session -ScriptBlock { param($item) ICACLS $item | FIND /V "Successfully processed" } -ArgumentList $items[$k] >> $DumpDir\0025icacls.txt
        }
    }
        Remove-PSSession -Session $session
}

write-host "Get-ipconfig-all-machines"
# Title: Get all ip configurations for machines in a domain.
# Author: Malthe Poulsen
# Version: 1.0
for($i = 0; $i -lt $computers.Length; ++$i) {
	$computername = $computers.DNSHostName[$i]
	$filename = "IPconfig-$($computername).txt"
	$PSSessionOption = New-PSSessionOption -OpenTimeOut 120000
	$session = New-PSSession -ComputerName $computername
	if(Get-PSSession){
		Invoke-Command -Session $session -ScriptBlock { ipconfig /all } >> $DumpDir\$filename
		Remove-PSSession -Session $session
	}
	else {
		Write-Output "We failed to connect: $($computername)"
	}
}


Get-ADComputer -filter *  -Properties whenCreated,IPv4Address,OperatingSystem | Out-file $DumpDir\ADComputers.txt
if (Test-Connection -BufferSize 32 -Count 1 -ComputerName 172.16.0.254 -Quiet) { tracert -d -h 2  -w 3 dr.dk > $DumpDir\Router.txt}
#Test-Connection (Get-NetRoute -DestinationPrefix 0.0.0.0/0 | Select-Object -ExpandProperty Nexthop) -Quiet -Count 1

if ( (Get-WindowsFeature -Name "Windows Server Backup").Installed) { wbadmin get versions > $DumpDir\WBackup.txt}


# "The full pathname of this running script:"
$file = $myinvocation.mycommand.path
dir $file | Out-file $DumpDir\00ScriptID.txt
get-filehash $file >> $DumpDir\00ScriptID.txt


Get-EventLog -LogName Security | Where-Object {$_.EventID -eq 4663} | select -first 20 | Out-file $DumpDir\EventLog-Sec-4663.txt




### vict0081 nu virker tiden ###
#$EndMs = (Get-Date).second
$EndMs = [int](Get-Date -UFormat %s -Millisecond 0);
$RunTime = $EndMs - $StartMs
###

$Runtime | Out-file $DumpDir\000RunTime.txt
############################################################################################## THE END #############################################################
#Zip mappen  O:B:S dette skal være den sidste commando
$dest = $env:userprofile + '\desktop\' + $dato + '-logs-' + $userdomain + '.zip'  
Compress-Archive -Path $DumpDir\* -DestinationPath $dest
### vict0081 sletter mappe, fordi vi kun bruger zip filen ###
#Remove-Item -Path "$DumpDir" -Force 
### 
cls
write-host ""
write-host ""
write-host "Der er oprettet en zip fil der hedder $dest"
Write-Host ""
write-Host ""
Write-Host "Log filerne er gemt i $DumpDir"
write-Host ""
#write-host ""
write-host ""
#write-host ""
write-host ""
write-host ""
write-host "upload den zippede fil til Itslearning, der hvor du hentede scriptet"
write-host ""
write-host ""
write-host "mvh Oliver"
write-host ""
write-host ""
write-host ""
write-host "Run Time seconds  $Runtime"

pause


