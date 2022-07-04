<#
PCI.ps1 - a PowerShell script for checking system security
            when conducting an assessment of systems where
            the Microsoft Policy Analyzer and other assessment
            tools cannot be installed.
#>

<#
License: 
Telefonica tech
 
PCI.ps1 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.
 

#>
########## Output Header Write-Host Functions ##############
# Postive Outcomes - configurations / settings that are, at a minimum, expected.
$pos_str = "   [+] "
$neg_str = "   [-] "
$inf_str = "[*] "
$rep_str = "[$] "
$err_str = "[x] "
$cumple = "  .... CUMPLE"
$no_cumple = "  .... **NO CUMPLE**"
###############################

########## Create storage directory for files in users Temp directory at $env:temp ##############
$PCI_dest = "PCI-hardening-$(get-date -f yyyyMMdd-hhmmss)"
#New-Item -ItemType directory -Path C:\Users\zj901513\OneDrive' - 'Telefonica\Documents\plantillas_hardening_ms\Scripts\$PCI_dest
#$out_file = "C:\Users\zj901513\OneDrive - Telefonica\Documents\plantillas_hardening_ms\Scripts\$PCI_dest\$Env:ComputerName-PCI.txt"
#$sysinfo_file = "C:\Users\zj901513\OneDrive - Telefonica\Documents\plantillas_hardening_ms\Scripts\$PCI_dest\$Env:Computername-sysinfo.txt"
$out_file = "C:\Temp\ansible-PCI\$Env:ComputerName-PCI.txt"
$sysinfo_file = "C:\Temp\ansible-PCI\$Env:Computername-sysinfo.txt"
###############################

########### Gather System Info #############
$inf_str +  "Dumping System Info to seperate file\n" | Tee-Object -FilePath $out_file -Append
systeminfo  | Tee-Object -FilePath $sysinfo_file -Append
###############################

########## Check for Windows Information ##############
$inf_str + "Windows Version: $(([Environment]::OSVersion).VersionString)" | Tee-Object -FilePath $out_file -Append
$inf_str + "Windows Default Path for $env:Username : $env:Path" | Tee-Object -FilePath $out_file -Append

$inf_str + "Checking IPv4 Network Settings"
Try{
    $ips = (Get-NetIPAddress | Where AddressFamily -eq 'IPv4' | Where IPAddress -ne '127.0.0.1').IPAddress
    if ($ips -ne $null){
        foreach ($ip in $ips){
            if ($ip -ne $null){
                #$inf_str + "Host network interface assigned:" $ip
                $inf_str + "Host network interface assigned: $ip" | Tee-Object -FilePath $out_file -Append
            }
        }
    }else{
        # Use Throw function to call the Catch function
        Throw('Get-NetIPAddress error') | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    Try{
        $ips = (gwmi win32_networkadapterconfiguration -filter 'ipenabled=true')
        if ($ips -ne $null){
            foreach ($ip in $ips){
                if ($ip -ne $null){
                    foreach ($i in $ip.IPAddress){
                        if ($i -notmatch ":"){
                            $inf_str + "Host network interface assigned (gwmi): $i" | Tee-Object -FilePath $out_file -Append
                        }
                    }
                }
            }
        } else {
            # Use Throw function to call the Catch function
            Throw('gwmi win32_networkadapterconfiguration error') | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        $err_str + "Check IPv4 Network Settings failed." | Tee-Object -FilePath $out_file -Append
    }
}
Write-Host " "
Write-Host " "
Write-Host " "
Write-Host "+-----------------------------------------------------------------------------+"
Write-Host "|                         ~~~ Configuracion de Firewall ~~~                   |"
Write-Host "+----+------+-----------------------------------------------------------------+"


$inf_str + "Testing if Windows Firewall Domain status." | Tee-Object -FilePath $out_file -Append
Try{
    $resfw =  netsh advfirewall show domain state
    #foreach ($r in $resfw){
        if ($r.Enabled -eq 'False'){
            $pos_str + "Windows Firewall Domain is disabled." | Tee-Object -FilePath $out_file -Append
            Write-Host " "
        } else {
            $neg_str + "Windows Firewall Domain is enabled." | Tee-Object -FilePath $out_file -Append
			Write-Host " "
        }
    #}
}
Catch{
    $err_str + "Testing if Windows Firewall Domain failed." | Tee-Object -FilePath $out_file -Append
}



$inf_str + "Testing if Windows Firewall Private status." | Tee-Object -FilePath $out_file -Append
Try{
    $resfw =  netsh advfirewall show private state
    #foreach ($r in $resfw){
        if ($r.Enabled -eq 'False'){
            $pos_str + "Windows Firewall Private is disabled." | Tee-Object -FilePath $out_file -Append
			Write-Host " "
        } else {
            $neg_str + "Windows Firewall Private is enabled." | Tee-Object -FilePath $out_file -Append
			Write-Host " "
        }
    #}
}
Catch{
    $err_str + "Testing if Windows Firewall Private failed." | Tee-Object -FilePath $out_file -Append
}

$inf_str + "Testing if Windows Firewall Public status." | Tee-Object -FilePath $out_file -Append
Try{
    $resfw =  netsh advfirewall show public state
    #foreach ($r in $resfw){
        if ($r.Enabled -eq 'False'){
            $pos_str + "Windows Firewall Public is disabled." | Tee-Object -FilePath $out_file -Append
			Write-Host " "
        } else {
            $neg_str + "Windows Firewall Public is enabled." | Tee-Object -FilePath $out_file -Append
			Write-Host " "
        }
    #}
}
Catch{
    $err_str + "Testing if Windows Firewall Public failed." | Tee-Object -FilePath $out_file -Append
}

Write-Host " "
Write-Host "+-----------------------------------------------------------------------------+"
Write-Host "|               ~~~ Contrasenias y parametros por defecto ~~~                 |"
Write-Host "+----+------+-----------------------------------------------------------------+"

$inf_str + "Verify if Administrator Account Status is Disabled." | Tee-Object -FilePath $out_file -Append
Try{
    $resfw =  Get-LocalUser -Name Administrador | select *
    foreach ($r in $resfw){
	   if ($r.Enabled -eq 'False'){
            $pos_str + "Administrador Account is enable." | Tee-Object -FilePath $out_file -Append
			$neg_str + "Disabling Administrador Account." | Tee-Object -FilePath $out_file -Append
			net user administrador /active:no | Tee-Object -FilePath $out_file -Append
			Write-Host " "
        } else {
            $neg_str + "Administrador Account is disabled." | Tee-Object -FilePath $out_file -Append
			Write-Host " "
        }
		
    }
}
Catch{
    $err_str + "Testing if Antivirus software failed." | Tee-Object -FilePath $out_file -Append
}
Write-Host " "

$inf_str + "Testing if WinRM Service is running." | Tee-Object -FilePath $out_file -Append
Try{
    if (Test-WSMan -ErrorAction Stop) { 
        $neg_str + "WinRM Services is running and may be accepting connections: Test-WSMan check."  | Tee-Object -FilePath $out_file -Append
    } else { 
        $pos_str + "WinRM Services is not running: Test-WSMan check."  | Tee-Object -FilePath $out_file -Append
    }   
}
Catch{
    Try{
        $ress = (Get-Service WinRM).status
        if ($ress -eq 'Stopped') { 
            $pos_str + "WinRM Services is not running: Get-Service check."  | Tee-Object -FilePath $out_file -Append
        } else { 
            $neg_str + "WinRM Services is running and may be accepting connections: Get-Service check."  | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        $err_str + "Testing if WimRM Service is running failed." | Tee-Object -FilePath $out_file -Append
    }
}

Write-Host " "
$inf_str + "Testing if PowerShell EnableScriptBlockLogging is Enabled" | Tee-Object -FilePath $out_file -Append
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging){
        $pos_str + "EnableScriptBlockLogging Is Enabled, This must be disabled" | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "EnableScriptBlockLogging Is Disabled" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).EnableScriptBlockLogging){
            $pos_str + "EnableScriptBlockLogging Is Enabled, This must be disabled" | Tee-Object -FilePath $out_file -Append
        } else {
            $neg_str + "EnableScriptBlockLogging Is Disabled" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        $err_str + "Testing PowerShell EnableScriptBlockLogging failed" | Tee-Object -FilePath $out_file -Append
    }
}
Write-Host " "

$inf_str + "Testing if PowerShell EnableTranscripting is Enabled" | Tee-Object -FilePath $out_file -Append
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).EnableTranscripting){
        $pos_str + "EnableTranscripting Is Enabled" | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "EnableTranscripting Is Disabled" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\Transcription' -ErrorAction SilentlyContinue).EnableTranscripting){
            $pos_str + "EnableTranscripting Is Enabled" | Tee-Object -FilePath $out_file -Append
        } else {
            $neg_str + "EnableTranscripting Is Disabled" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        $err_str + "Testing PowerShell EnableTranscripting failed" | Tee-Object -FilePath $out_file -Append
    }
}
Write-Host " "

Write-Host " "
#Validate Spynet
$inf_str + "Testing if Spynet Reporting is Disabled" | Tee-Object -FilePath $out_file -Append
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).SpyNetReporting){
        $pos_str + "Spynet Reporting Is Enabled, This must be disabled" | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "Spynet Reporting is Disabled" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\SOFTWARE\Wow6432Node\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' -ErrorAction SilentlyContinue).SpyNetReporting){
            $pos_str + "Spynet Reporting  Is Enabled, This must be disabled" | Tee-Object -FilePath $out_file -Append
        } else {
            $neg_str + "Spynet Reporting Is Disabled" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        $err_str + "Testing PowerShell Spynet Reporting failed" | Tee-Object -FilePath $out_file -Append
    }
}
Write-Host " "

Write-Host " "
#Validate App notification in the Lock Screen
$inf_str + "Testing if App notificacion is Enabled" | Tee-Object -FilePath $out_file -Append
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\System\' -ErrorAction SilentlyContinue).DisableLockScreenAppNotifications){
        $pos_str + "App notification Is Enabled" | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "App notification is Disabled" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows\System\' -ErrorAction SilentlyContinue).DisableLockScreenAppNotifications){
            $pos_str + "App notification  Is Enabled, This must be disabled" | Tee-Object -FilePath $out_file -Append
        } else {
            $neg_str + "App notification Is Disabled" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        $err_str + "Testing PowerShell App notification failed" | Tee-Object -FilePath $out_file -Append
    }
}
Write-Host " "

###############################
# Untrusted Fonts
###############################
# Block Untrusted Fonts
<#
Resources:
    Block untrusted fonts in an enterprise: https://docs.microsoft.com/en-us/windows/security/threat-protection/block-untrusted-fonts-in-enterprise
    How to Verify if Device Guard is Enabled or Disabled in Windows 10: https://www.tenforums.com/tutorials/68926-verify-if-device-guard-enabled-disabled-windows-10-a.html
#>

if ([System.Environment]::OSVersion.Version.Major -eq 10){
    $inf_str + "Testing if Untrusted Fonts are disabled using the Kernel MitigationOptions." | Tee-Object -FilePath $out_file -Append
    Try{
        $resuf = (Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Kernel\').MitigationOptions
        if ($resuf -eq $null){
            $neg_str + "Kernel MitigationOptions key does not exist." | Tee-Object -FilePath $out_file -Append
        } else {
            if ($ressh -ge 2000000000000){
                $neg_str + "Kernel MitigationOptions key is configured not to block: $resuf" | Tee-Object -FilePath $out_file -Append
            } else {
                $pos_str + "Kernel MitigationOptions key is set to block: $resuf" | Tee-Object -FilePath $out_file -Append
            }
        }
    }
    Catch{
        $err_str + "Testing for Untrusted Fonts configuration failed." | Tee-Object -FilePath $out_file -Append
    }
} else {
    $inf_str + "Windows Version is not 10. Cannot test for Untrusted Fonts." | Tee-Object -FilePath $out_file -Append
}
Write-Host " "
###############################
# Disable WDigest
###############################
# Ensure WDigest is disabled

$inf_str + "Testing if WDigest is disabled."
Try{
    $reswd = (Get-ItemProperty -path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest').UseLogonCredential
    if ($reswd -eq $null){
        $neg_str + "WDigest UseLogonCredential key does not exist." | Tee-Object -FilePath $out_file -Append
    } else {
        if ($reswd){
            $neg_str + "WDigest UseLogonCredential key is Enabled: $reswd" | Tee-Object -FilePath $out_file -Append
        } else {
            $pos_str + "WDigest UseLogonCredential key is Disabled: $reswd" | Tee-Object -FilePath $out_file -Append
        }
    }
}
Catch{
    $err_str + "Testing for WDigest failed." | Tee-Object -FilePath $out_file -Append
}

Write-Host " "
#Validate if Downloading of Print Drivers over HTTP is Disabled
$inf_str + "Testing if Turn off Downloading of Print Drivers over HTTP is Enabled" | Tee-Object -FilePath $out_file -Append
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\' -ErrorAction SilentlyContinue).DisableWebPnPDownload){
        $pos_str + "Turn off Downloading of Print Drivers over HTTP Is Enabled" | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "Turn off Downloading of Print Drivers over HTTP is Disabled" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows NT\Printers\' -ErrorAction SilentlyContinue).DisableWebPnPDownload){
            $pos_str + "Turn off Downloading of Print Drivers over HTTP Is Enabled" | Tee-Object -FilePath $out_file -Append
        } else {
            $neg_str + "Turn off Downloading of Print Drivers over HTTP is Disabled" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        $err_str + "Turn off Downloading of Print Drivers over HTTP failed" | Tee-Object -FilePath $out_file -Append
    }
}
Write-Host " "

Write-Host " "
Write-Host "+-----------------------------------------------------------------------------+"
Write-Host "|               ~~~ Transmision de datos en redes publicas ~~~                |"
Write-Host "+----+------+-----------------------------------------------------------------+"

$inf_str + "Verifyng if Secure RPC Communication is enabled" | Tee-Object -FilePath $out_file -Append
Try{
    if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'  -ErrorAction SilentlyContinue).fEncryptRPCTraffic){
        $pos_str + "EncryptRPCTraffic Is Enabled, This must be Disabled" | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "EncryptRPCTraffic Is Disabled" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    Try{
        if ([bool](Get-ItemProperty -path 'HKLM:\Software\Policies\Microsoft\Windows NT\Terminal Services'  -ErrorAction SilentlyContinue).fEncryptRPCTraffic){
            $pos_str + "EncryptRPCTraffic Is Enabled, This must be Disabled" | Tee-Object -FilePath $out_file -Append
        } else {
            $neg_str + "EncryptRPCTraffic Is Disabled" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        $err_str + "Testing PowerShell EncryptRPCTraffic failed" | Tee-Object -FilePath $out_file -Append
    }
}
Write-Host " "
Write-Host "+-----------------------------------------------------------------------------+"
Write-Host "|                 ~~~ Programas o software Antivirus ~~~                      |"
Write-Host "+----+------+-----------------------------------------------------------------+"

$inf_str + "Verify is Anti-virus software is installed, Up to date and Running correctly." | Tee-Object -FilePath $out_file -Append
Try{
    $resfw =  Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct
    foreach ($r in $resfw){
		$pos_str + "Name: " + $r.displayName | Tee-Object -FilePath $out_file -Append
		$pos_str + "Up to date: "+$r.timestamp | Tee-Object -FilePath $out_file -Append
		$pos_str + "State: "+$r.productState | Tee-Object -FilePath $out_file -Append
		Write-Host " "
		
    }
}
Catch{
    $err_str + "Testing if Antivirus software failed." | Tee-Object -FilePath $out_file -Append
}


Write-Host " "
Write-Host "+-----------------------------------------------------------------------------+"
Write-Host "|                ~~~ Sistemas y aplicaciones seguras ~~~                      |"
Write-Host "+----+------+-----------------------------------------------------------------+"

$inf_str + "Checking Windows AutoUpdate Configuration" | Tee-Object -FilePath $out_file -Append
# Check Auto Update Configuration
$AutoUpdateNotificationLevels= @{0="Not configured"; 1="Disabled" ; 2="Notify before download"; 3="Notify before installation"; 4="Scheduled installation"}
Try{
    $resa = ((New-Object -com "Microsoft.Update.AutoUpdate").Settings).NotificationLevel
    if ( $resa -eq 4){
        $pos_str + "Windows AutoUpdate is set to $resa :" + $AutoUpdateNotificationLevels.$resa | Tee-Object -FilePath $out_file -Append
    } else {
        $neg_str + "Windows AutoUpdate is not configuration to automatically install updates: $resa : $AutoUpdateNotificationLevels.$resa" | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Windows AutoUpdate test failed." | Tee-Object -FilePath $out_file -Append
}
Write-Host " "
Write-Host "+-----------------------------------------------------------------------------+"
Write-Host "|                ~~~ Restriccion de acceso a datos ~~~                        |"
Write-Host "+----+------+-----------------------------------------------------------------+"

$inf_str + "Testing Local Administrator Accounts." | Tee-Object -FilePath $out_file -Append
Try{
    $numadmin = (Get-LocalGroupMember -Group "Administrators" -ErrorAction Stop).Name.count
    if ([int]$numadmin -gt 1){
        $neg_str + "More than one account is in local Administrators group: $numadmin" | Tee-Object -FilePath $out_file -Append
    } else {
        $pos_str + "One account in local Administrators group." | Tee-Object -FilePath $out_file -Append
    }

    foreach ($n in (Get-LocalGroupMember -Group "Administrators").Name) {
        $inf_str + "Account in local Administrator group: $n" | Tee-Object -FilePath $out_file -Append
    }
}
# No PS Cmdlet, use net command
Catch [System.InvalidOperationException]{
    $netout = (net localgroup Administrators)
    foreach ($item in $netout){
        if ($item -match '----') {
            $index = $netout.IndexOf($item)
        }
    }

    $numadmin = $netout[($index + 1)..($netout.Length - 3)]
    if ($content.length -gt 1){
        $neg_str + "More than one account is in local Administrators group: $numadmin.length" | Tee-Object -FilePath $out_file -Append
    } else {
        $pos_str + "One account in local Administrators group." | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing local Administrator Accounts failed." | Tee-Object -FilePath $out_file -Append
}

Write-Host " "
# Restrict Anonymous Enumeration
$inf_str + "Testing Domain and Local Anonymous Enumeration settings: RestrictAnonymous." | Tee-Object -FilePath $out_file -Append
Try{
    $resra = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\').RestrictAnonymous 
    if ($resra -eq $null){
        $neg_str + "RestrictAnonymous registry key is not configured." | Tee-Object -FilePath $out_file -Append
    } else {
        if ($resra){
            $pos_str + "RestrictAnonymous registry key is configured: $resra" | Tee-Object -FilePath $out_file -Append
        } else {        
            $neg_str + "RestrictAnonymous registry key is not configured: $resra" | Tee-Object -FilePath $out_file -Append
        }   
    }
}
Catch{
    $err_str + "Testing for Anonymous Enumeration RestrictAnonymous failed." | Tee-Object -FilePath $out_file -Append
}

$inf_str + "Testing Domain and Local Anonymous Enumeration settings: RestrictAnonymoussam" | Tee-Object -FilePath $out_file -Append
Try{
    $resras = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\').RestrictAnonymoussam 
    if ($resras -eq $null){
        $neg_str + "RestrictAnonymoussam registry key is not configured." | Tee-Object -FilePath $out_file -Append
    } else {
        if ($resras){
            $pos_str + "RestrictAnonymoussam registry key is configured: $resras" | Tee-Object -FilePath $out_file -Append
        } else {        
            $neg_str + "RestrictAnonymoussam registry key is not configured: $resras" | Tee-Object -FilePath $out_file -Append
        }   
    }
}
Catch{
    $err_str + "Testing for Anonymous Enumeration RestrictAnonymoussam failed." | Tee-Object -FilePath $out_file -Append
}


Write-Host " "
#Validate Let Windows Apps Access are Force DENY
$inf_str + "Testing if Windows apps access account information is Force DENY" | Tee-Object -FilePath $out_file -Append
Try{
	 $reswapp = (Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessAccountInfo
	 if ($reswapp -eq $null){
            $neg_str + "Windows apps access account information key does not exist."  + $cumple | Tee-Object -FilePath $out_file -Append
        } 
	else {
		if ([bool](Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessAccountInfo){
			$pos_str + "Windows apps access account information is Force DENY"   + $cumple  | Tee-Object -FilePath $out_file -Append
			} else {
			$neg_str + "Windows apps access account information is NOT Force DENY"   + $no_cumple | Tee-Object -FilePath $out_file -Append
			}
		}
}
 Catch{
        $err_str + "Power Shell for Windows apps access account information is Force DENY  failed" | Tee-Object -FilePath $out_file -Append
    }

Write-Host " "
Write-Host " "
#Validate Let Windows access call history are Force DENY
$inf_str + "Testing if Windows apps access call history is Force DENY" | Tee-Object -FilePath $out_file -Append
Try{
	 $reswapp = (Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).	LetAppsAccessCallHistory
	 if ($reswapp -eq $null){
            $neg_str + "Windows apps aaccess call history key does not exist."  + $cumple  | Tee-Object -FilePath $out_file -Append
        } 
	else {
		if ([bool](Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).	LetAppsAccessCallHistory){
			$pos_str + "Windows apps access call history is Force DENY"  + $cumple  | Tee-Object -FilePath $out_file -Append
			} else {
			$neg_str + "Windows apps access call history is NOT Force DENY"  + $no_cumple| Tee-Object -FilePath $out_file -Append
			}
		}
}
 Catch{
        $err_str + "Power Shell for Windows apps access call history is Force DENY  failed" | Tee-Object -FilePath $out_file -Append
    }
Write-Host " "

Write-Host " "
#Validate Let Windows Apps Access contacts are Force DENY
$inf_str + "Testing if Windows apps access contacts  is Force DENY" | Tee-Object -FilePath $out_file -Append
Try{
	 $reswapp = (Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessContacts
	 if ($reswapp -eq $null){
            $neg_str + "Windows apps access contacts  key does not exist."  + $cumple | Tee-Object -FilePath $out_file -Append
        } 
	else {
		if ([bool](Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessContacts){
			$pos_str + "Windows apps access contacts  is Force DENY"  + $cumple  | Tee-Object -FilePath $out_file -Append
			} else {
			$neg_str + "Windows apps access contacts  is NOT Force DENY"  + $no_cumple| Tee-Object -FilePath $out_file -Append
			}
		}
}
 Catch{
        $err_str + "Power Shell for Windows apps access contacts is Force DENY  failed" | Tee-Object -FilePath $out_file -Append
    }
Write-Host " "

Write-Host " "
#Validate Let Windows Apps access location is Force DENY
$inf_str + "Testing if Windows apps access location is Force DENY" | Tee-Object -FilePath $out_file -Append
Try{
	 $reswapp = (Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessLocation
	 if ($reswapp -eq $null){
            $neg_str + "Windows apps access account information key does not exist." + $cumple  | Tee-Object -FilePath $out_file -Append
        } 
	else {
		if ([bool](Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessLocation){
			$pos_str + "Windows apps access location is Force DENY"  + $cumple | Tee-Object -FilePath $out_file -Append
			} else {
			$neg_str + "Windows apps access location is NOT Force DENY"  + $no_cumple | Tee-Object -FilePath $out_file -Append
			}
		}
}
 Catch{
        $err_str + "Power Shell for Windows apps access location is Force DENY  failed" | Tee-Object -FilePath $out_file -Append
    }
Write-Host " "

Write-Host " "
#Validate Let Windows Apps Access Email is Force DENY
$inf_str + "Testing if Windows apps access email is Force DENY" | Tee-Object -FilePath $out_file -Append
Try{
	 $reswapp = (Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessEmail
	 if ($reswapp -eq $null){
            $neg_str + "Windows apps access email key does not exist."  + $cumple  | Tee-Object -FilePath $out_file -Append
        } 
	else {
		if ([bool](Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessEmail){
			$pos_str + "Windows apps access email is Force DENY" + $cumple  | Tee-Object -FilePath $out_file -Append
			} else {
			$neg_str + "Windows apps access email is NOT Force DENY"  + $no_cumple | Tee-Object -FilePath $out_file -Append
			}
		}
}
 Catch{
        $err_str + "Power Shell for Windows apps access email is Force DENY  failed" | Tee-Object -FilePath $out_file -Append
    }
Write-Host " "

Write-Host " "
#Validate Let Windows Apps Access Messaging are Force DENY
$inf_str + "Testing if Windows apps Access Messaging is Force DENY" | Tee-Object -FilePath $out_file -Append
Try{
	 $reswapp = (Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessAccountInfo
	 if ($reswapp -eq $null){
            $neg_str + "Windows Access Messaging key does not exist." + $cumple | Tee-Object -FilePath $out_file -Append
        } 
	else {
		if ([bool](Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessAccountInfo){
			$pos_str + "Windows apps Access Messaging is Force DENY  + $cumple" | Tee-Object -FilePath $out_file -Append
			} else {
			$neg_str + "Windows apps Access Messaging is NOT Force DENY + $no_cumple" | Tee-Object -FilePath $out_file -Append
			}
		}
}
 Catch{
        $err_str + "Power Shell for Windows Access Messaging is Force DENY  failed" | Tee-Object -FilePath $out_file -Append
    }
Write-Host " "

Write-Host " "
#Validate Let Windows Apps Access Motion are Force DENY
$inf_str + "Testing if Windows apps Access Motion is Force DENY" | Tee-Object -FilePath $out_file -Append
Try{
	 $reswapp = (Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessAccountInfo
	 if ($reswapp -eq $null){
            $neg_str + "Windows apps Access Motion key does not exist.  + $cumple" | Tee-Object -FilePath $out_file -Append
        } 
	else {
		if ([bool](Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessAccountInfo){
			$pos_str + "Windows apps Access Motion is Force DENY  + $cumple" | Tee-Object -FilePath $out_file -Append
			} else {
			$neg_str + "Windows apps Access Motion is NOT Force DENY  + $no_cumple" | Tee-Object -FilePath $out_file -Append
			}
		}
}
 Catch{
        $err_str + "Power Shell for Windows apps Access Motion is Force DENY  failed" | Tee-Object -FilePath $out_file -Append
    }
Write-Host " "

Write-Host " "
#Validate Let Windows Apps Access Notifications are Force DENY
$inf_str + "Testing if Windows apps Access Notifications is Force DENY" | Tee-Object -FilePath $out_file -Append
Try{
	 $reswapp = (Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessAccountInfo
	 if ($reswapp -eq $null){
            $neg_str + "Windows apps Access Notifications key does not exist.  + $cumple" | Tee-Object -FilePath $out_file -Append
        } 
	else {
		if ([bool](Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessAccountInfo){
			$pos_str + "Windows apps Access Notifications is Force DENY  + $cumple" | Tee-Object -FilePath $out_file -Append
			} else {
			$neg_str + "Windows apps Access Notifications is NOT Force DENY + $no_cumple" | Tee-Object -FilePath $out_file -Append
			}
		}
}
 Catch{
        $err_str + "Power Shell for Windows apps Access Notifications is Force DENY  failed" | Tee-Object -FilePath $out_file -Append
    }
Write-Host " "



Write-Host " "
#Validate Let Windows Apps Access the Calendar are Force DENY
$inf_str + "Testing if Windows apps Access the Calendar is Force DENY" | Tee-Object -FilePath $out_file -Append
Try{
	 $reswapp = (Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessAccountInfo
	 if ($reswapp -eq $null){
            $neg_str + "Windows apps Access the Calendar key does not exist.  + $cumple" | Tee-Object -FilePath $out_file -Append
        } 
	else {
		if ([bool](Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessAccountInfo){
			$pos_str + "Windows apps Access the Calendar is Force DENY  + $cumple" | Tee-Object -FilePath $out_file -Append
			} else {
			$neg_str + "Windows apps Access the Calendar is NOT Force DENY + $no_cumple" | Tee-Object -FilePath $out_file -Append
			}
		}
}
 Catch{
        $err_str + "Power Shell for Windows apps Access the Calendar is Force DENY  failed" | Tee-Object -FilePath $out_file -Append
    }
Write-Host " "



Write-Host " "
#Validate Let Windows Apps Access the Camera are Force DENY
$inf_str + "Testing if Windows apps Access the Camera is Force DENY" | Tee-Object -FilePath $out_file -Append
Try{
	 $reswapp = (Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessAccountInfo
	 if ($reswapp -eq $null){
            $neg_str + "Windows apps Access the Camera key does not exist."  + $cumple | Tee-Object -FilePath $out_file -Append
        } 
	else {
		if ([bool](Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessAccountInfo){
			$pos_str + "Windows apps Access the Camera is Force DENY"  + $cumple | Tee-Object -FilePath $out_file -Append
			} else {
			$neg_str + "Windows apps Access the Camera is NOT Force DENY" + $no_cumple | Tee-Object -FilePath $out_file -Append
			}
		}
}
 Catch{
        $err_str + "Power Shell for Windows apps Access the Camera is Force DENY  failed" | Tee-Object -FilePath $out_file -Append
    }
Write-Host " "



Write-Host " "
#Validate Let Windows Apps Access the Microphone are Force DENY
$inf_str + "Testing if Windows apps Access the Microphone is Force DENY" | Tee-Object -FilePath $out_file -Append
Try{
	 $reswapp = (Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessAccountInfo
	 if ($reswapp -eq $null){
            $neg_str + "Windows apps Access the Microphone key does not exist." + $cumple | Tee-Object -FilePath $out_file -Append
        } 
	else {
		if ([bool](Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessAccountInfo){
			$pos_str + "Windows apps Access the Microphone is Force DENY"  + $cumple | Tee-Object -FilePath $out_file -Append
			} else {
			$neg_str + "Windows apps Access the Microphone is NOT Force DENY" + $no_cumple | Tee-Object -FilePath $out_file -Append
			}
		}
}
 Catch{
        $err_str + "Power Shell for Windows apps Access the Microphone is Force DENY  failed" | Tee-Object -FilePath $out_file -Append
    }
Write-Host " "


Write-Host " "
#Validate Let Windows Apps Access Trusted Devices are Force DENY
$inf_str + "Testing if Windows apps Access Trusted Devices is Force DENY" | Tee-Object -FilePath $out_file -Append
Try{
	 $reswapp = (Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessAccountInfo
	 if ($reswapp -eq $null){
            $neg_str + "Windows apps Access Trusted Devices key does not exist."  + $cumple | Tee-Object -FilePath $out_file -Append
        } 
	else {
		if ([bool](Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessAccountInfo){
			$pos_str + "Windows apps Access Trusted Devices is Force DENY"  + $cumple | Tee-Object -FilePath $out_file -Append
			} else {
			$neg_str + "Windows apps Access Trusted Devices is NOT Force DENY" + $no_cumple | Tee-Object -FilePath $out_file -Append
			}
		}
}
 Catch{
        $err_str + "Power Shell for Windows apps Access Trusted Devices is Force DENY  failed" | Tee-Object -FilePath $out_file -Append
    }
Write-Host " "


Write-Host " "
#Validate Let Windows Apps Control Radios are Force DENY
$inf_str + "Testing if Windows apps Control Radios is Force DENY" | Tee-Object -FilePath $out_file -Append
Try{
	 $reswapp = (Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessAccountInfo
	 if ($reswapp -eq $null){
            $neg_str + "Windows apps Control Radios key does not exist."  + $cumple | Tee-Object -FilePath $out_file -Append
        } 
	else {
		if ([bool](Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessAccountInfo){
			$pos_str + "Windows apps Control Radios is Force DENY"  + $cumple | Tee-Object -FilePath $out_file -Append
			} else {
			$neg_str + "Windows apps Control Radios is NOT Force DENY" + $no_cumple | Tee-Object -FilePath $out_file -Append
			}
		}
}
 Catch{
        $err_str + "Power Shell for Control Radios is Force DENY  failed" | Tee-Object -FilePath $out_file -Append
    }
Write-Host " "



Write-Host " "
#Validate Let Windows Make Phone Calls are Force DENY
$inf_str + "Testing if Windows apps Make Phone Calls is Force DENY" | Tee-Object -FilePath $out_file -Append
Try{
	 $reswapp = (Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessAccountInfo
	 if ($reswapp -eq $null){
            $neg_str + "Windows apps Make Phone Calls key does not exist."  + $cumple | Tee-Object -FilePath $out_file -Append
        } 
	else {
		if ([bool](Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessAccountInfo){
			$pos_str + "Windows apps Make Phone Calls is Force DENY" + $cumple | Tee-Object -FilePath $out_file -Append
			} else {
			$neg_str + "Windows apps Make Phone Calls is NOT Force DENY" + $no_cumple | Tee-Object -FilePath $out_file -Append
			}
		}
}
 Catch{
        $err_str + "Power Shell for Windows apps Make Phone Calls is Force DENY  failed" | Tee-Object -FilePath $out_file -Append
    }
Write-Host " "



Write-Host " "
#Validate Let Windows Apps Sync with Devices are Force DENY
$inf_str + "Testing if Windows apps Sync with Devices is Force DENY" | Tee-Object -FilePath $out_file -Append
Try{
	 $reswapp = (Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessAccountInfo
	 if ($reswapp -eq $null){
            $neg_str + "Windows Sync with Devices key does not exist."  + $cumple | Tee-Object -FilePath $out_file -Append
        } 
	else {
		if ([bool](Get-ItemProperty -path 'HKLM:\SSoftware\Policies\Microsoft\Windows\AppPrivacy\' -ErrorAction SilentlyContinue).LetAppsAccessAccountInfo){
			$pos_str + "Windows apps Sync with Devices is Force DENY" + $cumple | Tee-Object -FilePath $out_file -Append
			} else {
			$neg_str + "Windows apps Sync with Devices is NOT Force DENY" + $no_cumple | Tee-Object -FilePath $out_file -Append
			}
		}
}
 Catch{
        $err_str + "Power Shell for Windows apps Sync with Devices is Force DENY  failed" | Tee-Object -FilePath $out_file -Append
    }
Write-Host " "

Write-Host " "
Write-Host "+-----------------------------------------------------------------------------+"
Write-Host "|                ~~~ Identificacion y Autenticacion de acceso ~~~             |"
Write-Host "+----+------+-----------------------------------------------------------------+"

###############################
# Disable SMBV1
###############################
# Check if SMBv1 is available and if signing is turned on.
<#
Resources:
    Stop using SMB1: https://blogs.technet.microsoft.com/filecab/2016/09/16/stop-using-smb1/
    How to detect, enable and disable SMBv1, SMBv2, and SMBv3 in Windows and Windows Server: https://support.microsoft.com/en-us/help/2696547/how-to-detect-enable-and-disable-smbv1-smbv2-and-smbv3-in-windows-and
    Detecting and remediating SMBv1: https://blogs.technet.microsoft.com/leesteve/2017/05/11/detecting-and-remediating-smbv1/
#>

# Remove SMB v1 support
$inf_str + "Testing if SMBv1 is disabled." | Tee-Object -FilePath $out_file -Append
Try{
    $ressmb = Get-SmbServerConfiguration | Select-Object EnableSMB1Protocol 
    #$inf_str + "Testing if SMBv1 is disabled." | Tee-Object -FilePath $out_file -Append
    if ([bool] $ressmb) { 
        $neg_str + "SMBv1 is Enabled"  | Tee-Object -FilePath $out_file -Append
    } else { 
        $pos_str + "SMBv1 is Disabled"  | Tee-Object -FilePath $out_file -Append
    }
    $inf_str + "Testing if system is configured to audit SMBv1 activity." | Tee-Object -FilePath $out_file -Append
    if ([bool](Get-SmbServerConfiguration | Select-Object AuditSmb1Access)) { 
        $pos_str + "SMBv1 Auditing should be Enabled: Enabled"  | Tee-Object -FilePath $out_file -Append
    } else { 
        $neg_str + "SMBv1 Auditing is Disabled"  | Tee-Object -FilePath $out_file -Append
    }
}
Catch{
    $err_str + "Testing for SMBv1 failed." | Tee-Object -FilePath $out_file -Append
}
Write-Host " "

###############################
# NTLM Settings
###############################
# Configure NTLM session security
<#
Resource:
    Session security for NTLM SSP-based servers must be configured to require NTLMv2 session security and 128-bit encryption.: https://www.stigviewer.com/stig/windows_server_2016/2018-03-07/finding/V-73697
    The system is not configured to meet the minimum requirement for session security for NTLM SSP based clients.: https://www.stigviewer.com/stig/windows_7/2012-07-02/finding/V-3382
#>

$inf_str + "Testing NTLM Session Server Security settings." | Tee-Object -FilePath $out_file -Append
Try{
    $resntssec = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue).NtlmMinServerSec
    if ([int]$resntssec -eq 537395200){
        $pos_str + "NTLM Session Server Security settings is configured to require NTLMv2 and 128-bit encryption: $resntssec" | Tee-Object -FilePath $out_file -Append
    } else {        
        $neg_str + "NTLM Session Server Security settings is not configured to require NTLMv2 and 128-bit encryption: $resntssec" | Tee-Object -FilePath $out_file -Append
    }   
}
Catch{
    $err_str + "Testing NTLM Session Server Security settings failed." | Tee-Object -FilePath $out_file -Append
}

$inf_str + "Testing NTLM Session Client Security settings." | Tee-Object -FilePath $out_file -Append
$resntcsec = (Get-ItemProperty -path 'HKLM:\System\CurrentControlSet\Control\Lsa\MSV1_0' -ErrorAction SilentlyContinue).NtlmMinClientSec
Try{
    if ([int]$resntcsec -eq 537395200){
        $pos_str + "NTLM Session Client Security settings is configured to require NTLMv2 and 128-bit encryption: $resntcsec" | Tee-Object -FilePath $out_file -Append
    } else {        
        $neg_str + "NTLM Session Client Security settings is not configured to require NTLMv2 and 128-bit encryption: $resntcsec" | Tee-Object -FilePath $out_file -Append
    }   
}
Catch{
    $err_str + "Testing NTLM Session Client Security settings failed." | Tee-Object -FilePath $out_file -Append
}


Write-Host " "
Write-Host "+-----------------------------------------------------------------------------+"
Write-Host "|                ~~~ Acceso a los recursos de red  ~~~                        |"
Write-Host "+----+------+-----------------------------------------------------------------+"
########## Event Log Settings ##############
<#
Resources:
    Get-EventLog: https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.management/get-eventlog?view=powershell-5.1
    Recommended settings for event log sizes in Windows: https://support.microsoft.com/en-us/help/957662/recommended-settings-for-event-log-sizes-in-windows
    Hey, Scripting Guy! How Can I Check the Size of My Event Log and Then Backup and Archive It If It Is More Than Half Full?: https://blogs.technet.microsoft.com/heyscriptingguy/2009/04/08/hey-scripting-guy-how-can-i-check-the-size-of-my-event-log-and-then-backup-and-archive-it-if-it-is-more-than-half-full/
    Is there a log file for RDP connections?: https://social.technet.microsoft.com/Forums/en-US/cb1c904f-b542-4102-a8cb-e0c464249280/is-there-a-log-file-for-rdp-connections?forum=winserverTS
    WINDOWS POWERSHELL LOGGING CHEAT SHEET - Win 7/Win 2008 or later: https://static1.squarespace.com/static/552092d5e4b0661088167e5c/t/5760096ecf80a129e0b17634/1465911664070/Windows+PowerShell+Logging+Cheat+Sheet+ver+June+2016+v2.pdf0
#>

$inf_str + "Event logs settings defaults are too small. Test that max sizes have been increased." | Tee-Object -FilePath $out_file -Append

$logs = @{
'Application' = 4
'System' = 4
'Security' = 4
'Windows PowerShell' = 4
'Microsoft-Windows-PowerShell/Operational' = 1
'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational'= 1
'Microsoft-Windows-TaskScheduler/Operational' = 1
'Microsoft-Windows-SMBServer/Audit' = 1
'Microsoft-Windows-Security-Netlogon/Operational' = 1
'Microsoft-Windows-WinRM/Operational' = 1
'Microsoft-Windows-WMI-Activity/Operational' = 1
}

foreach ($l in $logs.keys){
    Try{
        $lsize = [math]::Round((Get-WinEvent -ListLog $l -ErrorAction Stop).MaximumSizeInBytes / (1024*1024*1024),3)
        if ($lsize -lt $logs[$l]){
            #$neg_str + $l "max log size is smaller than $logs[$l] GB: $lsize GB" | Tee-Object -FilePath $out_file -Append
            $neg_str + "$l max log size is smaller than " + $logs[$l] + " GB: " + $lsize + "GB" | Tee-Object -FilePath $out_file -Append
        } else {
            #$pos_str + $l "max log size is okay: $lsize GB" | Tee-Object -FilePath $out_file -Append
            $pos_str + "$l max log size is okay: $lsize GB" | Tee-Object -FilePath $out_file -Append
        }
    }
    Catch{
        $err_str + "Testing $l log size failed." | Tee-Object -FilePath $out_file -Append
    }
}

Write-Host " "
Write-Host "+-----------------------------------------------------------------------------+"
Write-Host "|                ~~~ Politica General de Seguridad  ~~~                       |"
Write-Host "+----+------+-----------------------------------------------------------------+"


Write-Host "+----+------+-----------------------------------------------------------------+"


########## Windows Information ##############
$inf_str + "Completed Date/Time: $(get-date -format yyyyMMddTHHmmssffzz)" | Tee-Object -FilePath $out_file -Append