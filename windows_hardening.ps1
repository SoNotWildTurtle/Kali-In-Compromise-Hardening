# windows_hardening.ps1

# Enable Windows Firewall for all profiles
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled True

# Configure Firewall Rules: Allow SSH and RDP if necessary
New-NetFirewallRule -DisplayName "Allow SSH" -Direction Inbound -Protocol TCP -LocalPort 22 -Action Allow
# Uncomment to allow RDP
# New-NetFirewallRule -DisplayName "Allow RDP" -Direction Inbound -Protocol TCP -LocalPort 3389 -Action Allow

# Ensure OpenSSH server is installed and running
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd
Set-Service sshd -StartupType Automatic

# Enable PowerShell Remoting
Enable-PSRemoting -Force

# Enable Windows Defender Antivirus
Set-MpPreference -DisableRealtimeMonitoring $false
Start-MpScan -ScanType QuickScan

# Enable Controlled Folder Access for ransomware protection
Set-MpPreference -EnableControlledFolderAccess Enabled

# Disable SMBv1 to reduce attack surface
Set-SmbServerConfiguration -EnableSMB1Protocol $false -Force

# Enable BitLocker Drive Encryption (Requires TPM)
Enable-BitLocker -MountPoint "C:" -EncryptionMethod Aes256 -UsedSpaceOnlyEncryption

# Enforce Password Policies
secedit /export /cfg C:\password_policy.cfg
$config = Get-Content C:\password_policy.cfg
$config = $config -replace "MinimumPasswordLength = \d+", "MinimumPasswordLength = 12"
$config = $config -replace "PasswordComplexity = \d+", "PasswordComplexity = 1"
Set-Content C:\password_policy.cfg $config
secedit /configure /db C:\Windows\Security\Database\secedit.sdb /cfg C:\password_policy.cfg /areas SECURITYPOLICY
Remove-Item C:\password_policy.cfg

# Disable Remote Assistance
Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Remote Assistance" -Name "fAllowToGetHelp" -Value 0

# Disable Unnecessary Services
Get-Service -Name "Fax", "XblGameSave", "WMPNetworkSvc" | Set-Service -StartupType Disabled

# Enable Audit Logging
auditpol /set /category:"Logon/Logoff" /success:enable /failure:enable
auditpol /set /category:"Object Access" /success:enable /failure:enable
auditpol /set /category:"Policy Change" /success:enable /failure:enable

# Remove Unnecessary Features
Disable-WindowsOptionalFeature -Online -FeatureName "TelnetClient" -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName "TFTP" -NoRestart

# Enable PowerShell transcription logging
$transcriptPath = 'C:\Logs\PS_Transcripts'
New-Item -Path $transcriptPath -ItemType Directory -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Name 'EnableTranscripting' -Value 1 -Type DWord
Set-ItemProperty -Path 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell' -Name 'TranscriptionSavePath' -Value $transcriptPath -Type String

# Update System and schedule daily updates
Install-PackageProvider -Name NuGet -Force
Install-Module -Name PSWindowsUpdate -Force
Import-Module PSWindowsUpdate
Get-WindowsUpdate -AcceptAll -Install -AutoReboot
$action = New-ScheduledTaskAction -Execute 'PowerShell.exe' -Argument '-Command "Import-Module PSWindowsUpdate; Get-WindowsUpdate -AcceptAll -Install -AutoReboot"'
$trigger = New-ScheduledTaskTrigger -Daily -At 3am
Register-ScheduledTask -TaskName 'DailyWindowsUpdate' -Action $action -Trigger $trigger -Force

# Enable firewall logging for deeper insight into network activity
Set-NetFirewallProfile -LogAllowed True -LogBlocked True -LogFileName "C:\\Windows\\System32\\LogFiles\\Firewall\\pfirewall.log" -LogMaxSizeKilobytes 32767

# Install Sysmon from Sysinternals for detailed system monitoring
$sysmonUrl = 'https://download.sysinternals.com/files/Sysmon.zip'
$sysmonZip = "$env:TEMP\\Sysmon.zip"
Invoke-WebRequest -Uri $sysmonUrl -OutFile $sysmonZip
Expand-Archive -Path $sysmonZip -DestinationPath "$env:TEMP\\Sysmon" -Force
Start-Process "$env:TEMP\\Sysmon\\Sysmon64.exe" -ArgumentList '-accepteula -i -n' -Wait
Set-Service sysmon -StartupType Automatic
Remove-Item $sysmonZip
Remove-Item "$env:TEMP\\Sysmon" -Recurse -Force

# Enable Windows Defender Attack Surface Reduction rules
$asrRules = @(
    'D4F940AB-401B-4EFC-AADC-AD5F3C50688A',
    '75668C1F-73B5-4CF0-BB93-3ECF5CB7CC84',
    '3B576869-A4EC-4529-8536-B80A7769E899',
    'D3E037E1-3EB8-44C8-A917-57927947596D'
)
foreach ($rule in $asrRules) {
    Add-MpPreference -AttackSurfaceReductionRules_Ids $rule -AttackSurfaceReductionRules_Actions Enabled
}

# Enforce TLS 1.2 and disable older protocols
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Server' -Name 'Enabled' -Value 1 -PropertyType DWord -Force
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Force | Out-Null
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client' -Name 'Enabled' -Value 1 -PropertyType DWord -Force
New-Item -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0' -Name 'Enabled' -Value 0 -Type DWord

# Increase Security event log size for better auditing
wevtutil sl Security /ms:32768
