import csv
import re
from netaddr import *
import xml.etree.ElementTree as ET
import pandas as pd
from datetime import datetime, timezone
from evtx import PyEvtxParser
from dateutil.parser import parse
from dateutil.parser import isoparse
from pytz import timezone
import pickle
import itertools
from itertools import product
minlength = 1000
import multiprocessing
import time
input_timezone = timezone("UTC")
from multiprocessing.sharedctypes import Value, Array
from pytz import timezone
import os
import platform
#manager = multiprocessing.Manager()
minlength=1000
processinitial=Value('i',1)
objectinitial=Value('i',1)
logoninitial=Value('i',1)
SecurityInitial=Value('i',1)
DefenderInitial=Value('i',1)
Group_PolicyInitial=Value('i',1)
SMB_ServerInitial=Value('i',1)
SMB_ClientInitial=Value('i',1)
ScheduledTaskInitial=Value('i',1)
SystemInitial=Value('i',1)
Powershell_OperationalInitial=Value('i',1)
PowershellInitial=Value('i',1)
TerminalServicesInitial=Value('i',1)
TerminalServices_RDPClientInitial=Value('i',1)
WinRMInitial=Value('i',1)
SysmonInitial=Value('i',1)
User_SIDsInitial=Value('i',1)


account_op = {}
PasswordSpray = {}
objectaccess=False
processexec=False
logons=False
frequencyanalysis=False
allreport=False
output=''
temp_dir='temp/'
Suspicious_executables = ["\\mshta.exe", "\\csc.exe", 'whoami.exe', '\\pl.exe', '\\nc.exe',
                          'nmap.exe', 'psexec.exe', 'plink.exe', 'mimikatz', 'procdump.exe', ' dcom.exe',
                          ' Inveigh.exe', ' LockLess.exe', ' Logger.exe', ' PBind.exe', ' PS.exe', ' Rubeus.exe',
                          ' RunasCs.exe', ' RunAs.exe', ' SafetyDump.exe', ' SafetyKatz.exe', ' Seatbelt.exe',
                          ' SExec.exe', ' SharpApplocker.exe', ' SharpChrome.exe', ' SharpCOM.exe', ' SharpDPAPI.exe',
                          ' SharpDump.exe', ' SharpEdge.exe', ' SharpEDRChecker.exe', ' SharPersist.exe',
                          ' SharpHound.exe', ' SharpLogger.exe', ' SharpPrinter.exe', ' SharpRoast.exe', ' SharpSC.exe',
                          ' SharpSniper.exe', ' SharpSocks.exe', ' SharpSSDP.exe', ' SharpTask.exe', ' SharpUp.exe',
                          ' SharpView.exe', ' SharpWeb.exe', ' SharpWMI.exe', ' Shhmon.exe', ' SweetPotato.exe',
                          ' Watson.exe', ' WExec.exe', '7zip.exe']

Suspicious_powershell_commands = ['FromBase64String', 'DomainPasswordSpray', 'PasswordSpray', 'Password',
                                  'Get-WMIObject', 'Get-GPPPassword', 'Get-Keystrokes', 'Get-TimedScreenshot',
                                  'Get-VaultCredential', 'Get-ServiceUnquoted', 'Get-ServiceEXEPerms',
                                  'Get-ServicePerms', 'Get-RegAlwaysInstallElevated', 'Get-RegAutoLogon',
                                  'Get-UnattendedInstallFiles', 'Get-Webconfig', 'Get-ApplicationHost',
                                  'Get-PassHashes', 'Get-LsaSecret', 'Get-Information', 'Get-PSADForestInfo',
                                  'Get-KerberosPolicy', 'Get-PSADForestKRBTGTInfo', 'Get-PSADForestInfo',
                                  'Get-KerberosPolicy', 'Invoke-Command', 'Invoke-Expression', 'iex(',
                                  'Invoke-Shellcode', 'Invoke--Shellcode', 'Invoke-ShellcodeMSIL',
                                  'Invoke-MimikatzWDigestDowngrade', 'Invoke-NinjaCopy', 'Invoke-CredentialInjection',
                                  'Invoke-TokenManipulation', 'Invoke-CallbackIEX', 'Invoke-PSInject',
                                  'Invoke-DllEncode', 'Invoke-ServiceUserAdd', 'Invoke-ServiceCMD',
                                  'Invoke-ServiceStart', 'Invoke-ServiceStop', 'Invoke-ServiceEnable',
                                  'Invoke-ServiceDisable', 'Invoke-FindDLLHijack', 'Invoke-FindPathHijack',
                                  'Invoke-AllChecks', 'Invoke-MassCommand', 'Invoke-MassMimikatz', 'Invoke-MassSearch',
                                  'Invoke-MassTemplate', 'Invoke-MassTokens', 'Invoke-ADSBackdoor',
                                  'Invoke-CredentialsPhish', 'Invoke-BruteForce', 'Invoke-PowerShellIcmp',
                                  'Invoke-PowerShellUdp', 'Invoke-PsGcatAgent', 'Invoke-PoshRatHttps',
                                  'Invoke-PowerShellTcp', 'Invoke-PoshRatHttp', 'Invoke-PowerShellWmi', 'Invoke-PSGcat',
                                  'Invoke-Encode', 'Invoke-Decode', 'Invoke-CreateCertificate', 'Invoke-NetworkRelay',
                                  'EncodedCommand', 'New-ElevatedPersistenceOption', 'wsman', 'Enter-PSSession',
                                  'DownloadString', 'DownloadFile', 'Out-Word', 'Out-Excel', 'Out-Java', 'Out-Shortcut',
                                  'Out-CHM', 'Out-HTA', 'Out-Minidump', 'HTTP-Backdoor', 'Find-AVSignature',
                                  'DllInjection', 'ReflectivePEInjection', 'Base64', 'System.Reflection',
                                  'System.Management', 'Restore-ServiceEXE', 'Add-ScrnSaveBackdoor', 'Gupt-Backdoor',
                                  'Execute-OnTime', 'DNS_TXT_Pwnage', 'Write-UserAddServiceBinary',
                                  'Write-CMDServiceBinary', 'Write-UserAddMSI', 'Write-ServiceEXE',
                                  'Write-ServiceEXECMD', 'Enable-DuplicateToken', 'Remove-Update',
                                  'Execute-DNSTXT-Code', 'Download-Execute-PS', 'Execute-Command-MSSQL',
                                  'Download_Execute', 'Copy-VSS', 'Check-VM', 'Create-MultipleSessions',
                                  'Run-EXEonRemote', 'Port-Scan', 'Remove-PoshRat', 'TexttoEXE', 'Base64ToString',
                                  'StringtoBase64', 'Do-Exfiltration', 'Parse_Keys', 'Add-Exfiltration',
                                  'Add-Persistence', 'Remove-Persistence', 'Find-PSServiceAccounts',
                                  'Discover-PSMSSQLServers', 'Discover-PSMSExchangeServers',
                                  'Discover-PSInterestingServices', 'Discover-PSMSExchangeServers',
                                  'Discover-PSInterestingServices', 'Mimikatz', 'powercat', 'powersploit',
                                  'PowershellEmpire', 'GetProcAddress', 'ICM', '.invoke', ' -e ', 'hidden', '-w hidden',
                                  'Invoke-Obfuscation-master', 'Out-EncodedWhitespaceCommand', 'Out-Encoded',
                                  "-EncodedCommand", "-enc", "-w hidden", "[Convert]::FromBase64String", "iex(",
                                  "New-Object", "Net.WebClient", "-windowstyle hidden", "DownloadFile",
                                  "DownloadString", "Invoke-Expression", "Net.WebClient", "-Exec bypass",
                                  "-ExecutionPolicy bypass"]

"""Suspicious_powershell_Arguments = ["-EncodedCommand", "-enc", "-w hidden", "[Convert]::FromBase64String", "iex(",
                                   "New-Object", "Net.WebClient", "-windowstyle hidden", "DownloadFile",
                                   "DownloadString", "Invoke-Expression", "Net.WebClient", "-Exec bypass",
                                   "-ExecutionPolicy bypass",'-Path ', 'System.CodeDom.Compiler.CompilerParameters','System.CodeDom.Compiler.CompilerParameters','Windows.Security.Credentials.PasswordVault','Microsoft.CSharp.CSharpCodeProvider','System.Runtime.InteropServices.RuntimeEnvironment','.RegisterXLL','-ComObject ','SilentlyContinue','psreadline','Enable-PSRemoting ','# Copyright 2016 Amazon.com, Inc. or its affiliates. All','$VerbosePreference.ToString(','System.Net.Sockets.TcpListener','[System.Net.HttpWebRequest]']
"""

"""print("Loading Powershell detections")
file=open("./lib/Powershell-detection.data","r")
Suspicious_powershell_Arguments=file.read().split("\n")
"""

Suspicious_powershell_Arguments =['""','&&','|','$DoIt','$env:ComSpec','$env:COR_ENABLE_PROFILING','$env:COR_PROFILER','$env:COR_PROFILER_PATH','> $env:TEMP\\','$env:TEMP\\','$env:UserName','$profile','0x11','0xdeadbeef',' 443 ',' 80 ','AAAAYInlM','AcceptTcpClient',' active_users ','add','Add-ConstrainedDelegationBackdoor','add-content','Add-Content','Add-DnsClientNrptRule','Add-DomainGroupMember','Add-DomainObjectAcl','Add-Exfiltration','Add-ObjectAcl','Add-Persistence','Add-RegBackdoor','Add-RemoteConnection','Add-ScrnSaveBackdoor','AddSecurityPackage','AdjustTokenPrivileges','ADRecon-Report.xlsx','Advapi32','-All ','Allow','-AnswerFile','\AppData\\Roaming\\Code\\','-append','.application','-ArgumentList ','-AttackSurfaceReductionRules_Actions ','-AttackSurfaceReductionRules_Ids ','.AuthenticateAsClient','-band',' basic_info ','.bat','bxor','bypass',' -c ','"carbonblack"','Cert:\\LocalMachine\\Root',' change_user ','char','-CheckForSignaturesBeforeRunningScan ','Check-VM','-ClassName ','-ClassName','-ClassName CommandLineEventConsumer ','-ClassName __EventFilter ','Clear-EventLog ','Clear-History','Clear-WinEvent ','ClientAccessible','CL_Invocation.ps1','CL_Mutexverifiers.ps1','CloseHandle','.cmd','CmdletsToExport','Collections.ArrayList',' command_exec ','-ComObject ','-ComObject','-comobject outlook.application','Compress-Archive ','Compress-Archive',' -ComputerName ','-ComputerName ','comspec','ConsoleHost_history.txt','-ControlledFolderAccessProtectedFolders ','Convert-ADName','[Convert]::FromBase64String','ConvertFrom-UACValue','Convert-NameToSid','ConvertTo-SID','.CopyFromScreen','Copy-Item ','Copy-Item','# Copyright 2016 Amazon.com, Inc. or its affiliates. All','Copy-VSS','C:\\ProgramData\\Amazon\\EC2-Windows\\Launch\\Module\\',').Create(','Create-MultipleSessions','CreateProcessWithToken','CreateRemoteThread','CreateThread','CreateUserThread','.CreationTime =','curl ','CurrentVersion\\Winlogon','C:\\Windows\\Diagnostics\\System\\PCW','"cylance"',' -d ','DangerousGetHandle','DataToEncode','"defender"','del','.Delete()','Delete()','.Description','-Destination ','-Destination',' -DestinationPath ','DisableArchiveScanning $true','DisableArchiveScanning 1','DisableBehaviorMonitoring $true','DisableBehaviorMonitoring 1','DisableBlockAtFirstSeen $true','DisableBlockAtFirstSeen 1','DisableIntrusionPreventionSystem $true','DisableIntrusionPreventionSystem 1','DisableIOAVProtection $true','DisableIOAVProtection 1','Disable-LocalUser','DisableRealtimeMonitoring $true','DisableRealtimeMonitoring 1','DisableRemovableDriveScanning $true','DisableRemovableDriveScanning 1','DisableScanningMappedNetworkDrivesForFullScan $true','DisableScanningMappedNetworkDrivesForFullScan 1','DisableScanningNetworkFiles $true','DisableScanningNetworkFiles 1','DisableScriptScanning $true','DisableScriptScanning 1',' disable_wdigest ','Disable-WindowsOptionalFeature',' disable_winrm ','DNS_TXT_Pwnage','.doc','.docx','DoesNotRequirePreAuth','Do-Exfiltration',' -doh ','.download','.Download','Download_Execute','Download-Execute-PS','.DownloadFile(','.DownloadString(','.DriveLetter','DumpCerts','DumpCreds','DuplicateTokenEx','-Enabled','Enabled-DuplicateToken','Enable-Duplication','Enable-LocalUser','Enable-PSRemoting ','EnableSmartScreen',' enable_wdigest ','Enable-WindowsOptionalFeature',' enable_winrm ',' -enc ','-Enc',' -EncodedCommand ','EnumerateSecurityPackages','-ep','-ErrorAction ',' -ErrorAction SilentlyContinue','Execute-Command-MSSQL','Execute-DNSTXT-Code','Execute-OnTime','ExetoText','exfill','ExfilOption','Exploit-Jboss','Export-PfxCertificate','Export-PowerViewCSV','-f ','Failed to update Help for the module','FakeDC','False','-FeatureName','-FilePath ','-FilePath "$env:comspec" ','-Filter',' -Filter Bookmarks','.findall()','Find-DomainLocalGroupMember','Find-DomainObjectPropertyOutlier','Find-DomainProcess','Find-DomainShare','Find-DomainUserEvent','Find-DomainUserLocation','Find-ForeignGroup','Find-ForeignUser','Find-Fruit','Find-GPOComputerAdmin','Find-GPOLocation','Find-InterestingDomainAcl','Find-InterestingDomainShareFile','Find-InterestingFile','Find-LocalAdminAccess','Find-ManagedSecurityGroups','Find-TrustedDocuments','FireBuster','FireListener',' -Force','foreach','format-table','FreeHGlobal','FreeLibrary','Function Get-ADRExcelComOb','gci',' gen_cli ','get-acl','Get-AdComputer ','Get-AdDefaultDomainPasswordPolicy','Get-AdGroup ','Get-ADObject','get-ADPrincipalGroupMembership','Get-ADRDomainController','Get-ADReplAccount','Get-ADRGPO','get-aduser','Get-ADUser','Get-ApplicationHost','Get-CachedRDPConnection','get-childitem','Get-ChildItem ','Get-ChildItem','Get-ChromeDump','Get-ClipboardContents','Get-CredManCreds','GetDelegateForFunctionPointer','Get-DFSshare','Get-DNSRecord','Get-DNSZone','Get-Domain','Get-DomainComputer','Get-DomainController','Get-DomainDFSShare','Get-DomainDNSRecord','Get-DomainDNSZone','Get-DomainFileServer','Get-DomainForeignGroupMember','Get-DomainForeignUser','Get-DomainGPO','Get-DomainGPOComputerLocalGroupMapping','Get-DomainGPOLocalGroup','Get-DomainGPOUserLocalGroupMapping','Get-DomainGroup','Get-DomainGroupMember','Get-DomainManagedSecurityGroup','Get-DomainObject','Get-DomainObjectAcl','Get-DomainOU','Get-DomainPolicy','Get-DomainSID','Get-DomainSite','Get-DomainSPNTicket','Get-DomainSubnet','Get-DomainTrust','Get-DomainTrustMapping','Get-DomainUser','Get-DomainUserEvent','Get-Forest','Get-ForestDomain','Get-ForestGlobalCatalog','Get-ForestTrust','Get-FoxDump','Get-GPO','Get-GPPPassword','Get-Inbox.ps1','Get-IndexedItem','Get-Information','Get-IPAddress','get-itemProperty','Get-ItemProperty','Get-Keystrokes','Get-LastLoggedOn','get-localgroup','Get-LocalGroupMember','Get-LocalUser','Get-LoggedOnLocal','GetLogonSessionData','Get-LSASecret','GetModuleHandle','Get-NetComputer','Get-NetComputerSiteName','Get-NetDomain','Get-NetDomainController','Get-NetDomainTrust','Get-NetFileServer','Get-NetForest','Get-NetForestCatalog','Get-NetForestDomain','Get-NetForestTrust','Get-NetGPO','Get-NetGPOGroup','Get-NetGroup','Get-NetGroupMember','Get-NetLocalGroup','Get-NetLocalGroupMember','Get-NetLoggedon','Get-NetOU','Get-NetProcess','Get-NetRDPSession','Get-NetSession','Get-NetShare','Get-NetSite','Get-NetSubnet','Get-NetUser','Get-ObjectAcl','Get-PassHashes','Get-PassHints','Get-PasswordVaultCredentials','Get-PathAcl','GetProcAddress','Get-ProcAddress user32.dll GetAsyncKeyState','Get-ProcAddress user32.dll GetForegroundWindow','get-process','Get-Process ','Get-Process','GetProcessHandle','Get-Process lsass','Get-Proxy','(Get-PSReadlineOption).HistorySavePath','Get-RegAlwaysInstallElevated','Get-RegAutoLogon','Get-RegistryMountedDrive','Get-RegLoggedOn','Get-RickAstley','Get-Screenshot','Get-SecurityPackages','Get-Service ','Get-ServiceFilePermission','Get-ServicePermission','Get-ServiceUnquoted','Get-SiteListPassword','Get-SiteName','get-smbshare','Get-StorageDiagnosticInfo','Get-System','Get-SystemDriveInfo','Get-TimedScreenshot','GetTokenInformation','::GetTypeFromCLSID(','Get-UnattendedInstallFile','Get-Unconstrained','Get-USBKeystrokes','Get-UserEvent','Get-VaultCredential','Get-Volume','Get-VulnAutoRun','Get-VulnSchTask','Get-Web-Credentials','Get-WLAN-Keys','Get-WmiObject','Get-WMIObject','Get-WMIProcess','Get-WMIRegCachedRDPConnection','Get-WMIRegLastLoggedOn','Get-WMIRegMountedDrive','Get-WMIRegProxy','\Google\\Chrome\\User Data\\Default\\Login Data','\\Google\\Chrome\\User Data\Default\Login Data For Account','GroupPolicyRefreshTime','GroupPolicyRefreshTimeDC','GroupPolicyRefreshTimeOffset','GroupPolicyRefreshTimeOffsetDC','Gupt-Backdoor','gwmi','harmj0y','hidden','Hidden','HighThreatDefaultAction','-HistorySaveStyle','HKCU:\\','HKCU\\software\\microsoft\\windows\\currentversion\\run','HKEY_CURRENT_USER\Control Panel\Desktop\\','HKLM:\\','HotFixID','http://127.0.0.1','HTTP-Backdoor','HTTP-Login',' -i ','-Identity ','iex(','IMAGE_NT_OPTIONAL_HDR64_MAGIC','-ImagePath ','ImpersonateLoggedOnUser','Import-Certificate','Import-Module "$Env:Appdata\\','Import-Module ''$Env:Appdata\\','Import-Module $Env:Appdata\\','Import-Module','$Env:Temp\\','Import-Module ''$Env:Temp\\','Import-Module $Env:Temp\\','Import-Module C:\\Users\\Public\\',' -Include ','-IncludeLiveDump','Install-ServiceBinary','Install-SSP','Internet-Explorer-Optional-amd64','invoke','Invoke-ACLScanner','Invoke-ADSBackdoor','Invoke-AllChecks','Invoke-AmsiBypass','Invoke-ARPScan','Invoke-AzureHound','Invoke-BackdoorLNK','Invoke-BadPotato','Invoke-BetterSafetyKatz','Invoke-BruteForce','Invoke-BypassUAC','Invoke-Carbuncle','Invoke-Certify','Invoke-CheckLocalAdminAccess','Invoke-CimMethod ','Invoke-CimMethod','invoke-command ','Invoke-CredentialInjection','Invoke-CredentialsPhish','Invoke-DAFT','Invoke-DCSync','Invoke-Decode','Invoke-DinvokeKatz','Invoke-DllInjection','Invoke-DNSExfiltrator','Invoke-DowngradeAccount','Invoke-EgressCheck','Invoke-Encode','Invoke-EnumerateLocalAdmin','Invoke-EventHunter','Invoke-Eyewitness','Invoke-FakeLogonScreen','Invoke-Farmer','Invoke-FileFinder','Invoke-Get-RBCD-Threaded','Invoke-Gopher','Invoke-GPOLinks','Invoke-Grouper2','Invoke-HandleKatz','Invoke-Interceptor','Invoke-Internalmonologue','Invoke-Inveigh','Invoke-InveighRelay','invoke-item ','Invoke-JSRatRegsvr','Invoke-JSRatRundll','Invoke-Kerberoast','Invoke-KrbRelayUp','Invoke-LdapSignCheck','Invoke-Lockless','Invoke-MapDomainTrust','Invoke-Mimikatz','Invoke-MimikatzWDigestDowngrade','Invoke-Mimikittenz','Invoke-MITM6','Invoke-NanoDump','Invoke-NetRipper','Invoke-NetworkRelay','Invoke-Nightmare','Invoke-NinjaCopy','Invoke-OxidResolver','Invoke-P0wnedshell','Invoke-Paranoia','Invoke-PortScan','Invoke-PoshRatHttp','Invoke-PoshRatHttps','Invoke-PostExfil','Invoke-Potato','Invoke-PowerDump','Invoke-PowerShellIcmp','Invoke-PowerShellTCP','Invoke-PowerShellUdp','Invoke-PowerShellWMI','Invoke-PPLDump','Invoke-Prasadhak','Invoke-ProcessHunter','Invoke-PsExec','Invoke-PSGcat','Invoke-PsGcatAgent','Invoke-PSInject','Invoke-PsUaCme','Invoke-ReflectivePEInjection','Invoke-ReverseDNSLookup','Invoke-RevertToSelf','Invoke-Rubeus','Invoke-RunAs','Invoke-SafetyKatz','Invoke-SauronEye','Invoke-SCShell','Invoke-Seatbelt','Invoke-ServiceAbuse','Invoke-SessionGopher','Invoke-ShareFinder','Invoke-SharpAllowedToAct','Invoke-SharpBlock','Invoke-SharpBypassUAC','Invoke-SharpChromium','Invoke-SharpClipboard','Invoke-SharpCloud','Invoke-SharpDPAPI','Invoke-SharpDump','Invoke-SharPersist','Invoke-SharpGPOAbuse','Invoke-SharpGPO-RemoteAccessPolicies','Invoke-SharpHandler','Invoke-SharpHide','Invoke-Sharphound2','Invoke-Sharphound3','Invoke-SharpHound4','Invoke-SharpImpersonation','Invoke-SharpImpersonationNoSpace','Invoke-SharpKatz','Invoke-SharpLdapRelayScan','Invoke-Sharplocker','Invoke-SharpLoginPrompt','Invoke-SharpMove','Invoke-SharpPrinter','Invoke-SharpPrintNightmare','Invoke-SharpRDP','Invoke-SharpSecDump','Invoke-Sharpshares','Invoke-SharpSniper','Invoke-SharpSploit','Invoke-SharpSpray','Invoke-SharpSSDP','Invoke-SharpStay','Invoke-SharpUp','Invoke-Sharpview','Invoke-SharpWatson','Invoke-Sharpweb','Invoke-Shellcode','Invoke-SMBAutoBrute','Invoke-SMBScanner','Invoke-Snaffler','Invoke-Spoolsample','Invoke-SSHCommand','Invoke-SSIDExfil','Invoke-StandIn','Invoke-StickyNotesExtract','Invoke-Tater','Invoke-Thunderfox','Invoke-ThunderStruck','Invoke-TokenManipulation','Invoke-Tokenvator','Invoke-TroubleshootingPack','Invoke-UrbanBishop','Invoke-UserHunter','Invoke-UserImpersonation','Invoke-VoiceTroll','Invoke-WebRequest','Invoke-Whisker','Invoke-WinEnum','Invoke-winPEAS','Invoke-WireTap','Invoke-WmiCommand','Invoke-WMIMethod','Invoke-WScriptBypassUAC','Invoke-Zerologon','[IO.File]::SetCreationTime','[IO.File]::SetLastAccessTime','[IO.File]::SetLastWriteTime','IO.FileStream','ipmo "$Env:Appdata\\','ipmo ''$Env:Appdata\\','ipmo $Env:Appdata\\','ipmo "$Env:Temp\\','ipmo ''$Env:Temp\\','ipmo $Env:Temp\\','ipmo C:\\Users\\Public\\','iwr ','join','.kdb','.kdbx','kernel32','Keylogger','.LastAccessTime =','.LastWriteTime =','-like','Limit-EventLog ','/listcreds:','.Load','LoadLibrary','LoggedKeys',' logon_events ','LowThreatDefaultAction','ls','LSA_UNICODE_STRING','MailRaider','mattifestation','-Members ','memcpy','Metasploit','-Method ','-MethodName ','Microsoft.CSharp.CSharpCodeProvider','\Microsoft\\Edge\\User Data\Default','Microsoft.Office.Interop.Outlook','Microsoft.Office.Interop.Outlook.olDefaultFolders','Microsoft.Win32.UnsafeNativeMethods','Mimikatz','MiniDumpWriteDump','ModerateThreatDefaultAction','-ModuleName ','-ModulePath ','Mount-DiskImage ','Move-Item','\Mozilla\Firefox\Profiles','MSAcpi_ThermalZoneTemperature','mshta','.msi','msvcrt','MsXml2.','-NameSe','-Namesp','-NameSpace','-Namespace root/subscription ','Net.Security.RemoteCertificateValidationCallback','Net.WebClient','New-CimInstance ','New-DomainGroup','New-DomainUser','New-HoneyHash','New-Item','New-LocalUser','new-object','(New-Object System.Net.WebClient).DownloadString(''https://chocolatey.org/install.ps1'')','(New-Object System.Net.WebClient).DownloadString(''https://community.chocolatey.org/install.ps1','(New-Object System.Net.WebClient).DownloadString(''https://community.chocolatey.org/install.ps1'')','New-PSDrive','New-PSSession','New-ScheduledTask','New-ScheduledTaskAction','New-ScheduledTaskPrincipal','New-ScheduledTaskSettingsSet','New-ScheduledTaskTrigger','New-VM','Nishang',' -noni ','-noni',' -noninteractive ','-nop','-noprofile','NotAllNameSpaces','ntdll','OiCAAAAYInlM','OiJAAAAYInlM','-Online','OpenDesktop','OpenProcess','OpenProcessToken','OpenThreadToken','OpenWindowStation','\Opera Software\\Opera Stable\\Login Data','Out-CHM','OUT-DNSTXT','Out-File ','Out-HTA','Out-Minidump','Out-RundllCommand','Out-SCF','Out-SCT','Out-Shortcut','Out-WebQuery','Out-Word',' -p ','PAGE_EXECUTE_READ','Parse_Keys','.pass','-PassThru ','Password-List',' -Path ','-Path ','-Pattern ','.pdf','-port ','Port-Scan','- Post ','PowerBreach','powercat ','powercat.ps1',' power_off ','Powerpreter','powershell','PowerUp','PowerView','.ppt','.pptx','-pr ',' process_kill ','-Profile','PromptForCredential','Properties.name','.PropertiesToLoad.Add','-Property ','PS ATTACK!!!','-psprovider ','psreadline','PS_ScheduledTask','PtrToString',' Put ','QueueUserApc',' -R','_RastaMouse','-RawData ','ReadProcessMemory','ReadProcessMemory.Invoke','readtoend','-recurse',' -Recurse ','-Recurse','[Reflection.Assembly]::Load($','Reflection.Emit.AssemblyBuilderAccess','reg','Register-ScheduledTask','.RegisterXLL','Registry::','REGISTRY::HKLM\\SYSTEM\\CurrentControlSet\\Services\\',' registry_mod ','-RemoteFXvGPUDisablementFilePath',' remote_posh ','RemoteSigned','Remove-ADGroupMember','Remove-EtwTraceProvider ','Remove-EventLog ','Remove-FileShare','Remove-Item','Remove-LocalUser','Remove-Module','Remove-MpPreference','Remove-Persistence','Remove-PoshRat','Remove-RemoteConnection','Remove-SmbShare','Remove-Update','Remove-WmiObject','Rename-LocalUser','Request-SPNTicket','Resolve-IPAddress','RevertToSelf','rm','-root ','Root\\\Microsoft\\\Windows\\\TaskScheduler','.rtf','RtlCreateUserThread','.run','runAfterCancelProcess','rundll32','rundll32.exe','Run-EXEonRemote','Runtime.InteropServices.DllImportAttribute','SaveNothing',' sched_job ','-ScriptBlock ','secur32','SECURITY_DELEGATION','select-object','select-string ','.Send(','Send-MailMessage','SE_PRIVILEGE_ENABLED','-Server ',' service_mod ','set','Set-ADObject','set-content','Set-DCShadowPermissions','Set-DomainObject','Set-DomainUserPassword','Set-EtwTraceProvider ','Set-ExecutionPolicy','-ExecutionPolicy bypass','Set-ItemProperty','Set-LocalUser','Set-MacAttribute','Set-MpPreference','Set-NetFirewallProfile','Set-PSReadlineOption','Set-RemotePSRemoting','Set-RemoteWMI','SetThreadToken','Set-VMFirmware','Set-Wallpaper','shell32.dll','Shellcode32','Shellcode64','shellexec_rundll','.ShellExecute(','ShellSmartScreenLevel','Show-TargetScreen','SilentlyContinue','SMB1Protocol','\software\\','\\SOFTWARE\\Policies\\Microsoft\\Windows\\System','Start-BitsTransfer','Start-CaptureServer','Start-Dnscat2','Start-Process','Start-VM','Start-WebcamRecorder','-stream','StringtoBase64','SuspendThread','SyncAppvPublishingServer.exe','SyncInvoke','System.CodeDom.Compiler.CompilerParameters','System.DirectoryServices.AccountManagement','System.DirectoryServices.DirectorySearcher','System.DirectoryServices.Protocols.LdapConnection','System.DirectoryServices.Protocols.LdapDirectoryIdentifier','[System.Environment]::UserName','System.IdentityModel.Tokens.KerberosRequestorSecurityToken','system.io.compression.deflatestream','system.io.streamreader','[System.Net.HttpWebRequest]','System.Net.NetworkCredential','System.Net.NetworkInformation.Ping','System.Net.Security.SslStream','System.Net.Sockets.TcpListener','system.net.webclient','System.Net.WebClient','SystemParametersInfo(20,0,,3)','[System.Reflection.Assembly]::Load($','System.Reflection.Assembly.Load($','System.Reflection.AssemblyName','[System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())','[System.Security.Principal.WindowsIdentity]::GetCurrent()','System.Xml.XmlDocument',' -t ','TelnetServer','Test-AdminAccess','Test-NetConnection','text.encoding]::ascii','TexttoExe','TFTP','tifkin_','-Exec bypass','TOKEN_ADJUST_PRIVILEGES','TOKEN_ALL_ACCESS','TOKEN_ASSIGN_PRIMARY','TOKEN_DUPLICATE','TOKEN_ELEVATION','TOKEN_IMPERSONATE','TOKEN_INFORMATION_CLASS','TOKEN_PRIVILEGES','TOKEN_QUERY','.txt',"2013HistorySaveStyle",'-Unattended','Unblock-File ','Unrestricted','Update-Help','useraccountcontrol','-UserAgent ',' vacant_system ','value','-Value','vaultcmd','vbscript:createobject','VirtualAlloc','VirtualFree','VirtualProtect','"virus"','VolumeShadowCopyTools',' -w ','WaitForSingleObject','WallPaper','Web Credentials','wget ',' -w hidden ','Win32_ComputerSystem','Win32_Group','Win32_PnPEntity','Win32_Product ','Win32_QuickFixEngineering','win32_shadowcopy','Win32_Shadowcopy','(window.close)',' -window hidden ','Windows Credentials','Windows-Defender','Windows-Defender-ApplicationGuard','Windows-Defender-Features','Windows-Defender-Gui','Windows.Security.Credentials.PasswordVault','\Windows\\System32','\Windows\\SysWOW64','-windowstyle','WindowStyle',' -windowstyle hidden ','WMImplant','Write-ChocolateyWarning','Write-EventLog','WriteInt32','WriteProcessMemory','.xls','.xlsx','XmlHttp','ZeroFreeGlobalAllocUnicode','UploadData']

"""
all_suspicious = ["%comspec%", "wscript.exe", "regsvr32.exe", "mshta.exe", "\\csc.exe", 'whoami.exe', '\\pl.exe',
                  '\\nc.exe', 'nmap.exe', 'psexec.exe', 'psexesvc.exe', 'plink.exe', 'kali', 'mimikatz', 'procdump.exe',
                  'dcom.exe', 'Inveigh.exe', 'LockLess.exe', 'Logger.exe', 'PBind.exe', 'PS.exe', 'Rubeus.exe',
                  'RunasCs.exe', 'RunAs.exe', 'SafetyDump.exe', 'SafetyKatz.exe', 'Seatbelt.exe', 'SExec.exe',
                  'SharpApplocker.exe', 'SharpChrome.exe', ' SharpCOM.exe', 'SharpDPAPI.exe', 'SharpDump.exe',
                  'SharpEdge.exe', 'SharpEDRChecker.exe', ' SharPersist.exe', 'SharpHound.exe', 'SharpLogger.exe',
                  'SharpPrinter.exe', 'SharpRoast.exe', 'SharpSC.exe', 'SharpSniper.exe', 'SharpSocks.exe',
                  'SharpSSDP.exe', 'SharpTask.exe', 'SharpUp.exe', 'SharpView.exe', 'SharpWeb.exe',
                  'SharpWMI.exe', 'Shhmon.exe', 'SweetPotato.exe', 'Watson.exe', 'WExec.exe', '7zip.exe',
                  'FromBase64String', 'DomainPasswordSpray', 'PasswordSpray', 'Password', 'Get-WMIObject',
                  'Get-GPPPassword', 'Get-Keystrokes', 'Get-TimedScreenshot', 'Get-VaultCredential',
                  'Get-ServiceUnquoted', 'Get-ServiceEXEPerms', 'Get-ServicePerms', 'Get-RegAlwaysInstallElevated',
                  'Get-RegAutoLogon', 'Get-UnattendedInstallFiles', 'Get-Webconfig', 'Get-ApplicationHost',
                  'Get-PassHashes', 'Get-LsaSecret', 'Get-Information', 'Get-PSADForestInfo', 'Get-KerberosPolicy',
                  'Get-PSADForestKRBTGTInfo', 'Get-PSADForestInfo', 'Get-KerberosPolicy', 'Invoke-Command',
                  'Invoke-Expression', 'iex(', 'Invoke-Shellcode', 'Invoke--Shellcode', 'Invoke-ShellcodeMSIL',
                  'Invoke-MimikatzWDigestDowngrade', 'Invoke-NinjaCopy', 'Invoke-CredentialInjection',
                  'Invoke-TokenManipulation', 'Invoke-CallbackIEX', 'Invoke-PSInject', 'Invoke-DllEncode',
                  'Invoke-ServiceUserAdd', 'Invoke-ServiceCMD', 'Invoke-ServiceStart', 'Invoke-ServiceStop',
                  'Invoke-ServiceEnable', 'Invoke-ServiceDisable', 'Invoke-FindDLLHijack', 'Invoke-FindPathHijack',
                  'Invoke-AllChecks', 'Invoke-MassCommand', 'Invoke-MassMimikatz', 'Invoke-MassSearch',
                  'Invoke-MassTemplate', 'Invoke-MassTokens', 'Invoke-ADSBackdoor', 'Invoke-CredentialsPhish',
                  'Invoke-BruteForce', 'Invoke-PowerShellIcmp', 'Invoke-PowerShellUdp', 'Invoke-PsGcatAgent',
                  'Invoke-PoshRatHttps', 'Invoke-PowerShellTcp', 'Invoke-PoshRatHttp', 'Invoke-PowerShellWmi',
                  'Invoke-PSGcat', 'Invoke-Encode', 'Invoke-Decode', 'Invoke-CreateCertificate', 'Invoke-NetworkRelay',
                  'EncodedCommand', 'New-ElevatedPersistenceOption', 'wsman', 'Enter-PSSession', 'DownloadString',
                  'DownloadFile', 'Out-Word', 'Out-Excel', 'Out-Java', 'Out-Shortcut', 'Out-CHM', 'Out-HTA',
                  'Out-Minidump', 'HTTP-Backdoor', 'Find-AVSignature', 'DllInjection', 'ReflectivePEInjection',
                  'Base64', 'System.Reflection', 'System.Management', 'Restore-ServiceEXE', 'Add-ScrnSaveBackdoor',
                  'Gupt-Backdoor', 'Execute-OnTime', 'DNS_TXT_Pwnage', 'Write-UserAddServiceBinary',
                  'Write-CMDServiceBinary', 'Write-UserAddMSI', 'Write-ServiceEXE', 'Write-ServiceEXECMD',
                  'Enable-DuplicateToken', 'Remove-Update', 'Execute-DNSTXT-Code', 'Download-Execute-PS',
                  'Execute-Command-MSSQL', 'Download_Execute', 'Copy-VSS', 'Check-VM', 'Create-MultipleSessions',
                  'Run-EXEonRemote', 'Port-Scan', 'Remove-PoshRat', 'TexttoEXE', 'Base64ToString', 'StringtoBase64',
                  'Do-Exfiltration', 'Parse_Keys', 'Add-Exfiltration', 'Add-Persistence', 'Remove-Persistence',
                  'Find-PSServiceAccounts', 'Discover-PSMSSQLServers', 'Discover-PSMSExchangeServers',
                  'Discover-PSInterestingServices', 'Discover-PSMSExchangeServers', 'Discover-PSInterestingServices',
                  'Mimikatz', 'powercat', 'powersploit', 'PowershellEmpire', 'GetProcAddress', '.invoke', ' -e ',
                  'hidden', '-w hidden', 'Invoke-Obfuscation-master', 'Out-EncodedWhitespaceCommand', 'Out-Encoded',
                  "-EncodedCommand", "-enc", "-w hidden", "[Convert]::FromBase64String", "iex(", "New-Object",
                  "Net.WebClient", "-windowstyle hidden", "DownloadFile", "DownloadString", "Invoke-Expression",
                  "Net.WebClient", "-Exec bypass", "-ExecutionPolicy bypass", "-EncodedCommand", "-enc", "-w hidden",
                  "[Convert]::FromBase64String", "iex(", "New-Object", "Net.WebClient", "-windowstyle hidden",
                  "DownloadFile", "DownloadString", "Invoke-Expression", "Net.WebClient", "-Exec bypass",
                  "-ExecutionPolicy bypass",'Remove-Item']
"""

all_suspicious = ["%comspec%", "wscript.exe", "regsvr32.exe", "mshta.exe", "\\csc.exe", 'whoami.exe', '\\pl.exe',
                  '\\nc.exe', 'nmap.exe', 'psexec.exe', 'psexesvc.exe', 'plink.exe', 'kali', 'mimikatz', 'procdump.exe',
                  'dcom.exe', 'Inveigh.exe', 'LockLess.exe', 'Logger.exe', 'PBind.exe', 'PS.exe', 'Rubeus.exe',
                  'RunasCs.exe', 'RunAs.exe', 'SafetyDump.exe', 'SafetyKatz.exe', 'Seatbelt.exe', 'SExec.exe',
                  'SharpApplocker.exe', 'SharpChrome.exe', ' SharpCOM.exe', 'SharpDPAPI.exe', 'SharpDump.exe',
                  'SharpEdge.exe', 'SharpEDRChecker.exe', ' SharPersist.exe', 'SharpHound.exe', 'SharpLogger.exe',
                  'SharpPrinter.exe', 'SharpRoast.exe', 'SharpSC.exe', 'SharpSniper.exe', 'SharpSocks.exe',
                  'SharpSSDP.exe', 'SharpTask.exe', 'SharpUp.exe', 'SharpView.exe', 'SharpWeb.exe',
                  'SharpWMI.exe', 'Shhmon.exe', 'SweetPotato.exe', 'Watson.exe', 'WExec.exe', '7zip.exe',
                  'FromBase64String', 'DomainPasswordSpray', 'PasswordSpray', 'Password', 'Get-WMIObject',
                  'Get-GPPPassword', 'Get-Keystrokes', 'Get-TimedScreenshot', 'Get-VaultCredential',
                  'Get-ServiceUnquoted', 'Get-ServiceEXEPerms', 'Get-ServicePerms', 'Get-RegAlwaysInstallElevated',
                  'Get-RegAutoLogon', 'Get-UnattendedInstallFiles', 'Get-Webconfig', 'Get-ApplicationHost',
                  'Get-PassHashes', 'Get-LsaSecret', 'Get-Information', 'Get-PSADForestInfo', 'Get-KerberosPolicy',
                  'Get-PSADForestKRBTGTInfo', 'Get-PSADForestInfo', 'Get-KerberosPolicy', 'Invoke-Command',
                  'Invoke-Expression', 'iex(', 'Invoke-Shellcode', 'Invoke--Shellcode', 'Invoke-ShellcodeMSIL',
                  'Invoke-MimikatzWDigestDowngrade', 'Invoke-NinjaCopy', 'Invoke-CredentialInjection',
                  'Invoke-TokenManipulation', 'Invoke-CallbackIEX', 'Invoke-PSInject', 'Invoke-DllEncode',
                  'Invoke-ServiceUserAdd', 'Invoke-ServiceCMD', 'Invoke-ServiceStart', 'Invoke-ServiceStop',
                  'Invoke-ServiceEnable', 'Invoke-ServiceDisable', 'Invoke-FindDLLHijack', 'Invoke-FindPathHijack',
                  'Invoke-AllChecks', 'Invoke-MassCommand', 'Invoke-MassMimikatz', 'Invoke-MassSearch',
                  'Invoke-MassTemplate', 'Invoke-MassTokens', 'Invoke-ADSBackdoor', 'Invoke-CredentialsPhish',
                  'Invoke-BruteForce', 'Invoke-PowerShellIcmp', 'Invoke-PowerShellUdp', 'Invoke-PsGcatAgent',
                  'Invoke-PoshRatHttps', 'Invoke-PowerShellTcp', 'Invoke-PoshRatHttp', 'Invoke-PowerShellWmi',
                  'Invoke-PSGcat', 'Invoke-Encode', 'Invoke-Decode', 'Invoke-CreateCertificate', 'Invoke-NetworkRelay',
                  'EncodedCommand', 'New-ElevatedPersistenceOption', 'wsman', 'Enter-PSSession', 'DownloadString',
                  'DownloadFile', 'Out-Word', 'Out-Excel', 'Out-Java', 'Out-Shortcut', 'Out-CHM', 'Out-HTA',
                  'Out-Minidump', 'HTTP-Backdoor', 'Find-AVSignature', 'DllInjection', 'ReflectivePEInjection',
                  'Base64', 'System.Reflection', 'System.Management', 'Restore-ServiceEXE', 'Add-ScrnSaveBackdoor',
                  'Gupt-Backdoor', 'Execute-OnTime', 'DNS_TXT_Pwnage', 'Write-UserAddServiceBinary',
                  'Write-CMDServiceBinary', 'Write-UserAddMSI', 'Write-ServiceEXE', 'Write-ServiceEXECMD',
                  'Enable-DuplicateToken', 'Remove-Update', 'Execute-DNSTXT-Code', 'Download-Execute-PS',
                  'Execute-Command-MSSQL', 'Download_Execute', 'Copy-VSS', 'Check-VM', 'Create-MultipleSessions',
                  'Run-EXEonRemote', 'Port-Scan', 'Remove-PoshRat', 'TexttoEXE', 'Base64ToString', 'StringtoBase64',
                  'Do-Exfiltration', 'Parse_Keys', 'Add-Exfiltration', 'Add-Persistence', 'Remove-Persistence',
                  'Find-PSServiceAccounts', 'Discover-PSMSSQLServers', 'Discover-PSMSExchangeServers',
                  'Discover-PSInterestingServices', 'Discover-PSMSExchangeServers', 'Discover-PSInterestingServices',
                  'Mimikatz', 'powercat', 'powersploit', 'PowershellEmpire', 'GetProcAddress', '.invoke', ' -e ',
                  'hidden', '-w hidden', 'Invoke-Obfuscation-master', 'Out-EncodedWhitespaceCommand', 'Out-Encoded',
                  "-EncodedCommand", "-enc", "-w hidden", "[Convert]::FromBase64String", "iex(", "New-Object",
                  "Net.WebClient", "-windowstyle hidden", "DownloadFile", "DownloadString", "Invoke-Expression",
                  "Net.WebClient", "-Exec bypass", "-ExecutionPolicy bypass", "-EncodedCommand", "-enc", "-w hidden",
                  "[Convert]::FromBase64String", "iex(", "New-Object", "Net.WebClient", "-windowstyle hidden",
                  "DownloadFile", "DownloadString", "Invoke-Expression", "Net.WebClient", "-Exec bypass",
                  ]

# all_suspicious_powershell = ["%comspec%", "wscript.exe", "regsvr32.exe", "mshta.exe", "\\csc.exe", 'whoami.exe', '\\pl.exe',
#                   '\\nc.exe', 'nmap.exe', 'psexec.exe', 'psexesvc.exe', 'plink.exe', 'kali', 'mimikatz', 'procdump.exe',
#                   'dcom.exe', 'Inveigh.exe', 'LockLess.exe', 'Logger.exe', 'PBind.exe', 'Rubeus.exe',
#                   'RunasCs.exe', 'RunAs.exe', 'SafetyDump.exe', 'SafetyKatz.exe', 'Seatbelt.exe', 'SExec.exe',
#                   'SharpApplocker.exe', 'SharpChrome.exe', ' SharpCOM.exe', 'SharpDPAPI.exe', 'SharpDump.exe',
#                   'SharpEdge.exe', 'SharpEDRChecker.exe', ' SharPersist.exe', 'SharpHound.exe', 'SharpLogger.exe',
#                   'SharpPrinter.exe', 'SharpRoast.exe', 'SharpSC.exe', 'SharpSniper.exe', 'SharpSocks.exe',
#                   'SharpSSDP.exe', 'SharpTask.exe', 'SharpUp.exe', 'SharpView.exe', 'SharpWeb.exe',
#                   'SharpWMI.exe', 'Shhmon.exe', 'SweetPotato.exe', 'Watson.exe', 'WExec.exe', '7zip.exe',
#                   'FromBase64String', 'DomainPasswordSpray', 'PasswordSpray', 'Password', 'Get-WMIObject',
#                   'Get-GPPPassword', 'Get-Keystrokes', 'Get-TimedScreenshot', 'Get-VaultCredential',
#                   'Get-ServiceUnquoted', 'Get-ServiceEXEPerms', 'Get-ServicePerms', 'Get-RegAlwaysInstallElevated',
#                   'Get-RegAutoLogon', 'Get-UnattendedInstallFiles', 'Get-Webconfig', 'Get-ApplicationHost',
#                   'Get-PassHashes', 'Get-LsaSecret', 'Get-Information', 'Get-PSADForestInfo', 'Get-KerberosPolicy',
#                   'Get-PSADForestKRBTGTInfo', 'Get-PSADForestInfo', 'Get-KerberosPolicy', 'Invoke-Command',
#                   'Invoke-Expression', 'iex(', 'Invoke-Shellcode', 'Invoke--Shellcode', 'Invoke-ShellcodeMSIL',
#                   'Invoke-MimikatzWDigestDowngrade', 'Invoke-NinjaCopy', 'Invoke-CredentialInjection',
#                   'Invoke-TokenManipulation', 'Invoke-CallbackIEX', 'Invoke-PSInject', 'Invoke-DllEncode',
#                   'Invoke-ServiceUserAdd', 'Invoke-ServiceCMD', 'Invoke-ServiceStart', 'Invoke-ServiceStop',
#                   'Invoke-ServiceEnable', 'Invoke-ServiceDisable', 'Invoke-FindDLLHijack', 'Invoke-FindPathHijack',
#                   'Invoke-AllChecks', 'Invoke-MassCommand', 'Invoke-MassMimikatz', 'Invoke-MassSearch',
#                   'Invoke-MassTemplate', 'Invoke-MassTokens', 'Invoke-ADSBackdoor', 'Invoke-CredentialsPhish',
#                   'Invoke-BruteForce', 'Invoke-PowerShellIcmp', 'Invoke-PowerShellUdp', 'Invoke-PsGcatAgent',
#                   'Invoke-PoshRatHttps', 'Invoke-PowerShellTcp', 'Invoke-PoshRatHttp', 'Invoke-PowerShellWmi',
#                   'Invoke-PSGcat', 'Invoke-Encode', 'Invoke-Decode', 'Invoke-CreateCertificate', 'Invoke-NetworkRelay',
#                   'EncodedCommand', 'New-ElevatedPersistenceOption', 'wsman', 'Enter-PSSession', 'DownloadString',
#                   'DownloadFile', 'Out-Word', 'Out-Excel', 'Out-Java', 'Out-Shortcut', 'Out-CHM', 'Out-HTA',
#                   'Out-Minidump', 'HTTP-Backdoor', 'Find-AVSignature', 'DllInjection', 'ReflectivePEInjection',
#                   'Base64', 'System.Reflection', 'System.Management', 'Restore-ServiceEXE', 'Add-ScrnSaveBackdoor',
#                   'Gupt-Backdoor', 'Execute-OnTime', 'DNS_TXT_Pwnage', 'Write-UserAddServiceBinary',
#                   'Write-CMDServiceBinary', 'Write-UserAddMSI', 'Write-ServiceEXE', 'Write-ServiceEXECMD',
#                   'Enable-DuplicateToken', 'Remove-Update', 'Execute-DNSTXT-Code', 'Download-Execute-PS',
#                   'Execute-Command-MSSQL', 'Download_Execute', 'Copy-VSS', 'Check-VM', 'Create-MultipleSessions',
#                   'Run-EXEonRemote', 'Port-Scan', 'Remove-PoshRat', 'TexttoEXE', 'Base64ToString', 'StringtoBase64',
#                   'Do-Exfiltration', 'Parse_Keys', 'Add-Exfiltration', 'Add-Persistence', 'Remove-Persistence',
#                   'Find-PSServiceAccounts', 'Discover-PSMSSQLServers', 'Discover-PSMSExchangeServers',
#                   'Discover-PSInterestingServices', 'Discover-PSMSExchangeServers', 'Discover-PSInterestingServices',
#                   'Mimikatz', 'powercat', 'powersploit', 'PowershellEmpire', 'GetProcAddress', '.invoke', ' -e ',
#                   'hidden', '-w hidden', 'Invoke-Obfuscation-master', 'Out-EncodedWhitespaceCommand', 'Out-Encoded',
#                   "-EncodedCommand", "-enc", "-w hidden", "[Convert]::FromBase64String", "iex(", "New-Object",
#                   "Net.WebClient", "-windowstyle hidden", "DownloadFile", "DownloadString", "Invoke-Expression",
#                   "Net.WebClient", "-Exec bypass", "-EncodedCommand", "-enc", "-w hidden",
#                   "[Convert]::FromBase64String", "iex(", "New-Object", "Net.WebClient", "-windowstyle hidden",
#                   "DownloadFile", "DownloadString", "Invoke-Expression", "Net.WebClient", "-Exec bypass",
#                   "-ExecutionPolicy",'Remove-Item','""','&&','$DoIt','$env:ComSpec','$env:COR_ENABLE_PROFILING','$env:COR_PROFILER','$env:COR_PROFILER_PATH','> $env:TEMP\\','$env:TEMP\\','$env:UserName','$profile','0x11','0xdeadbeef',' 443 ',' 80 ','AAAAYInlM','AcceptTcpClient',' active_users ','Add-ConstrainedDelegationBackdoor','add-content','Add-Content','Add-DnsClientNrptRule','Add-DomainGroupMember','Add-DomainObjectAcl','Add-Exfiltration','Add-ObjectAcl','Add-Persistence','Add-RegBackdoor','Add-RemoteConnection','Add-ScrnSaveBackdoor','AddSecurityPackage','AdjustTokenPrivileges','ADRecon-Report.xlsx','Advapi32','-All ','Allow','-AnswerFile','\AppData\\Roaming\\Code\\','-append','.application','-ArgumentList ','-AttackSurfaceReductionRules_Actions ','-AttackSurfaceReductionRules_Ids ','.AuthenticateAsClient','-band',' basic_info ','.bat','bxor','bypass',' -c ','"carbonblack"','Cert:\\LocalMachine\\Root',' change_user ','char','-CheckForSignaturesBeforeRunningScan ','Check-VM','-ClassName ','-ClassName','-ClassName CommandLineEventConsumer ','-ClassName __EventFilter ','Clear-EventLog ','Clear-History','Clear-WinEvent ','ClientAccessible','CL_Invocation.ps1','CL_Mutexverifiers.ps1','CloseHandle','.cmd','CmdletsToExport','Collections.ArrayList',' command_exec ','-ComObject ','-ComObject','-comobject outlook.application','Compress-Archive ','Compress-Archive',' -ComputerName ','-ComputerName ','comspec','ConsoleHost_history.txt','-ControlledFolderAccessProtectedFolders ','Convert-ADName','[Convert]::FromBase64String','ConvertFrom-UACValue','Convert-NameToSid','ConvertTo-SID','.CopyFromScreen','Copy-Item ','Copy-Item','# Copyright 2016 Amazon.com, Inc. or its affiliates. All','Copy-VSS','C:\\ProgramData\\Amazon\\EC2-Windows\\Launch\\Module\\',').Create(','Create-MultipleSessions','CreateProcessWithToken','CreateRemoteThread','CreateThread','CreateUserThread','.CreationTime =','curl ','CurrentVersion\\Winlogon','C:\\Windows\\Diagnostics\\System\\PCW','"cylance"',' -d ','DangerousGetHandle','DataToEncode','"defender"','del','.Delete()','Delete()','.Description','-Destination ','-Destination',' -DestinationPath ','DisableArchiveScanning $true','DisableArchiveScanning 1','DisableBehaviorMonitoring $true','DisableBehaviorMonitoring 1','DisableBlockAtFirstSeen $true','DisableBlockAtFirstSeen 1','DisableIntrusionPreventionSystem $true','DisableIntrusionPreventionSystem 1','DisableIOAVProtection $true','DisableIOAVProtection 1','Disable-LocalUser','DisableRealtimeMonitoring $true','DisableRealtimeMonitoring 1','DisableRemovableDriveScanning $true','DisableRemovableDriveScanning 1','DisableScanningMappedNetworkDrivesForFullScan $true','DisableScanningMappedNetworkDrivesForFullScan 1','DisableScanningNetworkFiles $true','DisableScanningNetworkFiles 1','DisableScriptScanning $true','DisableScriptScanning 1',' disable_wdigest ','Disable-WindowsOptionalFeature',' disable_winrm ','DNS_TXT_Pwnage','.doc','.docx','DoesNotRequirePreAuth','Do-Exfiltration',' -doh ','.download','.Download','Download_Execute','Download-Execute-PS','.DownloadFile(','.DownloadString(','.DriveLetter','DumpCerts','DumpCreds','DuplicateTokenEx','-Enabled','Enabled-DuplicateToken','Enable-Duplication','Enable-LocalUser','Enable-PSRemoting ','EnableSmartScreen',' enable_wdigest ','Enable-WindowsOptionalFeature',' enable_winrm ',' -enc ','-Enc',' -EncodedCommand ','EnumerateSecurityPackages','-ep','-ErrorAction ',' -ErrorAction SilentlyContinue','Execute-Command-MSSQL','Execute-DNSTXT-Code','Execute-OnTime','ExetoText','exfill','ExfilOption','Exploit-Jboss','Export-PfxCertificate','Export-PowerViewCSV','-f ','Failed to update Help for the module','FakeDC','False','-FeatureName','-FilePath ','-FilePath "$env:comspec" ','filesystem','-Filter',' -Filter Bookmarks','.findall()','Find-DomainLocalGroupMember','Find-DomainObjectPropertyOutlier','Find-DomainProcess','Find-DomainShare','Find-DomainUserEvent','Find-DomainUserLocation','Find-ForeignGroup','Find-ForeignUser','Find-Fruit','Find-GPOComputerAdmin','Find-GPOLocation','Find-InterestingDomainAcl','Find-InterestingDomainShareFile','Find-InterestingFile','Find-LocalAdminAccess','Find-ManagedSecurityGroups','Find-TrustedDocuments','FireBuster','FireListener',' -Force','foreach','format-table','FreeHGlobal','FreeLibrary','Function Get-ADRExcelComOb','gci',' gen_cli ','get-acl','Get-AdComputer ','Get-AdDefaultDomainPasswordPolicy','Get-AdGroup ','Get-ADObject','get-ADPrincipalGroupMembership','Get-ADRDomainController','Get-ADReplAccount','Get-ADRGPO','get-aduser','Get-ADUser','Get-ApplicationHost','Get-CachedRDPConnection','get-childitem','Get-ChildItem ','Get-ChildItem','Get-ChromeDump','Get-ClipboardContents','Get-CredManCreds','GetDelegateForFunctionPointer','Get-DFSshare','Get-DNSRecord','Get-DNSZone','Get-Domain','Get-DomainComputer','Get-DomainController','Get-DomainDFSShare','Get-DomainDNSRecord','Get-DomainDNSZone','Get-DomainFileServer','Get-DomainForeignGroupMember','Get-DomainForeignUser','Get-DomainGPO','Get-DomainGPOComputerLocalGroupMapping','Get-DomainGPOLocalGroup','Get-DomainGPOUserLocalGroupMapping','Get-DomainGroup','Get-DomainGroupMember','Get-DomainManagedSecurityGroup','Get-DomainObject','Get-DomainObjectAcl','Get-DomainOU','Get-DomainPolicy','Get-DomainSID','Get-DomainSite','Get-DomainSPNTicket','Get-DomainSubnet','Get-DomainTrust','Get-DomainTrustMapping','Get-DomainUser','Get-DomainUserEvent','Get-Forest','Get-ForestDomain','Get-ForestGlobalCatalog','Get-ForestTrust','Get-FoxDump','Get-GPO','Get-GPPPassword','Get-Inbox.ps1','Get-IndexedItem','Get-Information','Get-IPAddress','get-itemProperty','Get-ItemProperty','Get-Keystrokes','Get-LastLoggedOn','get-localgroup','Get-LocalGroupMember','Get-LocalUser','Get-LoggedOnLocal','GetLogonSessionData','Get-LSASecret','GetModuleHandle','Get-NetComputer','Get-NetComputerSiteName','Get-NetDomain','Get-NetDomainController','Get-NetDomainTrust','Get-NetFileServer','Get-NetForest','Get-NetForestCatalog','Get-NetForestDomain','Get-NetForestTrust','Get-NetGPO','Get-NetGPOGroup','Get-NetGroup','Get-NetGroupMember','Get-NetLocalGroup','Get-NetLocalGroupMember','Get-NetLoggedon','Get-NetOU','Get-NetProcess','Get-NetRDPSession','Get-NetSession','Get-NetShare','Get-NetSite','Get-NetSubnet','Get-NetUser','Get-ObjectAcl','Get-PassHashes','Get-PassHints','Get-PasswordVaultCredentials','Get-PathAcl','GetProcAddress','Get-ProcAddress user32.dll GetAsyncKeyState','Get-ProcAddress user32.dll GetForegroundWindow','get-process','Get-Process ','Get-Process','GetProcessHandle','Get-Process lsass','Get-Proxy','(Get-PSReadlineOption).HistorySavePath','Get-RegAlwaysInstallElevated','Get-RegAutoLogon','Get-RegistryMountedDrive','Get-RegLoggedOn','Get-RickAstley','Get-Screenshot','Get-SecurityPackages','Get-Service ','Get-ServiceFilePermission','Get-ServicePermission','Get-ServiceUnquoted','Get-SiteListPassword','Get-SiteName','get-smbshare','Get-StorageDiagnosticInfo','Get-System','Get-SystemDriveInfo','Get-TimedScreenshot','GetTokenInformation','::GetTypeFromCLSID(','Get-UnattendedInstallFile','Get-Unconstrained','Get-USBKeystrokes','Get-UserEvent','Get-VaultCredential','Get-Volume','Get-VulnAutoRun','Get-VulnSchTask','Get-Web-Credentials','Get-WLAN-Keys','Get-WmiObject','Get-WMIObject','Get-WMIProcess','Get-WMIRegCachedRDPConnection','Get-WMIRegLastLoggedOn','Get-WMIRegMountedDrive','Get-WMIRegProxy','\Google\\Chrome\\User Data\\Default\\Login Data','\\Google\\Chrome\\User Data\Default\Login Data For Account','GroupPolicyRefreshTime','GroupPolicyRefreshTimeDC','GroupPolicyRefreshTimeOffset','GroupPolicyRefreshTimeOffsetDC','Gupt-Backdoor','gwmi','harmj0y','hidden','Hidden','HighThreatDefaultAction','-HistorySaveStyle','HKCU:\\','HKCU\\software\\microsoft\\windows\\currentversion\\run','HKEY_CURRENT_USER\Control Panel\Desktop\\','HKLM:\\','HotFixID','http://127.0.0.1','HTTP-Backdoor','HTTP-Login',' -i ','-Identity ','iex(','IMAGE_NT_OPTIONAL_HDR64_MAGIC','-ImagePath ','ImpersonateLoggedOnUser','Import-Certificate','Import-Module "$Env:Appdata\\','Import-Module','$Env:Temp\\','Import-Module ''$Env:Temp\\','Import-Module C:\\Users\\Public\\',' -Include ','-IncludeLiveDump','Install-ServiceBinary','Install-SSP','Internet-Explorer-Optional-amd64','invoke','Invoke-ACLScanner','Invoke-ADSBackdoor','Invoke-AllChecks','Invoke-AmsiBypass','Invoke-ARPScan','Invoke-AzureHound','Invoke-BackdoorLNK','Invoke-BadPotato','Invoke-BetterSafetyKatz','Invoke-BruteForce','Invoke-BypassUAC','Invoke-Carbuncle','Invoke-Certify','Invoke-CheckLocalAdminAccess','Invoke-CimMethod ','Invoke-CimMethod','invoke-command ','Invoke-CredentialInjection','Invoke-CredentialsPhish','Invoke-DAFT','Invoke-DCSync','Invoke-Decode','Invoke-DinvokeKatz','Invoke-DllInjection','Invoke-DNSExfiltrator','Invoke-DowngradeAccount','Invoke-EgressCheck','Invoke-Encode','Invoke-EnumerateLocalAdmin','Invoke-EventHunter','Invoke-Eyewitness','Invoke-FakeLogonScreen','Invoke-Farmer','Invoke-FileFinder','Invoke-Get-RBCD-Threaded','Invoke-Gopher','Invoke-GPOLinks','Invoke-Grouper2','Invoke-HandleKatz','Invoke-Interceptor','Invoke-Internalmonologue','Invoke-Inveigh','Invoke-InveighRelay','invoke-item ','Invoke-JSRatRegsvr','Invoke-JSRatRundll','Invoke-Kerberoast','Invoke-KrbRelayUp','Invoke-LdapSignCheck','Invoke-Lockless','Invoke-MapDomainTrust','Invoke-Mimikatz','Invoke-MimikatzWDigestDowngrade','Invoke-Mimikittenz','Invoke-MITM6','Invoke-NanoDump','Invoke-NetRipper','Invoke-NetworkRelay','Invoke-Nightmare','Invoke-NinjaCopy','Invoke-OxidResolver','Invoke-P0wnedshell','Invoke-Paranoia','Invoke-PortScan','Invoke-PoshRatHttp','Invoke-PoshRatHttps','Invoke-PostExfil','Invoke-Potato','Invoke-PowerDump','Invoke-PowerShellIcmp','Invoke-PowerShellTCP','Invoke-PowerShellUdp','Invoke-PowerShellWMI','Invoke-PPLDump','Invoke-Prasadhak','Invoke-ProcessHunter','Invoke-PsExec','Invoke-PSGcat','Invoke-PsGcatAgent','Invoke-PSInject','Invoke-PsUaCme','Invoke-ReflectivePEInjection','Invoke-ReverseDNSLookup','Invoke-RevertToSelf','Invoke-Rubeus','Invoke-RunAs','Invoke-SafetyKatz','Invoke-SauronEye','Invoke-SCShell','Invoke-Seatbelt','Invoke-ServiceAbuse','Invoke-SessionGopher','Invoke-ShareFinder','Invoke-SharpAllowedToAct','Invoke-SharpBlock','Invoke-SharpBypassUAC','Invoke-SharpChromium','Invoke-SharpClipboard','Invoke-SharpCloud','Invoke-SharpDPAPI','Invoke-SharpDump','Invoke-SharPersist','Invoke-SharpGPOAbuse','Invoke-SharpGPO-RemoteAccessPolicies','Invoke-SharpHandler','Invoke-SharpHide','Invoke-Sharphound2','Invoke-Sharphound3','Invoke-SharpHound4','Invoke-SharpImpersonation','Invoke-SharpImpersonationNoSpace','Invoke-SharpKatz','Invoke-SharpLdapRelayScan','Invoke-Sharplocker','Invoke-SharpLoginPrompt','Invoke-SharpMove','Invoke-SharpPrinter','Invoke-SharpPrintNightmare','Invoke-SharpRDP','Invoke-SharpSecDump','Invoke-Sharpshares','Invoke-SharpSniper','Invoke-SharpSploit','Invoke-SharpSpray','Invoke-SharpSSDP','Invoke-SharpStay','Invoke-SharpUp','Invoke-Sharpview','Invoke-SharpWatson','Invoke-Sharpweb','Invoke-Shellcode','Invoke-SMBAutoBrute','Invoke-SMBScanner','Invoke-Snaffler','Invoke-Spoolsample','Invoke-SSHCommand','Invoke-SSIDExfil','Invoke-StandIn','Invoke-StickyNotesExtract','Invoke-Tater','Invoke-Thunderfox','Invoke-ThunderStruck','Invoke-TokenManipulation','Invoke-Tokenvator','Invoke-TroubleshootingPack','Invoke-UrbanBishop','Invoke-UserHunter','Invoke-UserImpersonation','Invoke-VoiceTroll','Invoke-WebRequest','Invoke-Whisker','Invoke-WinEnum','Invoke-winPEAS','Invoke-WireTap','Invoke-WmiCommand','Invoke-WMIMethod','Invoke-WScriptBypassUAC','Invoke-Zerologon','[IO.File]::SetCreationTime','[IO.File]::SetLastAccessTime','[IO.File]::SetLastWriteTime','IO.FileStream','ipmo "$Env:Appdata\\','ipmo ''$Env:Appdata\\','ipmo $Env:Appdata\\','ipmo "$Env:Temp\\','ipmo ''$Env:Temp\\','ipmo $Env:Temp\\','ipmo C:\\Users\\Public\\','iwr ','join','.kdb','.kdbx','kernel32','Keylogger','.LastAccessTime =','.LastWriteTime =','-like','Limit-EventLog ','/listcreds:','.Load','LoadLibrary','LoggedKeys',' logon_events ','LowThreatDefaultAction','LSA_UNICODE_STRING','MailRaider','mattifestation','-Members ','memcpy','Metasploit','-Method ','-MethodName ','Microsoft.CSharp.CSharpCodeProvider','\Microsoft\\Edge\\User Data\Default','Microsoft.Office.Interop.Outlook','Microsoft.Office.Interop.Outlook.olDefaultFolders','Microsoft.Win32.UnsafeNativeMethods','Mimikatz','MiniDumpWriteDump','ModerateThreatDefaultAction','-ModuleName ','-ModulePath ','Mount-DiskImage ','Move-Item','\Mozilla\Firefox\Profiles','MSAcpi_ThermalZoneTemperature','mshta','.msi','msvcrt','MsXml2.','-NameSe','-Namesp','-NameSpace','-Namespace root/subscription ','Net.Security.RemoteCertificateValidationCallback','Net.WebClient','New-CimInstance ','New-DomainGroup','New-DomainUser','New-HoneyHash','New-Item','New-LocalUser','new-object','(New-Object System.Net.WebClient).DownloadString(''https://chocolatey.org/install.ps1'')','(New-Object System.Net.WebClient).DownloadString(''https://community.chocolatey.org/install.ps1','(New-Object System.Net.WebClient).DownloadString(''https://community.chocolatey.org/install.ps1'')','New-PSDrive','New-PSSession','New-ScheduledTask','New-ScheduledTaskAction','New-ScheduledTaskPrincipal','New-ScheduledTaskSettingsSet','New-ScheduledTaskTrigger','New-VM','Nishang',' -noni ','-noni',' -noninteractive ','-nop','-noprofile','NotAllNameSpaces','ntdll','OiCAAAAYInlM','OiJAAAAYInlM','-Online','OpenDesktop','OpenProcess','OpenProcessToken','OpenThreadToken','OpenWindowStation','\Opera Software\\Opera Stable\\Login Data','Out-CHM','OUT-DNSTXT','Out-File ','Out-HTA','Out-Minidump','Out-RundllCommand','Out-SCF','Out-SCT','Out-Shortcut','Out-WebQuery','Out-Word',' -p ','PAGE_EXECUTE_READ','Parse_Keys','.pass','-PassThru ','Password-List','-Pattern ','.pdf','-port ','Port-Scan','-Post ','PowerBreach','powercat ','powercat.ps1',' power_off ','Powerpreter','PowerUp','PowerView','.ppt','.pptx','-pr ',' process_kill ','-Profile','PromptForCredential','Properties.name','.PropertiesToLoad.Add','-Property ','PS ATTACK!!!','-psprovider ','psreadline','PS_ScheduledTask','PtrToString',' Put ','QueueUserApc',' -R','_RastaMouse','-RawData ','ReadProcessMemory','ReadProcessMemory.Invoke','readtoend','-recurse',' -Recurse ','-Recurse','[Reflection.Assembly]::Load($','Reflection.Emit.AssemblyBuilderAccess','Register-ScheduledTask','.RegisterXLL','Registry::','REGISTRY::HKLM\\SYSTEM\\CurrentControlSet\\Services\\',' registry_mod ','-RemoteFXvGPUDisablementFilePath',' remote_posh ','RemoteSigned','Remove-ADGroupMember','Remove-EtwTraceProvider ','Remove-EventLog ','Remove-FileShare','Remove-Item','Remove-LocalUser','Remove-Module','Remove-MpPreference','Remove-Persistence','Remove-PoshRat','Remove-RemoteConnection','Remove-SmbShare','Remove-Update','Remove-WmiObject','Rename-LocalUser','Request-SPNTicket','Resolve-IPAddress','RevertToSelf','-root ','Root\\\Microsoft\\\Windows\\\TaskScheduler','.rtf','RtlCreateUserThread','.run','runAfterCancelProcess','rundll32','rundll32.exe','Run-EXEonRemote','Runtime.InteropServices.DllImportAttribute','SaveNothing',' sched_job ','-ScriptBlock ','secur32','SECURITY_DELEGATION','select-object','select-string ','.Send(','Send-MailMessage','SE_PRIVILEGE_ENABLED','-Server ',' service_mod ','set','Set-ADObject','set-content','Set-DCShadowPermissions','Set-DomainObject','Set-DomainUserPassword','Set-EtwTraceProvider ','Set-ExecutionPolicy','-ExecutionPolicy bypass','Set-ItemProperty','Set-LocalUser','Set-MacAttribute','Set-MpPreference','Set-NetFirewallProfile','Set-PSReadlineOption','Set-RemotePSRemoting','Set-RemoteWMI','SetThreadToken','Set-VMFirmware','Set-Wallpaper','shell32.dll','Shellcode32','Shellcode64','shellexec_rundll','.ShellExecute(','ShellSmartScreenLevel','Show-TargetScreen','SilentlyContinue','SMB1Protocol','\software\\','\\SOFTWARE\\Policies\\Microsoft\\Windows\\System','Start-BitsTransfer','Start-CaptureServer','Start-Dnscat2','Start-Process','Start-VM','Start-WebcamRecorder','-stream','StringtoBase64','SuspendThread','SyncAppvPublishingServer.exe','SyncInvoke','System.CodeDom.Compiler.CompilerParameters','System.DirectoryServices.AccountManagement','System.DirectoryServices.DirectorySearcher','System.DirectoryServices.Protocols.LdapConnection','System.DirectoryServices.Protocols.LdapDirectoryIdentifier','[System.Environment]::UserName','System.IdentityModel.Tokens.KerberosRequestorSecurityToken','system.io.compression.deflatestream','system.io.streamreader','[System.Net.HttpWebRequest]','System.Net.NetworkCredential','System.Net.NetworkInformation.Ping','System.Net.Security.SslStream','System.Net.Sockets.TcpListener','system.net.webclient','System.Net.WebClient','SystemParametersInfo(20,0,,3)','[System.Reflection.Assembly]::Load($','System.Reflection.Assembly.Load($','System.Reflection.AssemblyName','[System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())','[System.Security.Principal.WindowsIdentity]::GetCurrent()','System.Xml.XmlDocument','TelnetServer','Test-AdminAccess','Test-NetConnection','text.encoding]::ascii','TexttoExe','TFTP','tifkin_','-Exec bypass','TOKEN_ADJUST_PRIVILEGES','TOKEN_ALL_ACCESS','TOKEN_ASSIGN_PRIMARY','TOKEN_DUPLICATE','TOKEN_ELEVATION','TOKEN_IMPERSONATE','TOKEN_INFORMATION_CLASS','TOKEN_PRIVILEGES','TOKEN_QUERY','.txt',"2013HistorySaveStyle",'-Unattended','Unblock-File ','Unrestricted','Update-Help','useraccountcontrol','-UserAgent ',' vacant_system ','-Value','vaultcmd','vbscript:createobject','VirtualAlloc','VirtualFree','VirtualProtect','"virus"','VolumeShadowCopyTools',' -w ','WaitForSingleObject','WallPaper','Web Credentials','wget ',' -w hidden ','Win32_ComputerSystem','Win32_Group','Win32_PnPEntity','Win32_Product ','Win32_QuickFixEngineering','win32_shadowcopy','Win32_Shadowcopy','(window.close)',' -window hidden ','Windows Credentials','Windows-Defender','Windows-Defender-ApplicationGuard','Windows-Defender-Features','import-module ActiveDirectory','Windows-Defender-Gui','Windows.Security.Credentials.PasswordVault','\Windows\\System32','\Windows\\SysWOW64','-windowstyle','WindowStyle',' -windowstyle hidden ','WMImplant','Write-ChocolateyWarning','Write-EventLog','WriteInt32','WriteProcessMemory','.xls','.xlsx','XmlHttp','ZeroFreeGlobalAllocUnicode','UploadData']

all_suspicious_powershell = ["%comspec%", "wscript.exe", "regsvr32.exe", "mshta.exe", "\\csc.exe", 'whoami.exe', '\\pl.exe',
                  '\\nc.exe', 'nmap.exe', 'psexec.exe', 'psexesvc.exe', 'plink.exe', 'kali', 'mimikatz', 'procdump.exe',
                  'dcom.exe', 'Inveigh.exe', 'LockLess.exe', 'Logger.exe', 'PBind.exe', 'Rubeus.exe',
                  'RunasCs.exe', 'RunAs.exe', 'SafetyDump.exe', 'SafetyKatz.exe', 'Seatbelt.exe', 'SExec.exe',
                  'SharpApplocker.exe', 'SharpChrome.exe', ' SharpCOM.exe', 'SharpDPAPI.exe', 'SharpDump.exe',
                  'SharpEdge.exe', 'SharpEDRChecker.exe', ' SharPersist.exe', 'SharpHound.exe', 'SharpLogger.exe',
                  'SharpPrinter.exe', 'SharpRoast.exe', 'SharpSC.exe', 'SharpSniper.exe', 'SharpSocks.exe',
                  'SharpSSDP.exe', 'SharpTask.exe', 'SharpUp.exe', 'SharpView.exe', 'SharpWeb.exe',
                  'SharpWMI.exe', 'Shhmon.exe', 'SweetPotato.exe', 'Watson.exe', 'WExec.exe', '7zip.exe',
                  'FromBase64String', 'DomainPasswordSpray', 'PasswordSpray', 'Password', 'Get-WMIObject',
                  'Get-GPPPassword', 'Get-Keystrokes', 'Get-TimedScreenshot', 'Get-VaultCredential',
                  'Get-ServiceUnquoted', 'Get-ServiceEXEPerms', 'Get-ServicePerms', 'Get-RegAlwaysInstallElevated',
                  'Get-RegAutoLogon', 'Get-UnattendedInstallFiles', 'Get-Webconfig', 'Get-ApplicationHost',
                  'Get-PassHashes', 'Get-LsaSecret', 'Get-Information', 'Get-PSADForestInfo', 'Get-KerberosPolicy',
                  'Get-PSADForestKRBTGTInfo', 'Get-PSADForestInfo', 'Get-KerberosPolicy', 'Invoke-Command',
                  'Invoke-Expression', 'iex(', 'Invoke-Shellcode', 'Invoke--Shellcode', 'Invoke-ShellcodeMSIL',
                  'Invoke-MimikatzWDigestDowngrade', 'Invoke-NinjaCopy', 'Invoke-CredentialInjection',
                  'Invoke-TokenManipulation', 'Invoke-CallbackIEX', 'Invoke-PSInject', 'Invoke-DllEncode',
                  'Invoke-ServiceUserAdd', 'Invoke-ServiceCMD', 'Invoke-ServiceStart', 'Invoke-ServiceStop',
                  'Invoke-ServiceEnable', 'Invoke-ServiceDisable', 'Invoke-FindDLLHijack', 'Invoke-FindPathHijack',
                  'Invoke-AllChecks', 'Invoke-MassCommand', 'Invoke-MassMimikatz', 'Invoke-MassSearch',
                  'Invoke-MassTemplate', 'Invoke-MassTokens', 'Invoke-ADSBackdoor', 'Invoke-CredentialsPhish',
                  'Invoke-BruteForce', 'Invoke-PowerShellIcmp', 'Invoke-PowerShellUdp', 'Invoke-PsGcatAgent',
                  'Invoke-PoshRatHttps', 'Invoke-PowerShellTcp', 'Invoke-PoshRatHttp', 'Invoke-PowerShellWmi',
                  'Invoke-PSGcat', 'Invoke-Encode', 'Invoke-Decode', 'Invoke-CreateCertificate', 'Invoke-NetworkRelay',
                  'EncodedCommand', 'New-ElevatedPersistenceOption', 'Enter-PSSession', 'DownloadString',
                  'DownloadFile', 'Out-Word', 'Out-Excel', 'Out-Java', 'Out-Shortcut', 'Out-CHM', 'Out-HTA',
                  'Out-Minidump', 'HTTP-Backdoor', 'Find-AVSignature', 'DllInjection', 'ReflectivePEInjection',
                  'Base64', 'System.Reflection', 'System.Management', 'Restore-ServiceEXE', 'Add-ScrnSaveBackdoor',
                  'Gupt-Backdoor', 'Execute-OnTime', 'DNS_TXT_Pwnage', 'Write-UserAddServiceBinary',
                  'Write-CMDServiceBinary', 'Write-UserAddMSI', 'Write-ServiceEXE', 'Write-ServiceEXECMD',
                  'Enable-DuplicateToken', 'Remove-Update', 'Execute-DNSTXT-Code', 'Download-Execute-PS',
                  'Execute-Command-MSSQL', 'Download_Execute', 'Copy-VSS', 'Check-VM', 'Create-MultipleSessions',
                  'Run-EXEonRemote', 'Port-Scan', 'Remove-PoshRat', 'TexttoEXE', 'Base64ToString', 'StringtoBase64',
                  'Do-Exfiltration', 'Parse_Keys', 'Add-Exfiltration', 'Add-Persistence', 'Remove-Persistence',
                  'Find-PSServiceAccounts', 'Discover-PSMSSQLServers', 'Discover-PSMSExchangeServers',
                  'Discover-PSInterestingServices', 'Discover-PSMSExchangeServers', 'Discover-PSInterestingServices',
                  'Mimikatz', 'powercat', 'powersploit', 'PowershellEmpire', 'GetProcAddress', '.invoke', ' -e ',
                  'hidden', '-w hidden', 'Invoke-Obfuscation-master', 'Out-EncodedWhitespaceCommand', 'Out-Encoded',
                  "-EncodedCommand", "-enc", "-w hidden", "[Convert]::FromBase64String", "New-Object",
                  "Net.WebClient", "-windowstyle hidden", "DownloadFile", "DownloadString", "Invoke-Expression", "-Exec bypass", "-EncodedCommand", "-enc",
                  "[Convert]::FromBase64String", "-windowstyle hidden",
                  "DownloadFile", "DownloadString", "Invoke-Expression", "-Exec bypass",'Execute-Command-MSSQL','Execute-DNSTXT-Code','Execute-OnTime','ExetoText','exfill','ExfilOption','Exploit-Jboss','Export-PfxCertificate','Export-PowerViewCSV','Failed to update Help for the module','FakeDC','-FeatureName','-FilePath ','-FilePath "$env:comspec" ','filesystem','-Filter',' -Filter Bookmarks','.findall()','Find-DomainLocalGroupMember','Find-DomainObjectPropertyOutlier','Find-DomainProcess','Find-DomainShare','Find-DomainUserEvent','Find-DomainUserLocation','Find-ForeignGroup','Find-ForeignUser','Find-Fruit','Find-GPOComputerAdmin','Find-GPOLocation','Find-InterestingDomainAcl','Find-InterestingDomainShareFile','Find-InterestingFile','Find-LocalAdminAccess','Find-ManagedSecurityGroups','Find-TrustedDocuments','FireBuster','FireListener',' -Force','foreach','format-table','FreeHGlobal','FreeLibrary','Function Get-ADRExcelComOb','gci',' gen_cli ','get-acl','Get-AdComputer ','Get-AdDefaultDomainPasswordPolicy','Get-AdGroup ','Get-ADObject','get-ADPrincipalGroupMembership','Get-ADRDomainController','Get-ADReplAccount','Get-ADRGPO','get-aduser','Get-ADUser','Get-ApplicationHost','Get-CachedRDPConnection','Get-ChromeDump','Get-ClipboardContents','Get-CredManCreds','GetDelegateForFunctionPointer','Get-DFSshare','Get-DNSRecord','Get-DNSZone','Get-Domain','Get-DomainComputer','Get-DomainController','Get-DomainDFSShare','Get-DomainDNSRecord','Get-DomainDNSZone','Get-DomainFileServer','Get-DomainForeignGroupMember','Get-DomainForeignUser','Get-DomainGPO','Get-DomainGPOComputerLocalGroupMapping','Get-DomainGPOLocalGroup','Get-DomainGPOUserLocalGroupMapping','Get-DomainGroup','Get-DomainGroupMember','Get-DomainManagedSecurityGroup','Get-DomainObject','Get-DomainObjectAcl','Get-DomainOU','Get-DomainPolicy','Get-DomainSID','Get-DomainSite','Get-DomainSPNTicket','Get-DomainSubnet','Get-DomainTrust','Get-DomainTrustMapping','Get-DomainUser','Get-DomainUserEvent','Get-Forest','Get-ForestDomain','Get-ForestGlobalCatalog','Get-ForestTrust','Get-FoxDump','Get-GPO','Get-GPPPassword','Get-Inbox.ps1','Get-IndexedItem','Get-Information','Get-IPAddress','Get-Keystrokes','Get-LastLoggedOn','get-localgroup','Get-LocalGroupMember','Get-LocalUser','Get-LoggedOnLocal','GetLogonSessionData','Get-LSASecret','GetModuleHandle','Get-NetComputer','Get-NetComputerSiteName','Get-NetDomain','Get-NetDomainController','Get-NetDomainTrust','Get-NetFileServer','Get-NetForest','Get-NetForestCatalog','Get-NetForestDomain','Get-NetForestTrust','Get-NetGPO','Get-NetGPOGroup','Get-NetGroup','Get-NetGroupMember','Get-NetLocalGroup','Get-NetLocalGroupMember','Get-NetLoggedon','Get-NetOU','Get-NetProcess','Get-NetRDPSession','Get-NetSession','Get-NetShare','Get-NetSite','Get-NetSubnet','Get-NetUser','Get-ObjectAcl','Get-PassHashes','Get-PassHints','Get-PasswordVaultCredentials','Get-PathAcl','GetProcAddress','Get-ProcAddress user32.dll GetAsyncKeyState','Get-ProcAddress user32.dll GetForegroundWindow','get-process','Get-Process ','Get-Process','GetProcessHandle','Get-Process lsass','Get-Proxy','(Get-PSReadlineOption).HistorySavePath','Get-RegAlwaysInstallElevated','Get-RegAutoLogon','Get-RegistryMountedDrive','Get-RegLoggedOn','Get-RickAstley','Get-Screenshot','Get-SecurityPackages','Get-Service ','Get-ServiceFilePermission','Get-ServicePermission','Get-ServiceUnquoted','Get-SiteListPassword','Get-SiteName','get-smbshare','Get-StorageDiagnosticInfo','Get-System','Get-SystemDriveInfo','Get-TimedScreenshot','GetTokenInformation','::GetTypeFromCLSID(','Get-UnattendedInstallFile','Get-Unconstrained','Get-USBKeystrokes','Get-UserEvent','Get-VaultCredential','Get-Volume','Get-VulnAutoRun','Get-VulnSchTask','Get-Web-Credentials','Get-WLAN-Keys','Get-WMIProcess','Get-WMIRegCachedRDPConnection','Get-WMIRegLastLoggedOn','Get-WMIRegMountedDrive','Get-WMIRegProxy','\Google\\Chrome\\User Data\\Default\\Login Data','\\Google\\Chrome\\User Data\Default\Login Data For Account','GroupPolicyRefreshTime','GroupPolicyRefreshTimeDC','GroupPolicyRefreshTimeOffset','GroupPolicyRefreshTimeOffsetDC','Gupt-Backdoor','gwmi','harmj0y','HighThreatDefaultAction','-HistorySaveStyle','HKCU:\\','HKCU\\software\\microsoft\\windows\\currentversion\\run','HKEY_CURRENT_USER\Control Panel\Desktop\\','HKLM:\\','HotFixID','http://127.0.0.1','HTTP-Backdoor','HTTP-Login','-Identity ','IMAGE_NT_OPTIONAL_HDR64_MAGIC','-ImagePath ','ImpersonateLoggedOnUser','Import-Certificate','Import-Module "$Env:Appdata\\','Import-Module','$Env:Temp\\','Import-Module ''$Env:Temp\\','Import-Module C:\\Users\\Public\\',' -Include ','-IncludeLiveDump','Install-ServiceBinary','Install-SSP','Internet-Explorer-Optional-amd64','invoke','Invoke-ACLScanner','Invoke-ADSBackdoor','Invoke-AllChecks','Invoke-AmsiBypass','Invoke-ARPScan','Invoke-AzureHound','Invoke-BackdoorLNK','Invoke-BadPotato','Invoke-BetterSafetyKatz','Invoke-BruteForce','Invoke-BypassUAC','Invoke-Carbuncle','Invoke-Certify','Invoke-CheckLocalAdminAccess','Invoke-CimMethod ','Invoke-CimMethod','invoke-command ','Invoke-CredentialInjection','Invoke-CredentialsPhish','Invoke-DAFT','Invoke-DCSync','Invoke-Decode','Invoke-DinvokeKatz','Invoke-DllInjection','Invoke-DNSExfiltrator','Invoke-DowngradeAccount','Invoke-EgressCheck','Invoke-Encode','Invoke-EnumerateLocalAdmin','Invoke-EventHunter','Invoke-Eyewitness','Invoke-FakeLogonScreen','Invoke-Farmer','Invoke-FileFinder','Invoke-Get-RBCD-Threaded','Invoke-Gopher','Invoke-GPOLinks','Invoke-Grouper2','Invoke-HandleKatz','Invoke-Interceptor','Invoke-Internalmonologue','Invoke-Inveigh','Invoke-InveighRelay','invoke-item ','Invoke-JSRatRegsvr','Invoke-JSRatRundll','Invoke-Kerberoast','Invoke-KrbRelayUp','Invoke-LdapSignCheck','Invoke-Lockless','Invoke-MapDomainTrust','Invoke-Mimikatz','Invoke-MimikatzWDigestDowngrade','Invoke-Mimikittenz','Invoke-MITM6','Invoke-NanoDump','Invoke-NetRipper','Invoke-NetworkRelay','Invoke-Nightmare','Invoke-NinjaCopy','Invoke-OxidResolver','Invoke-P0wnedshell','Invoke-Paranoia','Invoke-PortScan','Invoke-PoshRatHttp','Invoke-PoshRatHttps','Invoke-PostExfil','Invoke-Potato','Invoke-PowerDump','Invoke-PowerShellIcmp','Invoke-PowerShellTCP','Invoke-PowerShellUdp','Invoke-PowerShellWMI','Invoke-PPLDump','Invoke-Prasadhak','Invoke-ProcessHunter','Invoke-PsExec','Invoke-PSGcat','Invoke-PsGcatAgent','Invoke-PSInject','Invoke-PsUaCme','Invoke-ReflectivePEInjection','Invoke-ReverseDNSLookup','Invoke-RevertToSelf','Invoke-Rubeus','Invoke-RunAs','Invoke-SafetyKatz','Invoke-SauronEye','Invoke-SCShell','Invoke-Seatbelt','Invoke-ServiceAbuse','Invoke-SessionGopher','Invoke-ShareFinder','Invoke-SharpAllowedToAct','Invoke-SharpBlock','Invoke-SharpBypassUAC','Invoke-SharpChromium','Invoke-SharpClipboard','Invoke-SharpCloud','Invoke-SharpDPAPI','Invoke-SharpDump','Invoke-SharPersist','Invoke-SharpGPOAbuse','Invoke-SharpGPO-RemoteAccessPolicies','Invoke-SharpHandler','Invoke-SharpHide','Invoke-Sharphound2','Invoke-Sharphound3','Invoke-SharpHound4','Invoke-SharpImpersonation','Invoke-SharpImpersonationNoSpace','Invoke-SharpKatz','Invoke-SharpLdapRelayScan','Invoke-Sharplocker','Invoke-SharpLoginPrompt','Invoke-SharpMove','Invoke-SharpPrinter','Invoke-SharpPrintNightmare','Invoke-SharpRDP','Invoke-SharpSecDump','Invoke-Sharpshares','Invoke-SharpSniper','Invoke-SharpSploit','Invoke-SharpSpray','Invoke-SharpSSDP','Invoke-SharpStay','Invoke-SharpUp','Invoke-Sharpview','Invoke-SharpWatson','Invoke-Sharpweb','Invoke-Shellcode','Invoke-SMBAutoBrute','Invoke-SMBScanner','Invoke-Snaffler','Invoke-Spoolsample','Invoke-SSHCommand','Invoke-SSIDExfil','Invoke-StandIn','Invoke-StickyNotesExtract','Invoke-Tater','Invoke-Thunderfox','Invoke-ThunderStruck','Invoke-TokenManipulation','Invoke-Tokenvator','Invoke-TroubleshootingPack','Invoke-UrbanBishop','Invoke-UserHunter','Invoke-UserImpersonation','Invoke-VoiceTroll','Invoke-WebRequest','Invoke-Whisker','Invoke-WinEnum','Invoke-winPEAS','Invoke-WireTap','Invoke-WmiCommand','Invoke-WMIMethod','Invoke-WScriptBypassUAC','Invoke-Zerologon','TOKEN_ADJUST_PRIVILEGES','TOKEN_ALL_ACCESS','Metasploit','TOKEN_ASSIGN_PRIMARY','TOKEN_DUPLICATE','TOKEN_ELEVATION','TOKEN_IMPERSONATE','TOKEN_INFORMATION_CLASS','TOKEN_PRIVILEGES','TOKEN_QUERY','DumpCerts','DumpCreds','DuplicateTokenEx','RastaMouse','Port-Scan','-Post ','PowerBreach','powercat ','powercat.ps1','[System.Environment]::UserName','System.IdentityModel.Tokens.KerberosRequestorSecurityToken','system.io.compression.deflatestream','system.io.streamreader','Set-MacAttribute','Set-MpPreference','Set-NetFirewallProfile','Set-PSReadlineOption','Set-RemotePSRemoting','Set-RemoteWMI','SetThreadToken','Set-VMFirmware','Set-Wallpaper','shell32.dll','Shellcode32','Shellcode64','shellexec_rundll','.ShellExecute(','ShellSmartScreenLevel','Show-TargetScreen','SMB1Protocol','\software\\','\\SOFTWARE\\Policies\\Microsoft\\Windows\\System','Start-BitsTransfer','Start-CaptureServer','Start-Dnscat2','Start-VM','Start-WebcamRecorder','-stream','StringtoBase64','SuspendThread','SyncAppvPublishingServer.exe','SyncInvoke','System.CodeDom.Compiler.CompilerParameters','System.DirectoryServices.AccountManagement','System.DirectoryServices.DirectorySearcher','System.DirectoryServices.Protocols.LdapConnection','System.DirectoryServices.Protocols.LdapDirectoryIdentifier','[System.Net.HttpWebRequest]','.DownloadFile(','.DownloadString(','Microsoft.Win32.UnsafeNativeMethods','Mimikatz','MiniDumpWriteDump','ModerateThreatDefaultAction','-ModuleName ','Send-MailMessage','SE_PRIVILEGE_ENABLED','-Server ',' service_mod ','Set-ADObject','set-content','Set-DCShadowPermissions','-UserAgent ',' vacant_system ','-Value','vaultcmd','vbscript:createobject','VirtualAlloc','VirtualFree','VirtualProtect','"virus"','VolumeShadowCopyTools','WaitForSingleObject','Web Credentials','wget ','Win32_ComputerSystem','Win32_Group','Win32_PnPEntity','Win32_Product ','Win32_QuickFixEngineering','win32_shadowcopy','Win32_Shadowcopy','New-DomainGroup','New-DomainUser','New-HoneyHash','New-Item','New-LocalUser','new-object','(New-Object System.Net.WebClient).DownloadString(''https://chocolatey.org/install.ps1'')','(New-Object System.Net.WebClient).DownloadString(''https://community.chocolatey.org/install.ps1','0xdeadbeef','AAAAYInlM','AcceptTcpClient',' active_users ','Add-ConstrainedDelegationBackdoor','add-content','Add-Content','Add-DnsClientNrptRule','Add-DomainGroupMember','Add-DomainObjectAcl','Add-Exfiltration','Add-ObjectAcl','Add-Persistence','Add-RegBackdoor','Add-RemoteConnection','Add-ScrnSaveBackdoor','AddSecurityPackage','AdjustTokenPrivileges','ADRecon-Report.xlsx','ReadProcessMemory.Invoke','readtoend','-recurse','[Reflection.Assembly]::Load($','Reflection.Emit.AssemblyBuilderAccess','Register-ScheduledTask','.RegisterXLL','Registry::','REGISTRY::HKLM\\SYSTEM\\CurrentControlSet\\Services\\',' registry_mod ','-RemoteFXvGPUDisablementFilePath',' remote_posh ','RemoteSigned','Remove-ADGroupMember','Remove-EtwTraceProvider ','Remove-EventLog ','Remove-FileShare','Remove-Item','Remove-LocalUser','Remove-Module','Remove-MpPreference','Remove-Persistence','Remove-PoshRat','Remove-RemoteConnection','Remove-SmbShare','Remove-Update','Remove-WmiObject','Rename-LocalUser','Request-SPNTicket','Resolve-IPAddress','RevertToSelf','-root ','Root\\\Microsoft\\\Windows\\\TaskScheduler','.rtf','RtlCreateUserThread','runAfterCancelProcess','rundll32','rundll32.exe','Run-EXEonRemote','Runtime.InteropServices.DllImportAttribute','SaveNothing',' sched_job ','-ScriptBlock ','secur32','SECURITY_DELEGATION','select-string ','.Send(','Set-DomainObject','Set-DomainUserPassword','Set-EtwTraceProvider ','Set-ItemProperty','Set-LocalUser','System.Net.NetworkCredential','System.Net.NetworkInformation.Ping','System.Net.Security.SslStream','System.Net.Sockets.TcpListener','system.net.webclient','System.Net.WebClient','SystemParametersInfo(20,0,,3)','[System.Reflection.Assembly]::Load($','System.Reflection.Assembly.Load($','System.Reflection.AssemblyName','[System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory())','[System.Security.Principal.WindowsIdentity]::GetCurrent()','System.Xml.XmlDocument','TelnetServer','Test-AdminAccess','Test-NetConnection','text.encoding]::ascii','TexttoExe','TFTP','tifkin_','-Exec bypass','.txt',"2013HistorySaveStyle",'-Unattended','Unblock-File ','Unrestricted','Update-Help','useraccountcontrol','(window.close)',' -window hidden ','Windows Credentials','Windows-Defender','Windows-Defender-ApplicationGuard','Windows-Defender-Features','import-module ActiveDirectory','Windows-Defender-Gui','Windows.Security.Credentials.PasswordVault','WMImplant','Write-ChocolateyWarning','Write-EventLog','WriteInt32','WriteProcessMemory','ZeroFreeGlobalAllocUnicode','UploadData','Net.ServicePointManagers',"CommandInvocation",'[IO.File]::SetLastAccessTime','[IO.File]::SetLastWriteTime','IO.FileStream','ipmo "$Env:Appdata\\','ipmo ''$Env:Appdata\\','ipmo $Env:Appdata\\','ipmo "$Env:Temp\\','ipmo ''$Env:Temp\\','ipmo $Env:Temp\\','ipmo C:\\Users\\Public\\','iwr ','join','.kdb','.kdbx','kernel32','Keylogger','.LastAccessTime =','.LastWriteTime =','-like','Limit-EventLog ','/listcreds:','.Load','LoadLibrary','LoggedKeys',' logon_events ','LowThreatDefaultAction','LSA_UNICODE_STRING','MailRaider','mattifestation','-Members ','memcpy','-Method ','-MethodName ','Microsoft.CSharp.CSharpCodeProvider','\Microsoft\\Edge\\User Data\Default','Microsoft.Office.Interop.Outlook','Microsoft.Office.Interop.Outlook.olDefaultFolders','-ModulePath ','Mount-DiskImage ','Move-Item','\Mozilla\Firefox\Profiles','MSAcpi_ThermalZoneTemperature','mshta','.msi','msvcrt','MsXml2.','-NameSe','-Namesp','-NameSpace','-Namespace root/subscription ','Net.Security.RemoteCertificateValidationCallback','Net.WebClient','New-CimInstance ','(New-Object System.Net.WebClient).DownloadString(''https://community.chocolatey.org/install.ps1'')','New-PSDrive','New-PSSession','New-ScheduledTask','New-ScheduledTaskAction','New-ScheduledTaskPrincipal','New-ScheduledTaskSettingsSet','New-ScheduledTaskTrigger','New-VM','Nishang',' -noni ','-noni',' -noninteractive ','-nop','-noprofile','NotAllNameSpaces','ntdll','OiCAAAAYInlM','OiJAAAAYInlM','-Online','OpenDesktop','OpenProcess','OpenProcessToken','OpenThreadToken','OpenWindowStation','\Opera Software\\Opera Stable\\Login Data','Out-CHM','OUT-DNSTXT','Out-File ','Out-HTA','Out-Minidump','Out-RundllCommand','Out-SCF','Out-SCT','Out-Shortcut','Out-WebQuery','Out-Word',' -p ','PAGE_EXECUTE_READ','Parse_Keys','.pass','-PassThru ','Password-List','-Pattern ','.pdf','-port ',' power_off ','Powerpreter','PowerUp','PowerView','.ppt','.pptx',' process_kill ','-Profile','PromptForCredential','Properties.name','.PropertiesToLoad.Add','PS ATTACK!!!','-psprovider ','psreadline','PS_ScheduledTask','PtrToString',' Put ','QueueUserApc','_RastaMouse','-RawData ','ReadProcessMemory' ]


Medium_powershell={'select-object','-Property ','bypass','get-itemProperty','Get-ItemProperty','-band',' basic_info ','.bat','bxor','bypass',' -d ',' -c ',' -doh ','del','Set-ExecutionPolicy','-ExecutionPolicy bypass','Start-Process','\Windows\\System32','\Windows\\SysWOW64','-windowstyle','WindowStyle',' -windowstyle hidden ','-append','.application','-ArgumentList ','get-childitem','Get-ChildItem ','Get-ChildItem','set',' -w ', "-w hidden",'-pr ',' -w hidden ','WallPaper','-Enc','-f ','-ep',' 443 ',' 80 ','.xls','.xlsx','XmlHttp','""','&&',' -i ',"-ExecutionPolicy",'Remove-Item','$DoIt','$env:ComSpec','$env:COR_ENABLE_PROFILING','$env:COR_PROFILER','$env:COR_PROFILER_PATH','> $env:TEMP\\','$env:TEMP\\','$env:UserName','$profile','Advapi32','-All ','Allow','-AnswerFile','\AppData\\Roaming\\Code\\','-AttackSurfaceReductionRules_Actions ','-AttackSurfaceReductionRules_Ids ','.AuthenticateAsClient','"carbonblack"','Cert:\\LocalMachine\\Root',' change_user ','char','-CheckForSignaturesBeforeRunningScan ','Check-VM','-ClassName ','-ClassName','-ClassName CommandLineEventConsumer ','-ClassName __EventFilter ','Clear-EventLog ','Clear-History','Clear-WinEvent ','ClientAccessible','CL_Invocation.ps1','CL_Mutexverifiers.ps1','CloseHandle','.cmd','CmdletsToExport','Collections.ArrayList',' command_exec ','-ComObject ','-ComObject','-comobject outlook.application','Compress-Archive ','Compress-Archive',' -ComputerName ','-ComputerName ','comspec','ConsoleHost_history.txt','-ControlledFolderAccessProtectedFolders ','Convert-ADName','[Convert]::FromBase64String','ConvertFrom-UACValue','Convert-NameToSid','ConvertTo-SID','.CopyFromScreen','Copy-Item ','Copy-Item','# Copyright 2016 Amazon.com, Inc. or its affiliates. All','Copy-VSS','C:\\ProgramData\\Amazon\\EC2-Windows\\Launch\\Module\\',').Create(','Create-MultipleSessions','CreateProcessWithToken','CreateRemoteThread','CreateThread','CreateUserThread','.CreationTime =','curl ','CurrentVersion\\Winlogon','C:\\Windows\\Diagnostics\\System\\PCW','"cylance"','DangerousGetHandle','DataToEncode','"defender"','.Delete()','Delete()','.Description','-Destination ','-Destination',' -DestinationPath ','DisableArchiveScanning $true','DisableArchiveScanning 1','DisableBehaviorMonitoring $true','DisableBehaviorMonitoring 1','DisableBlockAtFirstSeen $true','DisableBlockAtFirstSeen 1','DisableIntrusionPreventionSystem $true','DisableIntrusionPreventionSystem 1','DisableIOAVProtection $true','DisableIOAVProtection 1','Disable-LocalUser','DisableRealtimeMonitoring $true','DisableRealtimeMonitoring 1','DisableRemovableDriveScanning $true','DisableRemovableDriveScanning 1','DisableScanningMappedNetworkDrivesForFullScan $true','DisableScanningMappedNetworkDrivesForFullScan 1','DisableScanningNetworkFiles $true','DisableScanningNetworkFiles 1','DisableScriptScanning $true','DisableScriptScanning 1',' disable_wdigest ','Disable-WindowsOptionalFeature',' disable_winrm ','DNS_TXT_Pwnage','.doc','.docx','DoesNotRequirePreAuth','Do-Exfiltration','.download','.Download','Download_Execute','Download-Execute-PS','.DriveLetter','-Enabled','Enabled-DuplicateToken','Enable-Duplication','Enable-LocalUser','Enable-PSRemoting ','EnableSmartScreen',' enable_wdigest ','Enable-WindowsOptionalFeature',' enable_winrm ',' -enc ',' -EncodedCommand ','EnumerateSecurityPackages','-ErrorAction ',' -ErrorAction SilentlyContinue','[IO.File]::SetCreationTime'}



Suspicious_process_found = []
User_SIDs = [{'User': [], 'SID': []}]
Suspicious_Path = ['\\temp\\', '//temp//', '/temp/', '//windows//temp//', '/windows/temp/', '\\windows\\temp\\',
                   '\\appdata\\', '/appdata/', '//appdata//', '//programdata//', '\\programdata\\', '/programdata/']
Usual_Path = ['\\Windows\\System32\\', '/Windows/System32/', '//Windows//System32//', '\\Windows\\', '/Windows/',
              '//Windows//', 'Program Files', '\\Windows\\SysWOW64\\', '/Windows/SysWOW64/', '//Windows//SysWOW64//',
              '\\Windows\\Cluster\\', '/Windows/Cluster/', '//Windows//Cluster//']
Pass_the_hash_users = [{'User': [], 'Number of Logins': [], 'Reached': []}]
Logon_Events = [
    {'Date and Time': [], 'timestamp': [], 'Event ID': [], 'Account Name': [], 'Account Domain': [], 'Logon Type': [],
     'Logon Process': [], 'Source IP': [], 'Workstation Name': [], 'Computer Name': [], 'Channel': [],
     'Original Event Log': []}]
Executed_Process_Events = [
    {'DateTime': [], 'timestamp': [], 'EventID': [], 'ProcessName': [], 'User': [], 'ParentProcessName':[],
     'RawLog': []}]

Object_Access_Events = [
    {'Date and Time': [], 'timestamp': [], 'Event ID': [], 'Account Name': [], 'Object Name': [], 'Object Type': [],
     'Process Name': [], 'Computer Name': [], 'Channel': [], 'Original Event Log': []}]
TerminalServices_Summary = [{'User': [], 'Number of Logins': []}]
Security_Authentication_Summary = [{'User': [], 'Number of Failed Logins': [], 'Number of Successful Logins': []}]
Executed_Process_Summary = [{'Process Name': [], 'Number of Execution': []}]
Executed_Powershell_Summary=[{'Command': [], 'Number of Execution': []}]
critical_services = ["Software Protection", "Network List Service", "Network Location Awareness", "Windows Event Log"]

whitelisted = ['MpKslDrv', 'CreateExplorerShellUnelevatedTask']

Sysmon_events = [{'Date and Time': [], 'timestamp': [], 'Detection Rule': [], 'Severity': [], 'Detection Domain': [],
                  'Event Description': [], 'Event ID': [], 'Computer Name': [], 'Channel': [],
                  'Original Event Log': []}]
WinRM_events = [{'Date and Time': [], 'timestamp': [], 'Detection Rule': [], 'Severity': [], 'Detection Domain': [],
                 'Event Description': [],'UserID': [], 'Event ID': [], 'Computer Name': [], 'Channel': [], 'Original Event Log': []}]


Security_events = [{'Date and Time': []
, 'timestamp': []
, 'Detection Rule': []
, 'Severity': []
, 'Detection Domain': []
,
                    'Event Description': []
, 'Event ID': []
, 'Computer Name': []
, 'Channel': []
,
                    'Original Event Log': []
}]

#Security_events =manager.dict({'Date and Time': [], 'timestamp': [], 'Detection Rule': [], 'Severity': [], 'Detection Domain': [], 'Event Description': [], 'Event ID': [], 'Computer Name': [], 'Channel': [], 'Original Event Log': []})
System_events = [{'Date and Time': [], 'timestamp': [], 'Detection Rule': [], 'Severity': [], 'Detection Domain': [],
                  'Service Name': [], 'Image Path': [], 'Event Description': [], 'Event ID': [], 'Computer Name': [],
                  'Channel': [], 'Original Event Log': []}]
ScheduledTask_events = [
    {'Date and Time': [], 'timestamp': [], 'Detection Rule': [], 'Severity': [], 'Detection Domain': [],
     'Schedule Task Name': [], 'Event Description': [], 'Event ID': [], 'Computer Name': [], 'Channel': [],
     'Original Event Log': []}]
Powershell_events = [
    {'Date and Time': [], 'timestamp': [], 'Detection Rule': [], 'Severity': [], 'Detection Domain': [],
     'Event Description': [], 'Event ID': [], 'Computer Name': [], 'Channel': [], 'Original Event Log': []}]
Powershell_Operational_events = [
    {'Date and Time': [], 'timestamp': [], 'Detection Rule': [], 'Severity': [], 'Detection Domain': [],
     'Event Description': [], 'Event ID': [], 'Computer Name': [], 'Channel': [], 'Original Event Log': []}]
TerminalServices_events = [
    {'Date and Time': [], 'timestamp': [], 'Detection Rule': [], 'Severity': [], 'Detection Domain': [],
     'Event Description': [], 'Event ID': [], 'User': [], 'Source IP': [], 'Computer Name': [], 'Channel': [],
     'Original Event Log': []}]

TerminalServices_RDPClient_events = [
    {'Date and Time': [], 'timestamp': [], 'Detection Rule': [], 'Severity': [], 'Detection Domain': [],
     'Event Description': [], 'Event ID': [], 'UserID': [], 'Source IP': [], 'Computer Name': [], 'Channel': [],
     'Original Event Log': []}]

Windows_Defender_events = [
    {'Date and Time': [], 'timestamp': [], 'Detection Rule': [], 'Severity': [], 'Detection Domain': [],
     'Event Description': [], 'Event ID': [], 'Computer Name': [], 'Channel': [], 'Original Event Log': []}]
Group_Policy_events = [
    {'Date and Time': [], 'timestamp': [], 'Detection Rule': [], 'Severity': [], 'Detection Domain': [],
     'Event Description': [], 'Group Policy Name': [], 'Policy Extension Name': [], 'Event ID': [], 'Computer Name': [],
     'Channel': [], 'Original Event Log': []}]
SMB_Server_events = [
    {'Date and Time': [], 'timestamp': [], 'Detection Rule': [], 'Severity': [], 'Detection Domain': [],
     'Event Description': [], 'Client Address': [], 'UserName': [], 'Share Name': [], 'File Name': [], 'Event ID': [],
     'Computer Name': [], 'Channel': [], 'Original Event Log': []}]

SMB_Client_events = [
    {'Date and Time': [], 'timestamp': [], 'Detection Rule': [], 'Severity': [], 'Detection Domain': [],
     'Event Description': [], 'Share Name': [], 'File Name': [], 'Event ID': [], 'Computer Name': [], 'Channel': [],
     'Original Event Log': []}]

Timesketch_events = [
    {'message': [], 'timestamp': [], 'datetime': [], 'timestamp_desc': [], 'Event Description': [], 'Severity': [],
     'Detection Domain': [], 'Event ID': [], 'Computer Name': [], 'Channel': [], 'Original Event Log': []}]

#Group_Policy_events = manager.dict({'Date and Time': [], 'timestamp': [], 'Detection Rule': [], 'Severity': [], 'Detection Domain': [],     'Event Description': [], 'Group Policy Name': [], 'Policy Extension Name': [], 'Event ID': [], 'Computer Name': [],     'Channel': [], 'Original Event Log': []})
Frequency_Analysis_Security={}
Frequency_Analysis_Windows_Defender={}
Frequency_Analysis_SMB_Client={}
Frequency_Analysis_Group_Policy={}
Frequency_Analysis_Powershell_Operational={}
Frequency_Analysis_Powershell={}
Frequency_Analysis_ScheduledTask={}
Frequency_Analysis_WinRM={}
Frequency_Analysis_System={}
Frequency_Analysis_Sysmon={}
Frequency_Analysis_SMB_Server={}
Frequency_Analysis_TerminalServices={}
#=======================
#Regex for security logs

EventID_rex = re.compile('<EventID.*>(.*)<\/EventID>', re.IGNORECASE)

Logon_Type_rex = re.compile('<Data Name=\"LogonType\">(.*)</Data>|<LogonType>(.*)</LogonType>', re.IGNORECASE)


Account_Name_rex = re.compile('<Data Name=\"SubjectUserName\">(.*)</Data>|<SubjectUserName>(.*)</SubjectUserName>', re.IGNORECASE)
Account_Name_Target_rex = re.compile('<Data Name=\"TargetUserName\">(.*)</Data>|<TargetUserName>(.*)</TargetUserName>', re.IGNORECASE)


Security_ID_rex = re.compile('<Data Name=\"SubjectUserSid\">(.*)</Data>|<SubjectUserSid>(.*)</SubjectUserSid>', re.IGNORECASE)
Security_ID_Target_rex = re.compile('<Data Name=\"TargetUserSid\">(.*)</Data>|<TargetUserSid>(.*)</TargetUserSid>', re.IGNORECASE)

Account_Domain_rex = re.compile('<Data Name=\"SubjectDomainName\">(.*)</Data>|<SubjectDomainName>(.*)</SubjectDomainName>', re.IGNORECASE)
Account_Domain_Target_rex = re.compile('<Data Name=\"TargetDomainName\">(.*)</Data>|<TargetDomainName>(.*)</TargetDomainName>', re.IGNORECASE)

Workstation_Name_rex = re.compile('<Data Name=\"WorkstationName\">(.*)</Data>|<WorkstationName>(.*)</WorkstationName>', re.IGNORECASE)

Source_Network_Address_rex = re.compile('<Data Name=\"IpAddress\">(.*)</Data>|<IpAddress>(.*)</IpAddress>', re.IGNORECASE)

Logon_Process_rex = re.compile('<Data Name=\"LogonProcessName\">(.*)</Data>|<LogonProcessName>(.*)</LogonProcessName>', re.IGNORECASE)

Key_Length_rex = re.compile('<Data Name=\"KeyLength\">(.*)</Data>|<KeyLength>(.*)</KeyLength>', re.IGNORECASE)

AccessMask_rex = re.compile('<Data Name=\"AccessMask\">(.*)</Data>|<AccessMask>(.*)</AccessMask>', re.IGNORECASE)

Process_Command_Line_rex=re.compile('<Data Name=\"CommandLine\">(.*)</Data>|<CommandLine>(.*)</CommandLine>', re.IGNORECASE)

New_Process_Name_rex=re.compile('<Data Name=\"NewProcessName\">(.*)</Data>', re.IGNORECASE)

TicketOptions_rex=re.compile('<Data Name=\"TicketOptions\">(.*)</Data>|<TicketOptions>(.*)</TicketOptions>', re.IGNORECASE)
TicketEncryptionType_rex=re.compile('<Data Name=\"TicketEncryptionType\">(.*)</Data>|<TicketEncryptionType>(.*)</TicketEncryptionType>', re.IGNORECASE)
ServiceName_rex=re.compile('<Data Name=\"ServiceName\">(.*)</Data>|<ServiceName>(.*)</ServiceName>', re.IGNORECASE)

Group_Name_rex=re.compile('<Data Name=\"TargetUserName\">(.*)</Data>|<TargetUserName>(.*)</TargetUserName>', re.IGNORECASE)

Task_Name_rex=re.compile('<Data Name=\"TaskName\">(.*)</Data>|<TaskName>(.*)</TaskName>', re.IGNORECASE)

Task_Command_rex=re.compile('<Command>(.*)</Command>', re.IGNORECASE)

Task_args_rex=re.compile('<Arguments>(.*)</Arguments>', re.IGNORECASE)

Process_Name_sec_rex = re.compile('<Data Name=\"CallerProcessName\">(.*)</Data>|<CallerProcessName>(.*)</CallerProcessName>|<Data Name=\"ProcessName\">(.*)</Data>|<Data Name=\"NewProcessName\">(.*)</Data>', re.IGNORECASE)

Parent_Process_Name_sec_rex=re.compile('<Data Name=\"ParentProcessName\">(.*)</Data>|<ParentProcessName>(.*)</ParentProcessName>', re.IGNORECASE)


Category_sec_rex= re.compile('<Data Name=\"CategoryId\">(.*)</Data>|<CategoryId>(.*)</CategoryId>', re.IGNORECASE)

Subcategory_rex= re.compile('<Data Name=\"SubcategoryId\">(.*)</Data>|<SubcategoryId>(.*)</LogonType>', re.IGNORECASE)

Changes_rex= re.compile('<Data Name=\"AuditPolicyChanges\">(.*)</Data>|<AuditPolicyChanges>(.*)</AuditPolicyChanges>', re.IGNORECASE)

Member_Name_rex = re.compile('<Data Name=\"MemberName\">(.*)</Data>|<MemberName>(.*)</MemberName>', re.IGNORECASE)
Member_Sid_rex = re.compile('<Data Name=\"MemberSid\">(.*)</Data>|<MemberSid>(.*)</MemberSid>', re.IGNORECASE)

ShareName_rex = re.compile('<Data Name=\"ShareName\">(.*)</Data>|<shareName>(.*)</shareName>', re.IGNORECASE)

ShareLocalPath_rex = re.compile('<Data Name=\"ShareLocalPath\">(.*)</Data>|<ShareLocalPath>(.*)</ShareLocalPath>', re.IGNORECASE)
Object_Name_rex = re.compile('<Data Name=\"ObjectName\">(.*)</Data>|<ObjectName>(.*)</ObjectName>', re.IGNORECASE)

ObjectType_rex = re.compile('<Data Name=\"ObjectType\">(.*)</Data>|<ObjectType>(.*)</ObjectType>', re.IGNORECASE)

ObjectServer_rex = re.compile('<Data Name=\"ObjectServer\">(.*)</Data>|<ObjectServer>(.*)</ObjectServer>', re.IGNORECASE)
ObjectProcessName_rex = re.compile('<Data Name=\"ProcessName\">(.*)</Data>', re.IGNORECASE)


#=======================
#Regex for windows defender logs

Name_rex = re.compile('<Data Name=\"Threat Name\">(.*)</Data>|<Threat Name>(.*)</Threat Name>', re.IGNORECASE)

Severity_rex = re.compile('<Data Name=\"Severity Name\">(.*)</Data>|<Severity Name>(.*)</Severity Name>', re.IGNORECASE)

Category_rex = re.compile('<Data Name=\"Category Name\">(.*)</Data>|<Category Name>(.*)</Category Name>', re.IGNORECASE)

Path_rex = re.compile('<Data Name=\"Path\">(.*)</Data>|<Path>(.*)</Path>', re.IGNORECASE)

Defender_Remediation_User_rex = re.compile('<Data Name=\"Remediation User\">(.*)</Data>|<Remediation User>(.*)</Remediation User>', re.IGNORECASE)

Defender_User_rex = re.compile('<Data Name=\"User\">(.*)</Data>|<User>(.*)</User>', re.IGNORECASE)

Process_Name_rex = re.compile('<Data Name=\"Process Name\">(.*)</Data>|<Process Name>(.*)</Process Name>', re.IGNORECASE)

Action_rex = re.compile('<Data Name=\"Action ID\">(.*)</Data>|<Action ID>(.*)</Action ID>', re.IGNORECASE)

#=======================
#Regex for system logs

Service_Name_rex = re.compile('<Data Name=\"ServiceName\">(.*)</Data>|<ServiceName>(.*)</ServiceName>', re.IGNORECASE)
Service_File_Name_rex = re.compile('<Data Name=\"ImagePath\">(.*)</Data>|<ImagePath>(.*)</ImagePath>', re.IGNORECASE)
Service_Type_rex = re.compile('<Data Name=\"ServiceType\">(.*)</Data>|<ServiceType>(.*)</ServiceType>', re.IGNORECASE)
Service_Account_rex = re.compile('<Data Name=\"AccountName\">(.*)</Data>|<AccountName>(.*)</AccountName>', re.IGNORECASE)
State_Service_Name_rex = re.compile('<Data Name=\"param1\">(.*)</Data>|<param1>(.*)</param1>', re.IGNORECASE)
State_Service_Old_rex = re.compile('<Data Name=\"param2\">(.*)</Data>|<param2>(.*)</param2>', re.IGNORECASE)
State_Service_New_rex = re.compile('<Data Name=\"param3\">(.*)</Data>|<param3>(.*)</param2>', re.IGNORECASE)
Service_Start_Type_rex = re.compile('<Data Name=\"StartType\">(.*)</Data>|<StartType>(.*)</StartType>', re.IGNORECASE)


#=======================
#Regex for task scheduler logs
Task_Name = re.compile('<Data Name=\"TaskName\">(.*)</Data>|<TaskName>(.*)</TaskName>', re.IGNORECASE)
Task_Registered_User_rex = re.compile('<Data Name=\"UserContext\">(.*)</Data>|<UserContext>(.*)</UserContext>', re.IGNORECASE)
Task_Deleted_User_rex = re.compile('<Data Name=\"UserName\">(.*)</Data>|<UserName>(.*)</UserName>', re.IGNORECASE)
Task_Image_Path_rex = re.compile('<Data Name=\"UserName\">(.*)</Data>|<UserName>(.*)</UserName>', re.IGNORECASE)


#======================
#Regex for powershell operational logs
Powershell_ContextInfo= re.compile('<Data Name=\"ContextInfo\">(.*)</Data>', re.IGNORECASE)
Powershell_Payload= re.compile('<Data Name=\"Payload\">(.*)</Data>', re.IGNORECASE)
Powershell_ScriptBlockText= re.compile('<Data Name=\"ScriptBlockText\">(.*)</Data>', re.IGNORECASE)
Powershell_Path= re.compile('<Data Name=\"Path\">(.*)</Data>', re.IGNORECASE)

Host_Application_rex = re.compile('Host Application = (.*)')
Command_Name_rex = re.compile('Command Name = (.*)')
Command_Type_rex = re.compile('Command Type = (.*)')
Engine_Version_rex = re.compile('Engine Version = (.*)')
User_rex = re.compile('User = (.*)')
Error_Message_rex = re.compile('Error Message = (.*)')

#======================
#Regex for powershell logs
HostApplication_rex = re.compile('HostApplication=(.*)')
CommandLine_rex = re.compile('CommandLine=(.*)')
ScriptName_rex = re.compile('ScriptName=(.*)')
EngineVersion_rex = re.compile('EngineVersion=(.*)')
UserId_rex = re.compile('UserId=(.*)')
ErrorMessage_rex = re.compile('ErrorMessage=(.*)')
#======================
#TerminalServices Local Session Manager Logs
#Source_Network_Address_Terminal_rex= re.compile('Source Network Address: (.*)')
#Source_Network_Address_Terminal_rex= re.compile('<Address>(.*)</Address>')
Source_Network_Address_Terminal_rex= re.compile('<Address>((\d{1,3}\.){3}\d{1,3})</Address>')
Source_Network_Address_Terminal_NotIP_rex= re.compile('<Address>(.*)</Address>')
User_Terminal_rex=re.compile('User>(.*)</User>')
Session_ID_rex=re.compile('<SessionID>(.*)</SessionID>')
#======================
#TerminalServices RDP Client Logs
UserID_RDPCLIENT_rex= re.compile('<Security UserID=\"(.*)\"', re.IGNORECASE)
TraceMessage_RDPCLIENT_rex= re.compile('<Data Name="TraceMessage">(.*)</Data>')
ServerName_RDPCLIENT_rex= re.compile('<Data Name="Name">(.*)</Data>')
IP_RDPCLIENT_rex= re.compile('<Data Name="Value">(.*)</Data>')
#======================
#Microsoft-Windows-WinRM logs
Connection_rex=re.compile('<Data Name=\"connection\">(.*)</Data>|<connection>(.*)</connection>', re.IGNORECASE)
Winrm_UserID_rex=re.compile('<Security UserID=\"(.*)\"', re.IGNORECASE)

#User_ID_rex=re.compile("""<Security UserID=\'(?<UserID>.*)\'\/><\/System>""")
#src_device_rex=re.compile("""<Computer>(?<src>.*)<\/Computer>""")
#======================
#Sysmon Logs
Sysmon_CommandLine_rex=re.compile("<Data Name=\"CommandLine\">(.*)</Data>")
Sysmon_ProcessGuid_rex=re.compile("<Data Name=\"ProcessGuid\">(.*)</Data>")
Sysmon_ProcessId_rex=re.compile("<Data Name=\"ProcessId\">(.*)</Data>")
Sysmon_Image_rex=re.compile("<Data Name=\"Image\">(.*)</Data>")
Sysmon_FileVersion_rex=re.compile("<Data Name=\"FileVersion\">(.*)</Data>")
Sysmon_Company_rex=re.compile("<Data Name=\"Company\">(.*)</Data>")
Sysmon_Product_rex=re.compile("<Data Name=\"Product\">(.*)</Data>")
Sysmon_Description_rex=re.compile("<Data Name=\"Description\">(.*)</Data>")
Sysmon_User_rex=re.compile("<Data Name=\"User\">(.*)</Data>")
Sysmon_LogonGuid_rex=re.compile("<Data Name=\"LogonGuid\">(.*)</Data>")
Sysmon_TerminalSessionId_rex=re.compile("<Data Name=\"TerminalSessionId\">(.*)</Data>")
Sysmon_Hashes_MD5_rex=re.compile("<Data Name=\"MD5=(.*),")
Sysmon_Hashes_SHA256_rex=re.compile("<Data Name=\"SHA256=(.*)")
Sysmon_ParentProcessGuid_rex=re.compile("<Data Name=\"ParentProcessGuid\">(.*)</Data>")
Sysmon_ParentProcessId_rex=re.compile("<Data Name=\"ParentProcessId\">(.*)</Data>")
Sysmon_ParentImage_rex=re.compile("<Data Name=\"ParentImage\">(.*)</Data>")
Sysmon_ParentCommandLine_rex=re.compile("<Data Name=\"ParentCommandLine\">(.*)</Data>")
Sysmon_CurrentDirectory_rex=re.compile("<Data Name=\"CurrentDirectory\">(.*)</Data>")
Sysmon_OriginalFileName_rex=re.compile("<Data Name=\"OriginalFileName\">(.*)</Data>")
Sysmon_TargetObject_rex=re.compile("<Data Name=\"TargetObject\">(.*)</Data>")
#########
#Sysmon  event ID 3
Sysmon_Protocol_rex=re.compile("<Data Name=\"Protocol\">(.*)</Data>")
Sysmon_SourceIp_rex=re.compile("<Data Name=\"SourceIp\">(.*)</Data>")
Sysmon_SourceHostname_rex=re.compile("<Data Name=\"SourceHostname\">(.*)</Data>")
Sysmon_SourcePort_rex=re.compile("<Data Name=\"SourcePort\">(.*)</Data>")
Sysmon_DestinationIp_rex=re.compile("<Data Name=\"DestinationIp\">(.*)</Data>")
Sysmon_DestinationHostname_rex=re.compile("<Data Name=\"DestinationHostname\">(.*)</Data>")
Sysmon_DestinationPort_rex=re.compile("<Data Name=\"DestinationPort\">(.*)</Data>")

#########
#Sysmon  event ID 8
Sysmon_StartFunction_rex=re.compile("<Data Name=\"StartFunction\">(.*)</Data>")
Sysmon_StartModule_rex=re.compile("<Data Name=\"StartModule\">(.*)</Data>")
Sysmon_TargetImage_rex=re.compile("<Data Name=\"TargetImage\">(.*)</Data>")
Sysmon_SourceImage_rex=re.compile("<Data Name=\"SourceImage\">(.*)</Data>")
Sysmon_SourceProcessId_rex=re.compile("<Data Name=\"SourceProcessId\">(.*)</Data>")
Sysmon_SourceProcessGuid_rex=re.compile("<Data Name=\"SourceProcessGuid\">(.*)</Data>")
Sysmon_TargetProcessGuid_rex=re.compile("<Data Name=\"TargetProcessGuid\">(.*)</Data>")
Sysmon_TargetProcessId_rex=re.compile("<Data Name=\"TargetProcessId\">(.*)</Data>")

#########
Sysmon_ImageLoaded_rex=re.compile("<Data Name=\"ImageLoaded\">(.*)</Data>")
Sysmon_GrantedAccess_rex=re.compile("<Data Name=\"GrantedAccess\">(.*)</Data>")
Sysmon_CallTrace_rex=re.compile("<Data Name=\"CallTrace\">(.*)</Data>")
Sysmon_Details_rex=re.compile("<Data Name=\"Details\">(.*)</Data>")
Sysmon_PipeName_rex=re.compile("<Data Name=\"PipeName\">(.*)</Data>")

Sysmon_ImageLoaded_rex=re.compile("<Data Name=\"ImageLoaded\">(.*)</Data>")
Sysmon_GrantedAccess_rex=re.compile("<Data Name=\"GrantedAccess\">(.*)</Data>")
Sysmon_CallTrace_rex=re.compile("<Data Name=\"CallTrace\">(.*)</Data>")
Sysmon_Details_rex=re.compile("<Data Name=\"Details\">(.*)</Data>")
Sysmon_PipeName_rex=re.compile("<Data Name=\"PipeName\">(.*)</Data>")

##########

Channel_rex = re.compile('<Channel.*>(.*)<\/Channel>', re.IGNORECASE)
Computer_rex = re.compile('<Computer.*>(.*)<\/Computer>', re.IGNORECASE)

##########
Extension_ID_rex = re.compile('<Data Name=\"CSEExtensionId\">(.*)<\/Data>', re.IGNORECASE)
Extension_Name_rex = re.compile('<Data Name=\"CSEExtensionName\">(.*)<\/Data>', re.IGNORECASE)
Polcies_Name_rex = re.compile('<Data Name=\"DescriptionString\">((.*)\n){1,5}</Data>', re.IGNORECASE)
GPO_List_rex = re.compile('<Data Name=\"ApplicableGPOList\">(.*)<\/Data>', re.IGNORECASE)

###########
#SMB Server Regex
SMB_Server_Username_rex = re.compile('<UserName>(.*)</UserName>', re.IGNORECASE)
SMB_Server_ClientName_rex = re.compile('<ClientName>(.*)</ClientName>', re.IGNORECASE)
SMB_Server_ShareName_rex = re.compile('<ShareName>(.*)</ShareName>', re.IGNORECASE)
SMB_Server_FileName_rex = re.compile('<FileName>(.*)</FileName>', re.IGNORECASE)

##########
#SMB Client Regex
SMB_Client_ShareName_rex = re.compile('<Data Name=\"ShareName\">(.*)</Data>', re.IGNORECASE)
SMB_Client_ObjectName_rex = re.compile('<Data Name=\"ObjectName\">(.*)</Data>', re.IGNORECASE)

#############
#SMB Client Regex

UserProfile_SID_rex = re.compile('<Data Name=\"Key\">(.*)</Data>', re.IGNORECASE)
UserProfile_File_rex = re.compile('<Data Name=\"File\">(.*)</Data>', re.IGNORECASE)



input_timzone=timezone("UTC")
timestart=None
timeend=None
def detect_events_security_log(file_name, shared_data):

    global input_timzone, timestart, timeend,Security_events,initial,output,logons
    tic = time.time()
    input_timzone = shared_data["input_timezone"]
    timestart = shared_data["timestart"]
    timeend = shared_data["timeend"]
    objectaccess = shared_data["objectaccess"]
    processexec = shared_data["processexec"]
    logons = shared_data["logons"]
    frequencyanalysis = shared_data["frequencyanalysis"]
    allreport = shared_data["allreport"]
    output = shared_data["output"]


    if 1==1:
        #print("in")
        #print(file_name)

        parser = PyEvtxParser(file_name)
        for record in parser.records():

            EventID = EventID_rex.findall(record['data'])
            Computer = Computer_rex.findall(record['data'])
            Channel = Channel_rex.findall(record['data'])
            #print(EventID[0])
            #print(f'Event Record ID: {record["event_record_id"]}')
            #print(f'Event Timestamp: {record["timestamp"]}')

            if timestart is not None and timeend is not None :
                timestamp=datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat()))
                if not (timestamp>timestart and timestamp<timeend):
                    continue
            if len(EventID) > 0:

                # if frequencyanalysis==True and EventID[0] in Frequency_Analysis_Security:
                #     Frequency_Analysis_Security[EventID[0]]=Frequency_Analysis_Security[EventID[0]]+1
                # else:
                #     Frequency_Analysis_Security[EventID[0]]=1
                Logon_Type = Logon_Type_rex.findall(record['data'])

                Account_Name = Account_Name_rex.findall(record['data'])
                Target_Account_Name = Account_Name_Target_rex.findall(record['data'])

                Account_Domain = Account_Domain_rex.findall(record['data'])
                Target_Account_Domain=Account_Domain_Target_rex.findall(record['data'])

                Workstation_Name = Workstation_Name_rex.findall(record['data'])

                Source_IP = Source_Network_Address_rex.findall(record['data'])

                Logon_Process = Logon_Process_rex.findall(record['data'])

                Key_Length = Key_Length_rex.findall(record['data'])

                Security_ID = Security_ID_rex.findall(record['data'])

                Security_ID_Target=Security_ID_Target_rex.findall(record['data'])

                Group_Name = Group_Name_rex.findall(record['data'])
                Member_Name =  Member_Name_rex.findall(record['data'])
                Member_Sid =Member_Sid_rex.findall(record['data'])

                Task_Name=Task_Name_rex.findall(record['data'])

                Task_Command = Task_Command_rex.findall(record['data'])

                Task_args= Task_args_rex.findall(record['data'])

                New_Process_Name=New_Process_Name_rex.findall(record['data'])
                Process_Name=Process_Name_sec_rex.findall(record['data'])
                Parent_Process_Name = Parent_Process_Name_sec_rex.findall(record['data'])

                Category=Category_sec_rex.findall(record['data'])

                Subcategory=Subcategory_rex.findall(record['data'])

                Changes=Changes_rex.findall(record['data'])

                Process_Command_Line = Process_Command_Line_rex.findall(record['data'])

                ShareName = ShareName_rex.findall(record['data'])

                ShareLocalPath = ShareLocalPath_rex.findall(record['data'])

                Object_Name = Object_Name_rex.findall(record['data'])

                Object_Type = ObjectType_rex.findall(record['data'])
                ObjectServer = ObjectServer_rex.findall(record['data'])
                AccessMask = AccessMask_rex.findall(record['data'])
                ObjectProcessName=ObjectProcessName_rex.findall(record['data'])

                #Detect any log that contain suspicious process name or argument
                if EventID[0]=="4688" or EventID[0]=="4648" or EventID[0]=="4673":
                    for i in all_suspicious:

                        if record['data'].lower().find(i.lower())>-1:

                            #print("##### " + record["timestamp"] + " ####  ", end='')
                            #print("## Found Suspicios Process ", end='')
                            #print("User Name : ( %s ) " % Account_Name[0][0].strip(), end='')
                            #print("with Command Line : ( " + Process_Command_Line[0][0].strip() + " )")
                            # print("###########")

                            Event_desc ="Found a log contain suspicious command or process ( %s)"%i
                            Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                            Security_events[0]['Computer Name'].append(Computer[0])
                            Security_events[0]['Channel'].append(Channel[0])
                            Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                            Security_events[0]['Detection Rule'].append("Suspicious Command or process found in the log")
                            Security_events[0]['Detection Domain'].append("Threat")
                            Security_events[0]['Severity'].append("Critical")
                            Security_events[0]['Event Description'].append(Event_desc)
                            Security_events[0]['Event ID'].append(EventID[0])
                            Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                            break
                #User Creation using Net command
                if EventID[0]=="4688" or EventID[0]=="4648" or EventID[0]=="4673":
                    try:
                        process_name=''
                        process_command_line=" "
                        if len(Account_Name[0][0])>0:
                            user=Account_Name[0][0].strip()


                        if len(Account_Name[0][1])>0:
                            user=Account_Name[0][1].strip()
                            process_command_line=Process_Command_Line[0][1].strip()

                        if len(Process_Command_Line)>0:
                            process_command_line=Process_Command_Line[0][0].strip()
                        """
                        if len(New_Process_Name)>0:
                            process_name=New_Process_Name[0].strip()

                        elif len(Process_Name[0])>1:
                            process_name=Process_Name[0][1].strip()
                        elif len(Process_Name[0])>0:
                            process_name=Process_Name[0][0].strip()
                        """
                        for i in Process_Name[0]:
                            if len(i)>0:
                                process_name=i

                        if len(re.findall('.*user.*/add.*',record['data']))>0:
                            #print("test")

                            #print("##### " + record["timestamp"] + " ####  ", end='')
                            #print("## High ## User Added using Net Command ",end='')
                            #print("User Name : ( %s ) "%Account_Name[0][0].strip(),end='')
                            #print("with Command Line : ( " + Process_Command_Line[0][0].strip()+" )")

                            Event_desc ="User Name : ( %s ) "%user+"with Command Line : ( " + process_command_line+" )"
                            Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                            Security_events[0]['Computer Name'].append(Computer[0])
                            Security_events[0]['Channel'].append(Channel[0])
                            Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                            Security_events[0]['Detection Rule'].append("User Added using Net Command")
                            Security_events[0]['Detection Domain'].append("Audit")
                            Security_events[0]['Severity'].append("Critical")
                            Security_events[0]['Event Description'].append(Event_desc)
                            Security_events[0]['Event ID'].append(EventID[0])
                            Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))

                        #process runing in suspicious location
                        found=0
                        if process_name.strip() not in Suspicious_process_found:
                            for i in Suspicious_Path:
                                if str(record['data']).lower().find(i.lower())>-1:#process_name.strip().lower().find(i.lower())>-1 or process_command_line.lower().find(i.lower())>-1 :
                                    Suspicious_process_found.append(process_name.strip())
                                    found=1
                                    # print("test")
                                    #print("##### " + record["timestamp"] + " ####  ", end='')
                                    #print("## Process running in temp ", end='')
                                    #print("User Name : ( %s ) " % Account_Name[0][0].strip(), end='')
                                    #print("with Command Line : ( " + Process_Command_Line[0][0].strip() + " )")
                                    # print("###########")
                                    try:
                                        Event_desc ="User Name : ( %s ) " % user+" with process : ( " + process_name.strip() + " ) run from suspcious location, check the number and date of execution in process execution report"
                                    except:
                                        Event_desc =" Process run from suspicious location "
                                    Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                                    Security_events[0]['Computer Name'].append(Computer[0])
                                    Security_events[0]['Channel'].append(Channel[0])
                                    Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                                    Security_events[0]['Detection Rule'].append("Process running in suspicious location")
                                    Security_events[0]['Detection Domain'].append("Threat")
                                    Security_events[0]['Severity'].append("High")
                                    Security_events[0]['Event Description'].append(Event_desc)
                                    Security_events[0]['Event ID'].append(EventID[0])
                                    Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                                    break
                            if found!=1:
                                #process runing in suspicious location
                                found=0
                                for i in Usual_Path:
                                    if len(process_name)>5 and (process_name.lower().find(i.lower())>-1 or process_command_line.lower().find(i.lower())>-1) :
                                        found=1
                                        break
                                        # print("test")
                                        #print("##### " + record["timestamp"] + " ####  ", end='')
                                        #print("## Process running in temp ", end='')
                                        #print("User Name : ( %s ) " % Account_Name[0][0].strip(), end='')
                                        #print("with Command Line : ( " + Process_Command_Line[0][0].strip() + " )")
                                        # print("###########")
                                if found==0 and ( len(process_name)>5 or len(process_command_line)>5) :
                                    Suspicious_process_found.append(process_name.strip())
                                    try:
                                        Event_desc ="User Name : ( %s ) " % user+" with process : ( " + process_name.strip() + " ) run from Unusual location , check the number and date of execution in process execution report"
                                    except:
                                        Event_desc =" Process run from Unusual location "
                                    Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                                    Security_events[0]['Computer Name'].append(Computer[0])
                                    Security_events[0]['Channel'].append(Channel[0])
                                    Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                                    Security_events[0]['Detection Rule'].append("Process running in Unusual location")
                                    Security_events[0]['Detection Domain'].append("Threat")
                                    Security_events[0]['Severity'].append("High")
                                    Security_events[0]['Event Description'].append(Event_desc)
                                    Security_events[0]['Event ID'].append(EventID[0])
                                    Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                                found=0
                        if len(Process_Command_Line)>0:

                            #detect suspicious executables
                            for i in Suspicious_executables:

                                if process_command_line.lower().find(i.lower())>-1:

                                    #print("##### " + record["timestamp"] + " ####  ", end='')
                                    #print("## Found Suspicios Process ", end='')
                                    #print("User Name : ( %s ) " % Account_Name[0][0].strip(), end='')
                                    #print("with Command Line : ( " + Process_Command_Line[0][0].strip() + " )")
                                    # print("###########")
                                    Event_desc ="User Name : ( %s ) " % user+"with Command Line : ( " + process_command_line + " ) contain suspicious command ( %s)"%i
                                    Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                                    Security_events[0]['Computer Name'].append(Computer[0])
                                    Security_events[0]['Channel'].append(Channel[0])
                                    Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                                    Security_events[0]['Detection Rule'].append("Suspicious Process Found")
                                    Security_events[0]['Detection Domain'].append("Threat")
                                    Security_events[0]['Severity'].append("Critical")
                                    Security_events[0]['Event Description'].append(Event_desc)
                                    Security_events[0]['Event ID'].append(EventID[0])
                                    Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))

                            # detect suspicious powershell commands
                            for i in Suspicious_powershell_commands:

                                if process_command_line.lower().find(i.lower())>-1:

                                    #print("##### " + record["timestamp"] + " ####  ", end='')
                                    #print("## Found Suspicios Process ", end='')
                                    #print("User Name : ( %s ) " % Account_Name[0][0].strip(), end='')
                                    #print("with Command Line : ( " + Process_Command_Line[0][0].strip() + " )")
                                    # print("###########")

                                    Event_desc ="User Name : ( %s ) " % user+"with Command Line : ( " + process_command_line + " ) contain suspicious command ( %s)"%i
                                    Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                                    Security_events[0]['Computer Name'].append(Computer[0])
                                    Security_events[0]['Channel'].append(Channel[0])
                                    Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                                    Security_events[0]['Detection Rule'].append("Suspicious Powershell commands Process Found")
                                    Security_events[0]['Detection Domain'].append("Threat")
                                    Security_events[0]['Severity'].append("Critical")
                                    Security_events[0]['Event Description'].append(Event_desc)
                                    Security_events[0]['Event ID'].append(EventID[0])
                                    Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))


                            #Detecting privielge Escalation using Token Elevation
                            if len(re.findall(r"cmd.exe /c echo [a-z]{6} > \\\.\\pipe\\\w{1,10}",process_command_line.lower().strip()))>0 or len(re.findall(r"cmd.exe /c echo \w{1,10} .* \\\\\.\\pipe\\\w{1,10}",process_command_line.lower().strip()))>0:
                                    #print("detected",process_command_line.lower().strip())
                                    Event_desc ="User Name : ( %s ) " % user+"conducting Named PIPE privilege escalation with Command Line : ( " + process_command_line + " ) "
                                    Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                                    Security_events[0]['Computer Name'].append(Computer[0])
                                    Security_events[0]['Channel'].append(Channel[0])
                                    Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                                    Security_events[0]['Detection Rule'].append("Suspected privielge Escalation attempt using NAMED PIPE")
                                    Security_events[0]['Detection Domain'].append("Threat")
                                    Security_events[0]['Severity'].append("Critical")
                                    Security_events[0]['Event Description'].append(Event_desc)
                                    Security_events[0]['Event ID'].append(EventID[0])
                                    Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))

                    except Exception as e:
                        print("Error (%s) , Handling EventID (%s) with Event Content %s"%(e,EventID[0],record['data']))
                        #print(process_command_line)

                #Summary of process Execution
                if EventID[0]=="4688" or EventID[0]=="4648" or EventID[0]=="4673":
                    try:
                        #process_name=" "
                        for i in Process_Name[0]:
                            if len(i)>0:
                                process_name=i
                        #print(process_name)
                        #print(len(Process_Name[0]),Process_Name[0])
                        #print(process_name)
                        #print(Executed_Process_Summary[0]['Process Name'])
                        #print(process_name not in Executed_Process_Summary[0]['Process Name'])
                        if process_name not in Executed_Process_Summary[0]['Process Name']:
                            Executed_Process_Summary[0]['Process Name'].append(process_name.strip())
                            Executed_Process_Summary[0]['Number of Execution'].append(1)
                        else :
                            Executed_Process_Summary[0]['Number of Execution'][Executed_Process_Summary[0]['Process Name'].index(process_name.strip())]=Executed_Process_Summary[0]['Number of Execution'][Executed_Process_Summary[0]['Process Name'].index(process_name.strip())]+1
                    except:
                        pass

                #report of process Execution
                if (processexec==True or allreport==True) and EventID[0]=="4688":
                    #try:

                    if 1==1:
                        process_name="None"
                        parent_process_name="None"
                        for i in Process_Name[0]:
                            if len(i)>0:
                                process_name=i

                        for i in Account_Name[0]:
                            if len(i)>0:
                                user=i
                        if len(Parent_Process_Name)>0:
                            for i in Parent_Process_Name[0]:
                                if len(i)>0:
                                    parent_process_name=i
                        else:
                            parent_process_name="None"
                        Executed_Process_Events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Executed_Process_Events[0]['DateTime'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Executed_Process_Events[0]['ProcessName'].append(process_name)
                        Executed_Process_Events[0]['User'].append(user)
                        Executed_Process_Events[0]['ParentProcessName'].append(parent_process_name)
                        Executed_Process_Events[0]['EventID'].append(EventID[0])
                        Executed_Process_Events[0]['RawLog'].append(str(record['data']).replace("\r"," "))

                    #except:
                    #    print("issue adding events to Process execution events"+str(record['data']))


                # non-interactive powershell being executed by another application in the background
                if EventID[0]=="4688" :
                    try:
                        #process_name=" "
                        for i in New_Process_Name[0]:
                            if len(i)>0:
                                process_name=i

                        for i in Parent_Process_Name[0]:
                            if len(i)>0:
                                parent_process_name=i

                        if process_name[0].lower().find("powershell.exe")>-1 and parent_process_name[0].lower().find("explorer.exe")==-1:
                            try:
                                Event_desc ="User Name : ( %s ) "%user+" executed non-interactive ( " + New_Process_Name[0] + " ) through  : ( " + Parent_Process_Name[0] + " ) ."
                            except:
                                Event_desc = "user executed non interactive process through process."
                            Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                            Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                            Security_events[0]['Detection Rule'].append("non-interactive powershell being executed by another application in the background")
                            Security_events[0]['Detection Domain'].append("Audit")
                            Security_events[0]['Severity'].append("High")
                            Security_events[0]['Event Description'].append(Event_desc)
                            Security_events[0]['Event ID'].append(EventID[0])
                            Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    except:
                        pass

                # User Created through management interface
                if EventID[0]=="4720":
                    try:
                        if len(Account_Name[0][0])>0:
                            user=Account_Name[0][0].strip()
                            target_account_name=Target_Account_Name[0][0].strip()
                        if len(Account_Name[0][1])>0:
                            user=Account_Name[0][1].strip()
                            target_account_name=Target_Account_Name[0][1].strip()
                        #print("##### " + record["timestamp"] + " ####  ", end='')
                        #print("User Name ( " + Account_Name[0][0].strip() + " )", end='')
                        #print(" Created User Name ( " + Account_Name[1].strip()+ " )")

                        Event_desc="User Name ( " + user + " )" + " Created User Name ( " + target_account_name+ " )"
                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("User Created through management interface")
                        Security_events[0]['Detection Domain'].append("Audit")
                        Security_events[0]['Severity'].append("Medium")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    except:
                        Event_desc="User Created through management interface"
                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("User Created through management interface")
                        Security_events[0]['Detection Domain'].append("Audit")
                        Security_events[0]['Severity'].append("Medium")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                # Detect Dcsync attack
                if EventID[0]=="5136" or EventID[0]=="4662":
                    try:
                        if len(Account_Name[0][0])>0:
                            user=Account_Name[0][0].strip()
                        else:
                            user=""
                        #print("##### " + record["timestamp"] + " ####  ", end='')
                        #print("User Name ( " + Account_Name[0][0].strip() + " )", end='')
                        #print(" Created User Name ( " + Account_Name[1].strip()+ " )")
                        if user.find("$")<0 and ( str(record['data']).find("Replicating Directory Changes all")>0 or str(record['data']).find("1131f6ad-9c07-11d1-f79f-00c04fc2dcd2")>0 or str(record['data']).find("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2")>0 or str(record['data']).find("9923a32a-3607-11d2-b9be-0000f87a36b2")>0):
                            Event_desc="User Name ( " + user + " ) is suspected doing dcsync attack "
                            Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                            Security_events[0]['Computer Name'].append(Computer[0])
                            Security_events[0]['Channel'].append(Channel[0])
                            Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                            Security_events[0]['Detection Rule'].append("Dcsync Attack detected")
                            Security_events[0]['Detection Domain'].append("Threat")
                            Security_events[0]['Severity'].append("High")
                            Security_events[0]['Event Description'].append(Event_desc)
                            Security_events[0]['Event ID'].append(EventID[0])
                            Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    except:
                        print("issue parsing log : "+str(record['data']))


                # Detect Dcshadow attack
                if EventID[0]=="4742":
                    try:
                        if len(Account_Name[0][0])>0:
                            user=Account_Name[0][0].strip()
                        else:
                            user=""
                        #print("##### " + record["timestamp"] + " ####  ", end='')
                        #print("User Name ( " + Account_Name[0][0].strip() + " )", end='')
                        #print(" Created User Name ( " + Account_Name[1].strip()+ " )")
                        if user.find("$")<0 and  str(record['data']).find("E3514235-4B06-11D1-AB04-00C04FC2DCD2")>0 and str(record['data']).find(r"GC/.*/.*")>0:
                            Event_desc="User Name ( " + user + " ) is suspected doing dcshadow attack "
                            Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                            Security_events[0]['Computer Name'].append(Computer[0])
                            Security_events[0]['Channel'].append(Channel[0])
                            Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                            Security_events[0]['Detection Rule'].append("dcshadow Attack detected")
                            Security_events[0]['Detection Domain'].append("Threat")
                            Security_events[0]['Severity'].append("High")
                            Security_events[0]['Event Description'].append(Event_desc)
                            Security_events[0]['Event ID'].append(EventID[0])
                            Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    except:
                        print("issue parsing log : "+str(record['data']))


                # Detect A network share object was added.
                if EventID[0]=="5142":
                    try:
                        if len(Account_Name[0][0])>0:
                            user=Account_Name[0][0].strip()
                        else:
                            user=""
                        #print("##### " + record["timestamp"] + " ####  ", end='')
                        #print("User Name ( " + Account_Name[0][0].strip() + " )", end='')
                        #print(" Created User Name ( " + Account_Name[1].strip()+ " )")
                        Event_desc="User Name ( " + user + " ) add new share ( "+ShareName[0][0].strip()+" ) with path ( "+ShareLocalPath+" )"
                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("network share object was added")
                        Security_events[0]['Detection Domain'].append("Threat")
                        Security_events[0]['Severity'].append("High")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    except:
                        Event_desc="network share object was added"
                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("network share object was added")
                        Security_events[0]['Detection Domain'].append("Threat")
                        Security_events[0]['Severity'].append("High")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))


                # Windows is shutting down
                if EventID[0]=="4609" or EventID[0]=="1100":
                    #print("##### " + record["timestamp"] + " ####  ", end='')
                    #print("User Name ( " + Account_Name[0][0].strip() + " )", end='')
                    #print(" Created User Name ( " + Account_Name[1].strip()+ " )")

                    Event_desc="Windows is shutting down )"
                    Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Security_events[0]['Computer Name'].append(Computer[0])
                    Security_events[0]['Channel'].append(Channel[0])
                    Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Security_events[0]['Detection Rule'].append("Windows is shutting down")
                    Security_events[0]['Detection Domain'].append("Audit")
                    Security_events[0]['Severity'].append("Medium")
                    Security_events[0]['Event Description'].append(Event_desc)
                    Security_events[0]['Event ID'].append(EventID[0])
                    Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))




                # User added to local group
                if EventID[0]=="4732":
                    try:
                        #print("##### " + record["timestamp"] + " ####  ", end='')
                        #print("User ( " + Account_Name[0][0].strip() + " ) added User ( "+Security_ID[1].strip(), end='')
                        #print(" to local group ( " + Group_Name[0][0].strip() + " )")
                        if len(Account_Name[0][0])>0:
                            user=Account_Name[0][0].strip()
                            member_name=Member_Name[0][0].strip()
                            group_name=Group_Name[0][0].strip()
                            member_sid=Member_Sid[0][0].strip()
                        if len(Account_Name[0][1])>0:
                            user=Account_Name[0][1].strip()
                            member_name=Member_Name[0][1].strip()
                            group_name=Group_Name[0][1].strip()
                            member_sid=Member_Sid[0][1].strip()

                        try :
                            if member_name!="-":
                                Event_desc="User ( " + user + " ) added User ( "+member_name+" ) to local group ( " + group_name + " )"
                            else:
                                Event_desc = "User ( " + user + " ) added User ( " + member_sid + " ) to local group ( " + group_name + " )"
                        except:
                            Event_desc = "User ( " + user + " ) added User ( " + member_sid + " ) to local group ( " + group_name + " )"


                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("User added to local group")
                        Security_events[0]['Detection Domain'].append("Audit")
                        Security_events[0]['Severity'].append("High")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    except:
                        Event_desc="User added to local group"
                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("User added to local group")
                        Security_events[0]['Detection Domain'].append("Audit")
                        Security_events[0]['Severity'].append("High")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                #add user to global group
                if EventID[0] == "4728":

                    try:
                        if len(Account_Name[0][0])>0:
                            user=Account_Name[0][0].strip()
                            member_name=Member_Name[0][0].strip()
                            group_name=Group_Name[0][0].strip()
                        if len(Account_Name[0][1])>0:
                            user=Account_Name[0][1].strip()
                            member_name=Member_Name[0][1].strip()
                            group_name=Group_Name[0][1].strip()
                        #print("##### " + record["timestamp"] + " ####  ", end='')
                        #print("User ( " + Account_Name[0][0].strip() + " ) added User ( "+Security_ID[1].strip(), end='')
                        #print(" to Global group ( " + Group_Name[0][0].strip() + " )")
                        try :
                            if member_name!="-":
                                Event_desc="User ( " + user + " ) added User ( "+member_name+" ) to Global group ( " + group_name + " )"
                            else:
                                Event_desc = "User ( " + user + " ) added User ( " + member_sid + " ) to Global group ( " + group_name + " )"
                        except:
                            Event_desc = "User ( " + user + " ) added User ( " + member_name + " ) to Global group ( " + group_name + " )"
                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("User added to global group")
                        Security_events[0]['Detection Domain'].append("Audit")
                        Security_events[0]['Severity'].append("High")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    except:
                        Event_desc="User added to global group"
                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("User added to global group")
                        Security_events[0]['Detection Domain'].append("Audit")
                        Security_events[0]['Severity'].append("High")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))


                #add user to universal group
                if EventID[0] == "4756":
                    try:
                        if len(Account_Name[0][0])>0:
                            user=Account_Name[0][0].strip()
                            member_name=Member_Name[0][0].strip()
                            group_name=Group_Name[0][0].strip()
                            target_account_name=Target_Account_Name[0][0].strip()
                        if len(Account_Name[0][1])>0:
                            user=Account_Name[0][1].strip()
                            member_name=Member_Name[0][1].strip()
                            group_name=Group_Name[0][1].strip()
                            target_account_name=Target_Account_Name[0][1].strip()
                        #print("##### " + record["timestamp"] + " ####  ", end='')
                        #print("User ( " + Account_Name[0][0].strip() + " ) added User ( "+Security_ID[1].strip(), end='')
                        Event_desc ="User ( " + user + " ) added User ( "+member_name
                        if len(group_name)>0:
                            #print(" to Universal group ( " + Group_Name[0][0].strip() + " )")
                            Event_desc=Event_desc+" to Universal group ( " + group_name + " )"
                        else:
                            Event_desc = Event_desc +" to Universal group ( " + target_account_name + " )"
                            #print(" to Universal group ( " + Account_Name[1].strip() + " )")

                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("User added to Universal group")
                        Security_events[0]['Detection Domain'].append("Audit")
                        Security_events[0]['Severity'].append("High")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                    except:
                        Event_desc ="User added to Universal group"
                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("User added to Universal group")
                        Security_events[0]['Detection Domain'].append("Audit")
                        Security_events[0]['Severity'].append("High")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                #remove user from global group
                if EventID[0] == "4729":
                    try:
                        if len(Account_Name[0][0])>0:
                            user=Account_Name[0][0].strip()
                            member_name=Member_Name[0][0].strip()
                            group_name=Group_Name[0][0].strip()
                            target_account_name=Target_Account_Name[0][0].strip()
                        if len(Account_Name[0][1])>0:
                            user=Account_Name[0][1].strip()
                            member_name=Member_Name[0][1].strip()
                            group_name=Group_Name[0][1].strip()
                            target_account_name=Target_Account_Name[0][1].strip()
                        #print("##### " + record["timestamp"] + " ####  ", end='')
                        #print("User ( " + Account_Name[0][0].strip() + " ) removed User ( "+Security_ID[1].strip(), end='')
                        Event_desc ="User ( " +user + " ) removed User ( "+member_name
                        if len(group_name)>0:
                            #print(") from Global group ( " + Group_Name[0][0].strip() + " )")
                            Event_desc = Event_desc +") from Global group ( " + group_name + " )"
                        else:
                            Event_desc = Event_desc +") from Global group ( " + target_account_name + " )"
                            #print(") from Global group ( " + Account_Name[1].strip() + " )")


                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("User Removed from Global Group")
                        Security_events[0]['Detection Domain'].append("Audit")
                        Security_events[0]['Severity'].append("High")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                    except:
                        Event_desc ="User Removed from Global Group"
                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("User Removed from Global Group")
                        Security_events[0]['Detection Domain'].append("Audit")
                        Security_events[0]['Severity'].append("High")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                #remove user from universal group
                if EventID[0] == "4757":
                    try:
                        if len(Account_Name[0][0])>0:
                            user=Account_Name[0][0].strip()
                            member_name=Member_Name[0][0].strip()
                            group_name=Group_Name[0][0].strip()
                            target_account_name=Target_Account_Name[0][0].strip()
                        if len(Account_Name[0][1])>0:
                            user=Account_Name[0][1].strip()
                            member_name=Member_Name[0][1].strip()
                            group_name=Group_Name[0][1].strip()
                            target_account_name=Target_Account_Name[0][1].strip()
                        #print("##### " + record["timestamp"] + " ####  ", end='')
                        #print("User ( " + Account_Name[0][0].strip() + " ) removed User ( "+Security_ID[1].strip(), end='')
                        Event_desc ="User ( " + user + " ) removed User ( "+member_name
                        if len(group_name)>0:
                            #print(") from Universal group ( " + Group_Name[0][0].strip() + " )")
                            Event_desc = Event_desc+") from Universal group ( " + group_name + " )"
                        else:
                            #print(") from Universal group ( " + Account_Name[1].strip() + " )")
                            Event_desc = Event_desc +") from Universal group ( " + target_account_name + " )"

                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("User Removed from Universal Group")
                        Security_events[0]['Detection Domain'].append("Audit")
                        Security_events[0]['Severity'].append("High")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                    except:
                        Event_desc ="User Removed from Universal Group"
                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("User Removed from Universal Group")
                        Security_events[0]['Detection Domain'].append("Audit")
                        Security_events[0]['Severity'].append("High")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                #remove user from local group
                if EventID[0] == "4733":

                    try:
                        if len(Account_Name[0][0])>0:
                            user=Account_Name[0][0].strip()
                            member_name=Member_Name[0][0].strip()
                            group_name=Group_Name[0][0].strip()
                            target_account_name=Target_Account_Name[0][0].strip()
                        if len(Account_Name[0][1])>0:
                            user=Account_Name[0][1].strip()
                            member_name=Member_Name[0][1].strip()
                            group_name=Group_Name[0][1].strip()
                            target_account_name=Target_Account_Name[0][1].strip()
                        #print("##### " + record["timestamp"] + " ####  ", end='')
                        #print("User ( " + Account_Name[0][0].strip() + " ) removed User ( "+Security_ID[1].strip(), end='')
                        Event_desc ="User ( " + user + " ) removed User ( "+member_name
                        if len(group_name)>0:
                            #print(") from Local group ( " + Group_Name[0][0].strip() + " )")
                            Event_desc = Event_desc +") from Local group ( " + group_name + " )"
                        else:
                            #print(") from Local group ( " + Account_Name[1].strip() + " )")
                            Event_desc = Event_desc +") from Local group ( " + target_account_name + " )"

                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("User Removed from Local Group")
                        Security_events[0]['Detection Domain'].append("Audit")
                        Security_events[0]['Severity'].append("High")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                    except:
                        Event_desc ="User Removed from Local Group"
                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("User Removed from Local Group")
                        Security_events[0]['Detection Domain'].append("Audit")
                        Security_events[0]['Severity'].append("High")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))


                #user removed group from global
                if EventID[0] == "4730":

                    try:
                        if len(Account_Name[0][0])>0:
                            user=Account_Name[0][0].strip()
                            member_name=Member_Name[0][0].strip()
                            group_name=Group_Name[0][0].strip()
                            target_account_name=Target_Account_Name[0][0].strip()
                        if len(Account_Name[0][1])>0:
                            user=Account_Name[0][1].strip()
                            member_name=Member_Name[0][1].strip()
                            group_name=Group_Name[0][1].strip()
                            target_account_name=Target_Account_Name[0][1].strip()

                        #print("##### " + record["timestamp"] + " ####  ", end='')
                        #print("User ( " + Account_Name[0][0].strip() + " ) removed Group ( ", end='')

                        Event_desc ="User ( " + user + " ) removed Group ( "+target_account_name+ " )"

                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("User Removed Group")
                        Security_events[0]['Detection Domain'].append("Audit")
                        Security_events[0]['Severity'].append("High")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                    except:
                        Event_desc ="User Removed Group"
                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("User Removed Group")
                        Security_events[0]['Detection Domain'].append("Audit")
                        Security_events[0]['Severity'].append("High")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))


                #user account removed
                if EventID[0] == "4726":
                    #print("##### " + record["timestamp"] + " ####  ", end='')
                    #print("User ( " + Account_Name[0][0].strip() + " ) removed user ", end='')
                    #print("( " + Account_Name[1].strip() + " )")
                    try:
                        if len(Account_Name[0][0])>0:
                            user=Account_Name[0][0].strip()
                            target_account_name=Target_Account_Name[0][0].strip()
                        if len(Account_Name[0][1])>0:
                            user=Account_Name[0][1].strip()
                            target_account_name=Target_Account_Name[0][1].strip()

                        Event_desc ="User ( " + user + " ) removed user "+"( " + target_account_name + " )"
                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("User Account Removed")
                        Security_events[0]['Detection Domain'].append("Audit")
                        Security_events[0]['Severity'].append("High")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                    except:
                        Event_desc ="User Account Removed"
                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("User Account Removed")
                        Security_events[0]['Detection Domain'].append("Audit")
                        Security_events[0]['Severity'].append("High")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                if EventID[0] == "4625" :
                    try:
                        if len(Target_Account_Name[0][0])>0:
                            target_user=Target_Account_Name[0][0].strip()
                        if len(Target_Account_Name[0][1])>0:
                            target_user=Target_Account_Name[0][1].strip()

                        if target_user not in Security_Authentication_Summary[0]['User']:
                            Security_Authentication_Summary[0]['User'].append(target_user)
                            Security_Authentication_Summary[0]['Number of Failed Logins'].append(1)
                            Security_Authentication_Summary[0]['Number of Successful Logins'].append(0)
                        else :
                            try:
                                Security_Authentication_Summary[0]['Number of Failed Logins'][
                                    Security_Authentication_Summary[0]['User'].index(target_user)] = \
                                Security_Authentication_Summary[0]['Number of Failed Logins'][
                                    Security_Authentication_Summary[0]['User'].index(target_user)] + 1
                            except:
                                print("User : "+target_user +  " array : ")
                                print(Security_Authentication_Summary[0])
                    except:
                        print("error in analyzing event 4625 summary loging")


                if EventID[0] == "4624" :
                    #print(EventID[0])
                    try:

                        if len(Target_Account_Name[0][0])>0:
                            target_user=Target_Account_Name[0][0].strip()
                            if not Security_ID_Target[0][0].strip() in User_SIDs[0]['SID']:
                                User_SIDs[0]['User'].append(Target_Account_Name[0][0].strip())
                                User_SIDs[0]['SID'].append(Security_ID_Target[0][0].strip())
                        if len(Target_Account_Name[0][1])>0:
                            target_user=Target_Account_Name[0][1].strip()
                            if not Security_ID_Target[0][1].strip() in User_SIDs[0]['SID']:
                                User_SIDs[0]['User'].append(Target_Account_Name[0][1].strip())
                                User_SIDs[0]['SID'].append(Security_ID_Target[0][1].strip())

                        if target_user.strip() not in Security_Authentication_Summary[0]['User']:
                            Security_Authentication_Summary[0]['User'].append(target_user)
                            Security_Authentication_Summary[0]['Number of Successful Logins'].append(1)
                            Security_Authentication_Summary[0]['Number of Failed Logins'].append(0)
                        else :
                            Security_Authentication_Summary[0]['Number of Successful Logins'][
                                Security_Authentication_Summary[0]['User'].index(target_user)] = \
                            Security_Authentication_Summary[0]['Number of Successful Logins'][
                            Security_Authentication_Summary[0]['User'].index(target_user)] + 1
                    except:
                        print("error in analyzing event 4624 summary loging")

                #password spray detection
                if EventID[0] == "4648" :
                    try:

                        user=''
                        target_user=''
                        if len(Account_Name[0][0])>0:
                            user=Account_Name[0][0].strip()
                        if len(Account_Name[0][1])>0:
                            user=Account_Name[0][1].strip()
                        if len(Target_Account_Name[0][0])>0:
                            target_user=Target_Account_Name[0][0].strip()
                        if len(Target_Account_Name[0][1])>0:
                            target_user=Target_Account_Name[0][1].strip()


                        if user not in PasswordSpray:
                            PasswordSpray[user]=[]
                            PasswordSpray[user].append(target_user)
                        if target_user not in PasswordSpray[user] :
                            PasswordSpray[user].append(target_user)
                    except:
                        continue



                #detect pass the hash
                if (logons==True or allreport==True) and EventID[0] == "4625" or EventID[0] == "4624":
                    #print(Logon_Events,str(record['data']))
                    try:
                        #print(Logon_Events)
                        if len(Account_Name[0][0])>0:
                            logon_type=Logon_Type[0][0].strip()
                            user=Account_Name[0][0].strip()
                            target_account_name=Target_Account_Name[0][0].strip()
                            logon_process=Logon_Process[0][0].strip()
                            key_length=Key_Length[0][0].strip()
                            target_account_domain=Target_Account_Domain[0][0].strip()
                            source_ip=Source_IP[0][0].strip()
                            workstation_name=Workstation_Name[0][0].strip()
                        if len(Account_Name[0][1])>0:
                            logon_type=Logon_Type[0][1].strip()
                            target_account_name=Target_Account_Name[0][1].strip()
                            logon_process=Logon_Process[0][1].strip()
                            key_length=Key_Length[0][1].strip()
                            target_account_domain=Target_Account_Domain[0][1].strip()
                            source_ip=Source_IP[0][1].strip()
                            workstation_name=Workstation_Name[0][1].strip()

                        #print(Logon_Events)
                        #record every authentication
                        Logon_Events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Logon_Events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Logon_Events[0]['Event ID'].append(EventID[0])
                        Logon_Events[0]['Computer Name'].append(Computer[0])
                        Logon_Events[0]['Channel'].append(Channel[0])
                        Logon_Events[0]['Account Name'].append(target_account_name)
                        Logon_Events[0]['Account Domain'].append(target_account_domain)
                        Logon_Events[0]['Logon Type'].append(logon_type)
                        Logon_Events[0]['Logon Process'].append(logon_process)
                        Logon_Events[0]['Source IP'].append(source_ip)
                        Logon_Events[0]['Workstation Name'].append(workstation_name)
                        Logon_Events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                        if logon_type == "3" and target_account_name != "ANONYMOUS LOGON" and target_account_name.find("$")==-1 and logon_process == "NtLmSsp" and key_length == "0":
                            #print("##### " + record["timestamp"] + " ####  ", end='')
                            #print(
                            #        "Pass the hash attempt Detected : user name ( %s ) domain name ( %s ) from  IP ( %s ) and machine name ( %s )" % (
                            #        Account_Name[1].strip(), Account_Domain[1].strip(), Source_IP[0][0].strip(), Workstation_Name[0][0].strip()))
                            try:

                                #print(Pass_the_hash_users)
                                #

                                #print(target_account_name)
                                if target_account_name.strip() not in Pass_the_hash_users[0]['User']:
                                    #print("user not in pass the hash observed")
                                    Pass_the_hash_users[0]['User'].append(target_account_name)
                                    Pass_the_hash_users[0]['Number of Logins'].append(1)
                                    Pass_the_hash_users[0]['Reached'].append(0)
                                elif Pass_the_hash_users[0]['Reached'][Pass_the_hash_users[0]['User'].index(target_account_name)]<1 :
                                    Pass_the_hash_users[0]['Number of Logins'][
                                            Pass_the_hash_users[0]['User'].index(target_account_name)] = \
                                        Pass_the_hash_users[0]['Number of Logins'][
                                        Pass_the_hash_users[0]['User'].index(target_account_name)] + 1
                                #print(Pass_the_hash_users[0]['Number of Logins'][Pass_the_hash_users[0]['User'].index(target_account_name)])
                                if Pass_the_hash_users[0]['Reached'][Pass_the_hash_users[0]['User'].index(target_account_name)]>0:
                                    #print("True observed")
                                    continue
                                if Pass_the_hash_users[0]['Number of Logins'][Pass_the_hash_users[0]['User'].index(target_account_name)]>200:
                                    Pass_the_hash_users[0]['Reached'][Pass_the_hash_users[0]['User'].index(target_account_name)]=1
                                    Event_desc ="High number of Pass the hash attempt Detected from user name ( %s ) domain name ( %s ) . detection will be paused for this user to not flood the detection list" % (
                                        target_account_name, target_account_domain)
                                    Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                                    Security_events[0]['Computer Name'].append(Computer[0])
                                    Security_events[0]['Channel'].append(Channel[0])
                                    Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                                    Security_events[0]['Detection Rule'].append("High number of Pass the hash attempt Detected . detection will be paused for this user to not flood the detection list")
                                    Security_events[0]['Detection Domain'].append("Threat")
                                    if EventID[0].find("4624") > -1:
                                        Security_events[0]['Severity'].append("Critical")
                                    else:
                                        Security_events[0]['Severity'].append("Medium")
                                    Security_events[0]['Event Description'].append(Event_desc)
                                    Security_events[0]['Event ID'].append(EventID[0])
                                    Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                                    continue

                                Event_desc ="Pass the hash attempt Detected : user name ( %s ) domain name ( %s ) from  IP ( %s ) and machine name ( %s )" % (
                                    target_account_name, target_account_domain, source_ip, workstation_name)
                                Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                                Security_events[0]['Computer Name'].append(Computer[0])
                                Security_events[0]['Channel'].append(Channel[0])
                                Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                                Security_events[0]['Detection Rule'].append("Pass the hash attempt Detected")
                                Security_events[0]['Detection Domain'].append("Threat")
                                if EventID[0].find("4624") > -1:
                                    Security_events[0]['Severity'].append("Critical")
                                else:
                                    Security_events[0]['Severity'].append("Medium")
                                Security_events[0]['Event Description'].append(Event_desc)
                                Security_events[0]['Event ID'].append(EventID[0])
                                Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                                #print(Event_desc)
                            except:
                                Event_desc ="Pass the hash attempt Detected "
                                Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                                Security_events[0]['Computer Name'].append(Computer[0])
                                Security_events[0]['Channel'].append(Channel[0])
                                Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                                Security_events[0]['Detection Rule'].append("Pass the hash attempt Detected")
                                Security_events[0]['Detection Domain'].append("Threat")
                                if EventID[0].find("4624") > -1:
                                    Security_events[0]['Severity'].append("Critical")
                                else:
                                    Security_events[0]['Severity'].append("Medium")
                                Security_events[0]['Event Description'].append(Event_desc)
                                Security_events[0]['Event ID'].append(EventID[0])
                                Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    except:
                        print("Error parsing Event")

                #Audit log cleared
                if EventID[0] == "517" or EventID[0] == "1102":
                        """print("##### " + record["timestamp"] + " ####  ", end='')
                        print(
                                "Audit log cleared by user ( %s )" % (
                                Account_Name[0][0].strip()))
                        """
                        try:
                            if (len(Account_Name[0][0].strip())>1):
                                Event_desc = "Audit log cleared by user ( %s )" % (
                                Account_Name[0][0].strip())
                            else:
                                Event_desc = "Audit log cleared by user ( %s )" % (
                            Account_Name[0][1].strip())

                        except:
                            Event_desc = "Audit log cleared by user"

                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("Audit log cleared")
                        Security_events[0]['Detection Domain'].append("Audit")
                        Security_events[0]['Severity'].append("Critical")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                #Suspicious Attempt to enumerate users or groups
                """if EventID[0] == "4798" or EventID[0] == "4799" and record['data'].find("System32\\svchost.exe")==-1:
                        #print("##### " + record["timestamp"] + " ####  ", end='')
                        #print(
                        #        "Suspicious Attempt to enumerate groups by user ( %s ) using process ( %s )" % (
                        #        Account_Name[0][0].strip(),Process_Name[0][0].strip()))

                        try:
                            if len(Account_Name[0][0])>0:
                                process_name=Process_Name[0][0].strip()
                                user=Account_Name[0][0].strip()
                            if len(Account_Name[0][1])>0:
                                process_name=Process_Name[0][1].strip()
                                user=Account_Name[0][1].strip()

                            Event_desc ="Suspicious Attempt to enumerate groups by user ( %s ) using process ( %s )" % (user,process_name)
                            Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                            Security_events[0]['Computer Name'].append(Computer[0])
                            Security_events[0]['Channel'].append(Channel[0])
                            Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                            Security_events[0]['Detection Rule'].append("Suspicious Attempt to enumerate groups")
                            Security_events[0]['Detection Domain'].append("Audit")
                            Security_events[0]['Severity'].append("Medium")
                            Security_events[0]['Event Description'].append(Event_desc)
                            Security_events[0]['Event ID'].append(EventID[0])
                            Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                        except:
                            Event_desc ="Suspicious Attempt to enumerate groups by user"
                            Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                            Security_events[0]['Computer Name'].append(Computer[0])
                            Security_events[0]['Channel'].append(Channel[0])
                            Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                            Security_events[0]['Detection Rule'].append("Suspicious Attempt to enumerate groups")
                            Security_events[0]['Detection Domain'].append("Audit")
                            Security_events[0]['Severity'].append("High")
                            Security_events[0]['Event Description'].append(Event_desc)
                            Security_events[0]['Event ID'].append(EventID[0])
                            Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                """
                #System audit policy was changed
                if EventID[0] == "4719" and Security_ID[0][0].strip()!="S-1-5-18" and Security_ID[0][0].strip()!="SYSTEM" :
                        """print("##### " + record["timestamp"] + " ####  ", end='')
                        print(
                                "System audit policy was changed by user ( %s ) , Audit Poricly category ( %s ) , Subcategory ( %s ) with changes ( %s )" % (
                                Account_Name[0][0].strip(),Category[0].strip(),Subcategory[0].strip(),Changes[0].strip()))
                        """

                        try :
                            if len(Account_Name[0][0])>0:
                                category=Category[0][0].strip()
                                user=Account_Name[0][0].strip()
                                subcategory=Subcategory[0][0].strip()
                                changes=Changes[0][0].strip()
                            if len(Account_Name[0][1])>0:
                                category=Category[0][1].strip()
                                subcategory=Subcategory[0][1].strip()
                                changes=Changes[0][1].strip()
                                user=Account_Name[0][1].strip()

                            Event_desc ="System audit policy was changed by user ( %s ) , Audit Poricly category ( %s ) , Subcategory ( %s ) with changes ( %s )" % (user,category,subcategory,changes)
                        except :
                            Event_desc = "System audit policy was changed by user"
                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("System audit policy was changed")
                        Security_events[0]['Detection Domain'].append("Audit")
                        Security_events[0]['Severity'].append("High")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))

                #scheduled task created
                if EventID[0]=="4698" :
                    #print("##### " + record["timestamp"] + " ####  ", end='')

                    #print("schedule task created by user ( %s ) with task name ( %s ) , Command ( %s ) and Argument ( %s )  " % ( Account_Name[0][0].strip(),Task_Name[0][0].strip(),Task_Command[0][0],Task_args[0][0]))

                        try:
                            if len(Account_Name[0][0])>0:
                                task_command=Task_Command[0][0].strip()
                                user=Account_Name[0][0].strip()
                                task_name=Task_Name[0][0].strip()
                                task_args=Task_args[0][0].strip()
                            if len(Account_Name[0][1])>0:
                                task_command=Task_Command[0][1].strip()
                                user=Account_Name[0][1].strip()
                                task_name=Task_Name[0][1].strip()
                                task_args=Task_args[0][1].strip()

                            Event_desc ="schedule task created by user ( %s ) with task name ( %s ) , Command ( %s ) and Argument ( %s )  " % ( user,task_name,task_command,task_args)
                        except:
                            Event_desc = "schedule task created by user"
                        Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Security_events[0]['Computer Name'].append(Computer[0])
                        Security_events[0]['Channel'].append(Channel[0])
                        Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Security_events[0]['Detection Rule'].append("schedule task created")
                        Security_events[0]['Detection Domain'].append("Audit")
                        Security_events[0]['Severity'].append("High")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(EventID[0])
                        Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                #scheduled task deleted
                if EventID[0]=="1699" :
                    #print("##### " + record["timestamp"] + " ####  ", end='')

                    #print("schedule task deleted by user ( %s ) with task name ( %s ) , Command ( %s ) and Argument ( %s )  " % ( Account_Name[0][0].strip(),Task_Name[0][0].strip(),Task_Command[0][0],Task_args[0][0]))
                    try :
                        if len(Account_Name[0][0])>0:
                            task_command=Task_Command[0][0].strip()
                            user=Account_Name[0][0].strip()
                            task_name=Task_Name[0][0].strip()
                            task_args=Task_args[0][0].strip()
                        if len(Account_Name[0][1])>0:
                            task_command=Task_Command[0][1].strip()
                            user=Account_Name[0][1].strip()
                            task_name=Task_Name[0][1].strip()
                            task_args=Task_args[0][1].strip()
                        Event_desc ="schedule task deleted by user ( %s ) with task name ( %s ) , Command ( %s ) and Argument ( %s )  " % ( user,task_name,task_command,task_args)
                    except:
                        Event_desc = "schedule task deleted by user"
                    Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Security_events[0]['Computer Name'].append(Computer[0])
                    Security_events[0]['Channel'].append(Channel[0])
                    Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Security_events[0]['Detection Rule'].append("schedule task deleted")
                    Security_events[0]['Detection Domain'].append("Audit")
                    Security_events[0]['Severity'].append("High")
                    Security_events[0]['Event Description'].append(Event_desc)
                    Security_events[0]['Event ID'].append(EventID[0])
                    Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                #schedule task updated
                if EventID[0]=="4702" :
                    #print("##### " + record["timestamp"] + " ####  ", end='')

                    #print("schedule task updated by user ( %s ) with task name ( %s ) , Command ( %s ) and Argument ( %s )  " % ( Account_Name[0][0].strip(),Task_Name[0][0].strip(),Task_Command[0][0],Task_args[0][0]))
                    try:
                        if len(Account_Name[0][0])>0:
                            task_command=Task_Command[0][0].strip()
                            user=Account_Name[0][0].strip()
                            task_name=Task_Name[0][0].strip()
                            task_args=Task_args[0][0].strip()
                        if len(Account_Name[0][1])>0:
                            task_command=Task_Command[0][1].strip()
                            user=Account_Name[0][1].strip()
                            task_name=Task_Name[0][1].strip()
                            task_args=Task_args[0][1].strip()
                        Event_desc ="schedule task updated by user ( %s ) with task name ( %s ) , Command ( %s ) and Argument ( %s )  " % (  user,task_name,task_command,task_args)
                    except:
                        Event_desc = "schedule task updated by user"
                    Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Security_events[0]['Computer Name'].append(Computer[0])
                    Security_events[0]['Channel'].append(Channel[0])
                    Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Security_events[0]['Detection Rule'].append("schedule task updated")
                    Security_events[0]['Detection Domain'].append("Audit")
                    Security_events[0]['Severity'].append("Low")
                    Security_events[0]['Event Description'].append(Event_desc)
                    Security_events[0]['Event ID'].append(EventID[0])
                    Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                #schedule task enabled
                if EventID[0]=="4700" :
                    #print("##### " + record["timestamp"] + " ####  ", end='')

                    #print("schedule task enabled by user ( %s ) with task name ( %s )  " % ( Account_Name[0][0].strip(),Task_Name[0][0].strip(),Task_Command[0][0],Task_args[0][0]))
                    try :
                        if len(Account_Name[0][0])>0:
                            task_command=Task_Command[0][0].strip()
                            user=Account_Name[0][0].strip()
                            task_name=Task_Name[0][0].strip()
                            task_args=Task_args[0][0].strip()
                        if len(Account_Name[0][1])>0:
                            task_command=Task_Command[0][1].strip()
                            user=Account_Name[0][1].strip()
                            task_name=Task_Name[0][1].strip()
                            task_args=Task_args[0][1].strip()
                        Event_desc ="schedule task enabled by user ( %s ) with task name ( %s )  " % (  user,task_name,task_command,task_args)
                    except:
                        Event_desc = "schedule task enabled by user"
                    Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Security_events[0]['Computer Name'].append(Computer[0])
                    Security_events[0]['Channel'].append(Channel[0])
                    Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Security_events[0]['Detection Rule'].append("schedule task enabled")
                    Security_events[0]['Detection Domain'].append("Audit")
                    Security_events[0]['Severity'].append("High")
                    Security_events[0]['Event Description'].append(Event_desc)
                    Security_events[0]['Event ID'].append(EventID[0])
                    Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                #schedule task disabled
                if EventID[0]=="4701" :
                    #print("##### " + record["timestamp"] + " ####  ", end='')

                    #print("schedule task disabled by user ( %s ) with task name ( %s ) " % ( Account_Name[0][0].strip(),Task_Name[0][0].strip(),Task_Command[0][0],Task_args[0][0]))
                    try :
                        if len(Account_Name[0][0])>0:
                            task_command=Task_Command[0][0].strip()
                            user=Account_Name[0][0].strip()
                            task_name=Task_Name[0][0].strip()
                            task_args=Task_args[0][0].strip()
                        if len(Account_Name[0][1])>0:
                            task_command=Task_Command[0][1].strip()
                            user=Account_Name[0][1].strip()
                            task_name=Task_Name[0][1].strip()
                            task_args=Task_args[0][1].strip()
                        Event_desc ="schedule task disabled by user ( %s ) with task name ( %s ) " % (  user,task_name,task_command,task_args)
                    except:
                        Event_desc = "schedule task disabled by user"
                    Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Security_events[0]['Computer Name'].append(Computer[0])
                    Security_events[0]['Channel'].append(Channel[0])
                    Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Security_events[0]['Detection Rule'].append("schedule task disabled")
                    Security_events[0]['Detection Domain'].append("Audit")
                    Security_events[0]['Severity'].append("Medium")
                    Security_events[0]['Event Description'].append(Event_desc)
                    Security_events[0]['Event ID'].append(EventID[0])
                    Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))


                # user accessing directory service objects with replication permissions
                if EventID[0]=="4662" :
                    try :



                        if len(Account_Name[0][0])>0:
                            user        = Account_Name[0][0].strip()
                            processname = Process_Name[0][0].strip()
                            objectname  = Object_Name[0][0].strip()
                            objecttype  = Object_Type[0][0].strip()
                            objectserver = ObjectServer[0][1].strip()
                            AccessMask = AccessMask[0][1].strip()
                        if len(Account_Name[0][1])>0:
                            user        = Account_Name[0][1].strip()
                            processname = Process_Name[0][1].strip()
                            objectname  = Object_Name[0][1].strip()
                            objecttype  = Object_Type[0][1].strip()
                            objectserver = ObjectServer[0][1].strip()
                            accessmask = AccessMask[0][1].strip()

                        if ( objectserver.lower().find("DS")>-1 and accessmask.lower().find("0x40000")>-1 and objecttype.lower().find("19195a5b_6da0_11d0_afd3_00c04fd930c9")>-1 ) :
                            try:
                                Event_desc = "Non-system account ( %s ) with process ( %s ) got access to object ( %s ) of type ( %s )" % (user,processname,objectname,objecttype)
                            except:
                                Event_desc = "Non-system account with process got access to object"
                            Security_events[0]['Computer Name'].append(Computer[0])
                            Security_events[0]['Channel'].append(Channel[0])
                            Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                            Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                            Security_events[0]['Detection Rule'].append("non-system accounts getting a handle to and accessing lsass")
                            Security_events[0]['Detection Domain'].append("Audit")
                            Security_events[0]['Severity'].append("High")
                            Security_events[0]['Event Description'].append(Event_desc)
                            Security_events[0]['Event ID'].append(EventID[0])
                            Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    except :
                        pass

                # Object Access Statistics
                if (objectaccess==True or allreport==True) and EventID[0]=="4663" :
                    #print("in")
                    #try :
                    if 1==1:
                        if len(Account_Name[0][0])>0:
                            user        = Account_Name[0][0].strip()
                            #processname = Process_Name[0][0].strip()
                            objectname  = Object_Name[0][0].strip()
                            objecttype  = Object_Type[0][0].strip()
                        if len(Account_Name[0][1])>0:
                            user        = Account_Name[0][1].strip()
                            #processname = Process_Name[0][1].strip()
                            objectname  = Object_Name[0][1].strip()
                            objecttype  = Object_Type[0][1].strip()

                        Object_Access_Events[0]['Computer Name'].append(Computer[0])
                        Object_Access_Events[0]['Channel'].append(Channel[0])
                        Object_Access_Events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Object_Access_Events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Object_Access_Events[0]['Account Name'].append(user)
                        Object_Access_Events[0]['Object Name'].append(objectname)
                        Object_Access_Events[0]['Object Type'].append(objecttype)
                        Object_Access_Events[0]['Process Name'].append(ObjectProcessName[0])
                        Object_Access_Events[0]['Event ID'].append(EventID[0])
                        Object_Access_Events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                    #except Exception as e :
                    #    print("error parsing fields for "+str(record['data']))

                # non-system accounts with process requested accessing to object 4656
                if EventID[0]=="4656" or EventID[0]=="4663" :
                    try :

                        if len(Account_Name[0][0])>0:
                            user        = Account_Name[0][0].strip()
                            #processname = Process_Name[0][0].strip()
                            objectname  = Object_Name[0][0].strip()
                            objecttype  = Object_Type[0][0].strip()
                        if len(Account_Name[0][1])>0:
                            user        = Account_Name[0][1].strip()
                            #processname = Process_Name[0][1].strip()
                            objectname  = Object_Name[0][1].strip()
                            objecttype  = Object_Type[0][1].strip()


                        if len(Security_ID[0][0])>30 and objectname.lower().find("lsass.exe")>-1:
                            try:
                                Event_desc ="Non-system account ( %s ) with process ( %s ) got access to object ( %s ) of type ( %s )" % (user,ObjectProcessName[0],objectname,objecttype)
                            except:
                                Event_desc = "Non-system account with process got access to object"
                            Security_events[0]['Computer Name'].append(Computer[0])
                            Security_events[0]['Channel'].append(Channel[0])
                            Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                            Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                            Security_events[0]['Detection Rule'].append("non-system accounts getting a handle to and accessing lsass")
                            Security_events[0]['Detection Domain'].append("Audit")
                            Security_events[0]['Severity'].append("High")
                            Security_events[0]['Event Description'].append(Event_desc)
                            Security_events[0]['Event ID'].append(EventID[0])
                            Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    except Exception as e :
                        print("error parsing fields for "+str(record['data']))

            else:
                print(record['data'])
        for user in PasswordSpray:
            if len(PasswordSpray[user])>3 and user.find("$")<0:
                Event_desc = "Password Spray Detected by user ( "+user+" )"
                Security_events[0]['timestamp'].append(datetime.timestamp(datetime.now(input_timzone)))
                Security_events[0]['Computer Name'].append(Computer[0])
                Security_events[0]['Channel'].append(Channel[0])
                Security_events[0]['Date and Time'].append(datetime.now(input_timzone).isoformat())
                Security_events[0]['Detection Rule'].append("Password Spray Detected")
                Security_events[0]['Detection Domain'].append("Threat")
                Security_events[0]['Severity'].append("High")
                Security_events[0]['Event Description'].append(Event_desc)
                Security_events[0]['Event ID'].append("4648")
                Security_events[0]['Original Event Log'].append("User ( "+user+" ) did password sparay attack using usernames ( "+",".join(PasswordSpray[user])+" )")
        Security=pd.DataFrame(Security_events[0])
        #Security_Authentication = pd.DataFrame(Security_Authentication_Summary[0])
        Executed_Process = pd.DataFrame(Executed_Process_Summary[0])
        Security_Authentication_dataframes=[]
        lock.acquire()
        if os.path.exists(temp_dir +"Security_Authentication.pickle"):
            with open(temp_dir + "Security_Authentication.pickle", 'rb') as handle:
                #lock.acquire()
                try:
                    Security_Authentication_dataframes=pickle.load(handle)
                    handle.close()
                    #lock.release()
                    #print("Read:" + str(Security_Authentication_dataframes))
                except Exception as e:
                    print("Erorr : " + str(e))
                    #lock.release()
        else:
            with open(temp_dir + "Security_Authentication.pickle", 'wb') as handle:

                Security_Authentication_dataframes.append(pd.DataFrame(Security_Authentication_Summary[0]))
                #print("Write:" + str(Security_Authentication_dataframes))
                #lock.acquire()
                pickle.dump(Security_Authentication_dataframes, handle, protocol=pickle.HIGHEST_PROTOCOL)
                handle.close()
                #lock.release()
        with open(temp_dir + "Security_Authentication.pickle", 'wb') as handle:

            Security_Authentication_dataframes.append(pd.DataFrame(Security_Authentication_Summary[0]))
            #print("Write:" + str(Security_Authentication_dataframes))
            #lock.acquire()
            pickle.dump(Security_Authentication_dataframes, handle, protocol=pickle.HIGHEST_PROTOCOL)
            handle.close()
            #lock.release()
        lock.release()
        #Security_Authentication.to_csv(temp_dir + '_Security_Authentication_report.csv', index=False, quotechar='"')#, quoting=csv.QUOTE_NONNUMERIC)
        Executed_Process.to_csv(temp_dir + '_Executed_Process_report.csv', index=False, quotechar='"')#, quoting=csv.QUOTE_NONNUMERIC)
        if SecurityInitial.value == 1:
            Security.to_csv(temp_dir + '_Security_report.csv', index=False)

            SecurityInitial.value = 0
        else:
            Security.to_csv(temp_dir + '_Security_report.csv', mode='a', index=False, header=False)
        #if os.path.exists(temp_dir + "Security.pickle"):

            #Security_Authentication.to_csv(temp_dir + '_Security_Authentication_report.csv', mode='a', index=False, header=False)
            #Executed_Process.to_csv(temp_dir + '_Executed_Process_report.csv', mode='a', index=False, header=False)

        if (processexec==True or allreport==True):
            ExecutedProcess_Events_pd=pd.DataFrame(Executed_Process_Events[0])
            #print("Executed process events : " + str(Executed_Process_Events[0]))
            if processinitial.value==1:
                ExecutedProcess_Events_pd.to_csv(output+'_Process_Execution_Events.csv', index=False)
                processinitial.value=0
            else:
                ExecutedProcess_Events_pd.to_csv(output+'_Process_Execution_Events.csv', mode='a', index=False, header=False)
        if (logons==True or allreport==True):
            Logon_Events_pd=pd.DataFrame(Logon_Events[0])
            #print("logon events : "+str(Logon_Events))
            if logoninitial.value==1:
                #print(f"inside function , output is {output}")
                Logon_Events_pd.to_csv(output+'_Logon_Events.csv', index=False)
                logoninitial.value=0
            else:
                Logon_Events_pd.to_csv(output+'_Logon_Events.csv', mode='a', index=False, header=False)
        Process_Execution_dataframes=[]
        lock.acquire()
        if os.path.exists(temp_dir +"Executed_Process_Events.pickle"):
            with open(temp_dir + "Executed_Process_Events.pickle", 'rb') as handle:
                #lock.acquire()
                try:
                    Process_Execution_dataframes=pickle.load(handle)
                    handle.close()
                    #lock.release()
                    #print("Read:" + str(Security_Authentication_dataframes))
                except Exception as e:
                    print("Erorr : " + str(e))
                    #lock.release()
        else:
            with open(temp_dir + "Executed_Process_Events.pickle", 'wb') as handle:

                Process_Execution_dataframes.append(pd.DataFrame(Executed_Process_Summary[0]))
                #print("Write:" + str(Security_Authentication_dataframes))
                #lock.acquire()
                pickle.dump(Process_Execution_dataframes, handle, protocol=pickle.HIGHEST_PROTOCOL)
                handle.close()
                #lock.release()
        with open(temp_dir + "Executed_Process_Events.pickle", 'wb') as handle:

            Process_Execution_dataframes.append(pd.DataFrame(Executed_Process_Summary[0]))
            #print("Write:" + str(Security_Authentication_dataframes))
            #lock.acquire()
            pickle.dump(Process_Execution_dataframes, handle, protocol=pickle.HIGHEST_PROTOCOL)
            handle.close()
            #lock.release()
        lock.release()
        # print(Frequency_Analysis_Security)
        # pd.DataFrame(Frequency_Analysis_Security).to_csv(output+'frequency_Analysis.csv', mode='a')
        if (objectaccess==True or allreport==True):
            Object_Access_Events_pd=pd.DataFrame(Object_Access_Events[0])

            if objectinitial.value==1:
                Object_Access_Events_pd.to_csv(output+'_Object_Access_Events.csv', index=False)
                objectinitial.value=0
            else:
                Object_Access_Events_pd.to_csv(output+'_Object_Access_Events.csv', mode='a', index=False, header=False)

    toc = time.time()
    print('Security Logs Done in {:.4f} seconds'.format(toc - tic))



def detect_events_windows_defender_log(file_name, shared_data):
    tic = time.time()
    input_timezone = shared_data["input_timezone"]
    timestart = shared_data["timestart"]
    timeend = shared_data["timeend"]
    objectaccess = shared_data["objectaccess"]
    processexec = shared_data["processexec"]
    logons = shared_data["logons"]
    frequencyanalysis = shared_data["frequencyanalysis"]
    allreport = shared_data["allreport"]
    output = shared_data["output"]
    if 1==1:
        parser = PyEvtxParser(file_name)
        for record in parser.records():
            EventID = EventID_rex.findall(record['data'])
            Computer = Computer_rex.findall(record['data'])
            Channel = Channel_rex.findall(record['data'])
            #print(f'Event Record ID: {record["event_record_id"]}')
            #print(f'Event Timestamp: {record["timestamp"]}')
            if timestart is not None and timeend is not None :
                timestamp=datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat()))
                if not (timestamp>timestart and timestamp<timeend):
                    continue
            if len(EventID) > 0:

                # if frequencyanalysis==True and EventID[0] in Frequency_Analysis_Windows_Defender:
                #     Frequency_Analysis_Windows_Defender[EventID[0]]=Frequency_Analysis_Windows_Defender[EventID[0]]+1
                # else:
                #     Frequency_Analysis_Windows_Defender[EventID[0]]=1
                Name = Name_rex.findall(record['data'])
                Severity = Severity_rex.findall(record['data'])
                Category = Category_rex.findall(record['data'])
                Path = Path_rex.findall(record['data'])
                User = Defender_User_rex.findall(record['data'])
                Remediation_User=Defender_Remediation_User_rex.findall(record['data'])
                Process_Name = Process_Name_rex.findall(record['data'])
                Action = Action_rex.findall(record['data'])


                #Detect any log that contain suspicious process name or argument
                for i in all_suspicious:

                    if record['data'].lower().find(i.lower())>-1:

                        #print("##### " + record["timestamp"] + " ####  ", end='')
                        #print("## Found Suspicios Process ", end='')
                        #print("User Name : ( %s ) " % Account_Name[0][0].strip(), end='')
                        #print("with Command Line : ( " + Process_Command_Line[0][0].strip() + " )")
                        # print("###########")

                        Event_desc ="Found a log contain suspicious powershell command ( %s)"%i
                        lock.acquire()
                        Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Windows_Defender_events[0]['Computer Name'].append(Computer[0])
                        Windows_Defender_events[0]['Channel'].append(Channel[0])
                        Windows_Defender_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Windows_Defender_events[0]['Detection Rule'].append("Suspicious Command or process found in the log")
                        Windows_Defender_events[0]['Detection Domain'].append("Threat")
                        Windows_Defender_events[0]['Severity'].append("Critical")
                        Windows_Defender_events[0]['Event Description'].append(Event_desc)
                        Windows_Defender_events[0]['Event ID'].append(EventID[0])
                        Windows_Defender_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                        lock.release()
                        break
                #Windows Defender took action against Malware
                if EventID[0]=="1117" or EventID[0]=="1007" :
                    try :
                        if  len(Severity[0][0])>0:
                            severity=Severity[0][0].strip()
                            name=Name[0][0].strip()
                            action=Action[0][0].strip()
                            category=Category[0][0].strip()
                            path=Path[0][0].strip()
                            process_name=Process_Name[0][0].strip()
                            remediation_user=Remediation_User[0][0].strip()
                        if  len(Severity[0][1])>0:
                            severity=Severity[0][1].strip()
                            name=Name[0][1].strip()
                            action=Action[0][1].strip()
                            category=Category[0][1].strip()
                            path=Path[0][1].strip()
                            process_name=Process_Name[0][1].strip()
                            remediation_user=Remediation_User[0][1].strip()
                    #print("##### " + record["timestamp"] + " ####  ", end='')
                    #print(" Windows Defender took action against Malware - details : Severity ( %s ) , Name ( %s ) , Action ( %s ) , Catgeory ( %s ) , Path ( %s ) , Process Name ( %s ) , User ( %s ) "%(Severity[0].strip(),Name[0].strip(),Action[0].strip(),Category[0].strip(),Path[0].strip(),Process_Name[0][0].strip(),User[0]))
                        Event_desc="Windows Defender took action against Malware - details : Severity ( %s ) , Name ( %s ) , Action ( %s ) , Catgeory ( %s ) , Path ( %s ) , Process Name ( %s ) , User ( %s ) "%(severity,name,action,category,path,process_name,remediation_user)
                    except:
                        Event_desc="Windows Defender took action against Malware"
                    lock.acquire()
                    Windows_Defender_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Windows_Defender_events[0]['Computer Name'].append(Computer[0])
                    Windows_Defender_events[0]['Channel'].append(Channel[0])
                    Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Windows_Defender_events[0]['Detection Rule'].append("Windows Defender took action against Malware")
                    Windows_Defender_events[0]['Detection Domain'].append("Threat")
                    Windows_Defender_events[0]['Severity'].append("Critical")
                    Windows_Defender_events[0]['Event Description'].append(Event_desc)
                    Windows_Defender_events[0]['Event ID'].append(EventID[0])
                    Windows_Defender_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()
                #Windows Defender failed to take action against Malware
                if  EventID[0]=="1118" or EventID[0]=="1008" or EventID[0]=="1119":
                    #print("##### " + record["timestamp"] + " ####  ", end='')
                    #print("Windows Defender failed to take action against Malware - details : Severity ( %s ) , Name ( %s ) , Action ( %s ) , Catgeory ( %s ) , Path ( %s ) , Process Name ( %s ) , User ( %s ) "%(Severity[0].strip(),Name[0].strip(),Action[0].strip(),Category[0].strip(),Path[0].strip(),Process_Name[0][0].strip(),User[0]))

                    try :
                        if  len(Severity[0][0])>0:
                            severity=Severity[0][0].strip()
                            name=Name[0][0].strip()
                            action=Action[0][0].strip()
                            category=Category[0][0].strip()
                            path=Path[0][0].strip()
                            process_name=Process_Name[0][0].strip()
                            remediation_user=Remediation_User[0][0].strip()
                        if  len(Severity[0][1])>0:
                            severity=Severity[0][1].strip()
                            name=Name[0][1].strip()
                            action=Action[0][1].strip()
                            category=Category[0][1].strip()
                            path=Path[0][1].strip()
                            process_name=Process_Name[0][1].strip()
                            remediation_user=Remediation_User[0][1].strip()

                        Event_desc="Windows Defender failed to take action against Malware - details : Severity ( %s ) , Name ( %s ) , Action ( %s ) , Catgeory ( %s ) , Path ( %s ) , Process Name ( %s ) , User ( %s ) "%(severity,name,action,category,path,process_name,remediation_user)
                    except:
                        Event_desc="Windows Defender failed to take action against Malware"
                    lock.acquire()
                    Windows_Defender_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Windows_Defender_events[0]['Computer Name'].append(Computer[0])
                    Windows_Defender_events[0]['Channel'].append(Channel[0])
                    Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Windows_Defender_events[0]['Detection Rule'].append("Windows Defender failed to take action against Malware")
                    Windows_Defender_events[0]['Detection Domain'].append("Threat")
                    Windows_Defender_events[0]['Severity'].append("Critical")
                    Windows_Defender_events[0]['Event Description'].append(Event_desc)
                    Windows_Defender_events[0]['Event ID'].append(EventID[0])
                    Windows_Defender_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()
                #Windows Defender Found Malware
                if EventID[0] == "1116" or EventID[0]=="1006":
                    #print("##### " + record["timestamp"] + " ####  ", end='')
                    #print(" Windows Defender Found Malware - details : Severity ( %s ) , Name ( %s ) , Catgeory ( %s ) , Path ( %s ) , Process Name ( %s ) , User ( %s ) "%(Severity[0].strip(),Name[0].strip(),Category[0].strip(),Path[0].strip(),Process_Name[0][0].strip(),User[0]))
                    try :
                        if  len(Severity[0][0])>0:
                            severity=Severity[0][0].strip()
                            name=Name[0][0].strip()
                            category=Category[0][0].strip()
                            path=Path[0][0].strip()
                            process_name=Process_Name[0][0].strip()
                            remediation_user=Remediation_User[0][0].strip()
                        if  len(Severity[0][1])>0:
                            severity=Severity[0][1].strip()
                            name=Name[0][1].strip()
                            category=Category[0][1].strip()
                            path=Path[0][1].strip()
                            process_name=Process_Name[0][1].strip()
                            remediation_user=Remediation_User[0][1].strip()

                        Event_desc="Windows Defender Found Malware - details : Severity ( %s ) , Name ( %s ) , Catgeory ( %s ) , Path ( %s ) , Process Name ( %s ) , User ( %s ) "%(severity,name,category,path,process_name,remediation_user)
                    except:
                        Event_desc="Windows Defender Found Malware"
                    lock.acquire()
                    Windows_Defender_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Windows_Defender_events[0]['Computer Name'].append(Computer[0])
                    Windows_Defender_events[0]['Channel'].append(Channel[0])
                    Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Windows_Defender_events[0]['Detection Rule'].append("Windows Defender Found Malware")
                    Windows_Defender_events[0]['Detection Domain'].append("Threat")
                    Windows_Defender_events[0]['Severity'].append("Critical")
                    Windows_Defender_events[0]['Event Description'].append(Event_desc)
                    Windows_Defender_events[0]['Event ID'].append(EventID[0])
                    Windows_Defender_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()
                #Windows Defender deleted history of malwares
                if  EventID[0]=="1013":
                    #print("##### " + record["timestamp"] + " ####  ", end='')
                    #print(" Windows Defender deleted history of malwares - details : User ( %s ) "%(User[0]))
                    try:
                        if  len(User[0][0])>0:
                            user=User[0][0]
                        if  len(User[0][1])>0:
                            user=User[0][1]
                        Event_desc=" Windows Defender deleted history of malwares - details : User ( %s ) "%(user)
                    except:
                        Event_desc=" Windows Defender deleted history of malwares"
                    lock.acquire()
                    Windows_Defender_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Windows_Defender_events[0]['Computer Name'].append(Computer[0])
                    Windows_Defender_events[0]['Channel'].append(Channel[0])
                    Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Windows_Defender_events[0]['Detection Rule'].append("Windows Defender deleted history of malwares")
                    Windows_Defender_events[0]['Detection Domain'].append("Audit")
                    Windows_Defender_events[0]['Severity'].append("Medium")
                    Windows_Defender_events[0]['Event Description'].append(Event_desc)
                    Windows_Defender_events[0]['Event ID'].append(EventID[0])
                    Windows_Defender_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()
                #Windows Defender detected suspicious behavior Malware
                if  EventID[0] == "1015" :
                    #print("##### " + record["timestamp"] + " ####  ", end='')
                    #print(" Windows Defender detected suspicious behavious Malware - details : Severity ( %s ) , Name ( %s ) , Catgeory ( %s ) , Path ( %s ) , Process Name ( %s ) , User ( %s ) "%(Severity[0].strip(),Name[0].strip(),Category[0].strip(),Path[0].strip(),Process_Name[0][0].strip(),User[0]))
                    try :
                        if  len(Severity[0][0])>0:
                            severity=Severity[0][0].strip()
                            name=Name[0][0].strip()
                            category=Category[0][0].strip()
                            path=Path[0][0].strip()
                            process_name=Process_Name[0][0].strip()
                            remediation_user=Remediation_User[0][0].strip()
                        if  len(Severity[0][1])>0:
                            severity=Severity[0][1].strip()
                            name=Name[0][1].strip()
                            category=Category[0][1].strip()
                            path=Path[0][1].strip()
                            process_name=Process_Name[0][1].strip()
                            remediation_user=Remediation_User[0][1].strip()

                        Event_desc="Windows Defender detected suspicious behavior Malware - details : Severity ( %s ) , Name ( %s ) , Catgeory ( %s ) , Path ( %s ) , Process Name ( %s ) , User ( %s ) "%(severity,name,category,path,process_name,remediation_user)
                    except:
                        Event_desc="Windows Defender detected suspicious behavior Malware"
                    lock.acquire()
                    Windows_Defender_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Windows_Defender_events[0]['Computer Name'].append(Computer[0])
                    Windows_Defender_events[0]['Channel'].append(Channel[0])
                    Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Windows_Defender_events[0]['Detection Rule'].append("Windows Defender detected suspicious behavior Malware")
                    Windows_Defender_events[0]['Detection Domain'].append("Threat")
                    Windows_Defender_events[0]['Severity'].append("Critical")
                    Windows_Defender_events[0]['Event Description'].append(Event_desc)
                    Windows_Defender_events[0]['Event ID'].append(EventID[0])
                    Windows_Defender_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

                if  EventID[0] == "5001" :
                    #print("##### " + record["timestamp"] + " ####  ", end='')
                    #print("Windows Defender real-time protection disabled")
                    lock.acquire()
                    Event_desc="Windows Defender real-time protection disabled"
                    Windows_Defender_events[0]['Computer Name'].append(Computer[0])
                    Windows_Defender_events[0]['Channel'].append(Channel[0])
                    Windows_Defender_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Windows_Defender_events[0]['Detection Rule'].append("Windows Defender real-time protection disabled")
                    Windows_Defender_events[0]['Detection Domain'].append("Audit")
                    Windows_Defender_events[0]['Severity'].append("High")
                    Windows_Defender_events[0]['Event Description'].append(Event_desc)
                    Windows_Defender_events[0]['Event ID'].append(EventID[0])
                    Windows_Defender_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()
                if  EventID[0] == "5004" :
                    #print("##### " + record["timestamp"] + " ####  ", end='')
                    #print(" Windows Defender real-time protection configuration changed")
                    lock.acquire()
                    Event_desc="Windows Defender real-time protection configuration changed"
                    Windows_Defender_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Windows_Defender_events[0]['Computer Name'].append(Computer[0])
                    Windows_Defender_events[0]['Channel'].append(Channel[0])
                    Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Windows_Defender_events[0]['Detection Rule'].append("Windows Defender real-time protection configuration changed")
                    Windows_Defender_events[0]['Detection Domain'].append("Audit")
                    Windows_Defender_events[0]['Severity'].append("Medium")
                    Windows_Defender_events[0]['Event Description'].append(Event_desc)
                    Windows_Defender_events[0]['Event ID'].append(EventID[0])
                    Windows_Defender_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()
                if  EventID[0] == "5007" :
                    #print("##### " + record["timestamp"] + " ####  ", end='')
                    #print(" Windows Defender antimalware platform configuration changed")
                    lock.acquire()
                    Event_desc="Windows Defender antimalware platform configuration changed"
                    Windows_Defender_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Windows_Defender_events[0]['Computer Name'].append(Computer[0])
                    Windows_Defender_events[0]['Channel'].append(Channel[0])
                    Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Windows_Defender_events[0]['Detection Rule'].append("Windows Defender antimalware platform configuration changed")
                    Windows_Defender_events[0]['Detection Domain'].append("Audit")
                    Windows_Defender_events[0]['Severity'].append("Medium")
                    Windows_Defender_events[0]['Event Description'].append(Event_desc)
                    Windows_Defender_events[0]['Event ID'].append(EventID[0])
                    Windows_Defender_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()
                if  EventID[0] == "5010" :
                    #print("##### " + record["timestamp"] + " ####  ", end='')
                    #print(" Windows Defender scanning for malware is disabled")

                    Event_desc="Windows Defender scanning for malware is disabled"
                    Windows_Defender_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Windows_Defender_events[0]['Computer Name'].append(Computer[0])
                    Windows_Defender_events[0]['Channel'].append(Channel[0])
                    Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Windows_Defender_events[0]['Detection Rule'].append("Windows Defender scanning for malware is disabled")
                    Windows_Defender_events[0]['Detection Domain'].append("Audit")
                    Windows_Defender_events[0]['Severity'].append("Medium")
                    Windows_Defender_events[0]['Event Description'].append(Event_desc)
                    Windows_Defender_events[0]['Event ID'].append(EventID[0])
                    Windows_Defender_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                if  EventID[0] == "5012" :
                    #print("##### " + record["timestamp"] + " ####  ", end='')
                    #print(" Windows Defender scanning for viruses is disabled")
                    lock.acquire()
                    Event_desc="Windows Defender scanning for viruses is disabled"
                    Windows_Defender_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Windows_Defender_events[0]['Computer Name'].append(Computer[0])
                    Windows_Defender_events[0]['Channel'].append(Channel[0])
                    Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Windows_Defender_events[0]['Detection Rule'].append("Windows Defender scanning for viruses is disabled")
                    Windows_Defender_events[0]['Detection Domain'].append("Audit")
                    Windows_Defender_events[0]['Severity'].append("Medium")
                    Windows_Defender_events[0]['Event Description'].append(Event_desc)
                    Windows_Defender_events[0]['Event ID'].append(EventID[0])
                    Windows_Defender_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()
            else:
                print(record['data'])
        Windows_Defender = pd.DataFrame(Windows_Defender_events[0])
        if DefenderInitial.value == 1:
            Windows_Defender.to_csv(temp_dir + '_Defender_report.csv', index=False)
            DefenderInitial.value = 0
        else:
            Windows_Defender.to_csv(temp_dir + '_Defender_report.csv', mode='a', index=False, header=False)

    toc = time.time()
    print('Windows Defender Logs Done in {:.4f} seconds'.format(toc - tic))

def detect_events_group_policy_log(file_name, shared_data):
    tic = time.time()
    input_timezone = shared_data["input_timezone"]
    timestart = shared_data["timestart"]
    timeend = shared_data["timeend"]
    objectaccess = shared_data["objectaccess"]
    processexec = shared_data["processexec"]
    logons = shared_data["logons"]
    frequencyanalysis = shared_data["frequencyanalysis"]
    allreport = shared_data["allreport"]
    output = shared_data["output"]
    parser = PyEvtxParser(file_name)
    for record in parser.records():
        EventID = EventID_rex.findall(record['data'])
        Computer = Computer_rex.findall(record['data'])
        Channel = Channel_rex.findall(record['data'])
        if timestart is not None and timeend is not None :
            timestamp=datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat()))
            if not (timestamp>timestart and timestamp<timeend):
                continue
        if len(EventID) > 0:
            Extension_ID=Extension_ID_rex.findall(record['data'])
            Extension_Name=Extension_Name_rex.findall(record['data'])
            Polcies_Name=Polcies_Name_rex.findall(record['data'])
            GPO_List=GPO_List_rex.findall(record['data'])

            # if frequencyanalysis==True and EventID[0] in Frequency_Analysis_Group_Policy:
            #     Frequency_Analysis_Group_Policy[EventID[0]]=Frequency_Analysis_Group_Policy[EventID[0]]+1
            # else:
            #     Frequency_Analysis_Group_Policy[EventID[0]]=1

            if  EventID[0] == "4016" :
                 try:
                #if 1==1:

                    if len(Polcies_Name)>0:
                        policies=",".join(Polcies_Name[0])
                    else:
                        policies="Not Parsed"
                    if len(GPO_List[0])>0:
                        gpolist=GPO_List[0]
                    else:
                        gpolist="Not Parsed"
                    if len(Extension_Name[0])>0:
                        ExtensionName=Extension_Name[0]
                    else:
                        ExtensionName="Not Parsed"

                    if Extension_Name[0].find("Scheduled Tasks")>-1:
                        Event_desc="Group policy (%s) processed with Scheduled Tasks , list of GPO (%s)"%(policies,gpolist)
                        lock.acquire()
                        Group_Policy_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Group_Policy_events[0]['Computer Name'].append(Computer[0])
                        Group_Policy_events[0]['Channel'].append(Channel[0])
                        Group_Policy_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Group_Policy_events[0]['Detection Rule'].append("Group policy processing with Scheduled Tasks")
                        Group_Policy_events[0]['Detection Domain'].append("Audit")
                        Group_Policy_events[0]['Severity'].append("High")
                        Group_Policy_events[0]['Group Policy Name'].append(policies)
                        Group_Policy_events[0]['Policy Extension Name'].append(ExtensionName)
                        Group_Policy_events[0]['Event Description'].append(Event_desc)
                        Group_Policy_events[0]['Event ID'].append(EventID[0])
                        Group_Policy_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                        lock.release()
                 except:
                     print("issue parsing event : ",str(record['data']).replace("\r"," "))

            if  EventID[0] == "4016" :
                try:
                #if 1==1:
                    lock.acquire()
                    try:
                        if len(Polcies_Name)>0:
                            policies=",".join(Polcies_Name[0])
                        else:
                            policies="Not Parsed"
                        Event_desc="Group policy (%s) processed with Extension Type (%s) , list of GPO (%s)"%(policies,Extension_Name[0],GPO_List[0])
                        Group_Policy_events[0]['Group Policy Name'].append(policies)
                        Group_Policy_events[0]['Policy Extension Name'].append(Extension_Name[0])
                    except:
                        Event_desc="Group policy processed"
                        Group_Policy_events[0]['Group Policy Name'].append("Not Parsed")
                        Group_Policy_events[0]['Policy Extension Name'].append("Not Parsed")

                    Group_Policy_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Group_Policy_events[0]['Computer Name'].append(Computer[0])
                    Group_Policy_events[0]['Channel'].append(Channel[0])
                    Group_Policy_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Group_Policy_events[0]['Detection Rule'].append("Group policy processing")
                    Group_Policy_events[0]['Detection Domain'].append("Audit")
                    Group_Policy_events[0]['Severity'].append("Medium")
                    Group_Policy_events[0]['Event Description'].append(Event_desc)
                    Group_Policy_events[0]['Event ID'].append(EventID[0])
                    Group_Policy_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()
                except:
                    print("issue parsing event : ",str(record['data']).replace("\r"," "))
    Group_Policy = pd.DataFrame(Group_Policy_events[0])
    if Group_PolicyInitial.value == 1:
        Group_Policy.to_csv(temp_dir + '_Group_Policy_report.csv', index=False)
        Group_PolicyInitial.value = 0
    else:
        Group_Policy.to_csv(temp_dir + '_Group_Policy_report.csv', mode='a', index=False, header=False)
    toc = time.time()
    print('Group Policy Logs Done in {:.4f} seconds'.format(toc - tic))

def detect_events_SMB_Server_log(file_name, shared_data):
    tic = time.time()
    input_timezone = shared_data["input_timezone"]
    timestart = shared_data["timestart"]
    timeend = shared_data["timeend"]
    objectaccess = shared_data["objectaccess"]
    processexec = shared_data["processexec"]
    logons = shared_data["logons"]
    frequencyanalysis = shared_data["frequencyanalysis"]
    allreport = shared_data["allreport"]
    output = shared_data["output"]
    #print(file_name)

    parser = PyEvtxParser(file_name)
    for record in parser.records():
        EventID = EventID_rex.findall(record['data'])
        Computer = Computer_rex.findall(record['data'])
        Channel = Channel_rex.findall(record['data'])
        if timestart is not None and timeend is not None :
            timestamp=datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat()))
            if not (timestamp>timestart and timestamp<timeend):
                continue
        if len(EventID) > 0:
            ClientName=SMB_Server_ClientName_rex.findall(record['data'])
            Username=SMB_Server_Username_rex.findall(record['data'])
            ShareName=SMB_Server_ShareName_rex.findall(record['data'])
            FileName=SMB_Server_FileName_rex.findall(record['data'])



            # if frequencyanalysis==True and EventID[0] in Frequency_Analysis_SMB_Server:
            #     Frequency_Analysis_SMB_Server[EventID[0]]=Frequency_Analysis_SMB_Server[EventID[0]]+1
            # else:
            #     Frequency_Analysis_SMB_Server[EventID[0]]=1
            if  EventID[0] == "1020" :
                try:
                #if 1==1:

                    Event_desc="User (%s) with Device (%s) connected to share (%s) and accessed file (%s)"%(Username[0],ClientName[0],ShareName[0],FileName[0])
                    lock.acquire()
                    SMB_Server_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    SMB_Server_events[0]['Computer Name'].append(Computer[0])
                    SMB_Server_events[0]['Client Address'].append(ClientName[0])
                    SMB_Server_events[0]['UserName'].append(Username[0])
                    SMB_Server_events[0]['Share Name'].append(ShareName[0])
                    SMB_Server_events[0]['File Name'].append(FileName[0])
                    SMB_Server_events[0]['Channel'].append(Channel[0])
                    SMB_Server_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    SMB_Server_events[0]['Detection Rule'].append("Device to connected to share through SMB")
                    SMB_Server_events[0]['Detection Domain'].append("Audit")
                    SMB_Server_events[0]['Severity'].append("Medium")
                    SMB_Server_events[0]['Event Description'].append(Event_desc)
                    SMB_Server_events[0]['Event ID'].append(EventID[0])
                    SMB_Server_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()
                except:
                    print("issue parsing event : ",str(record['data']).replace("\r"," "))
    SMB_Server = pd.DataFrame(SMB_Server_events[0])
    if SMB_ServerInitial.value == 1:
        SMB_Server.to_csv(temp_dir + '_SMB_Server_report.csv', index=False)
        SMB_ServerInitial.value = 0
    else:
        SMB_Server.to_csv(temp_dir + '_SMB_Server_report.csv', mode='a', index=False, header=False)
    toc = time.time()
    print('SMB Server Logs Done in {:.4f} seconds'.format(toc - tic))

def detect_events_SMB_Client_log(file_name, shared_data):
    tic = time.time()
    input_timezone = shared_data["input_timezone"]
    timestart = shared_data["timestart"]
    timeend = shared_data["timeend"]
    objectaccess = shared_data["objectaccess"]
    processexec = shared_data["processexec"]
    logons = shared_data["logons"]
    frequencyanalysis = shared_data["frequencyanalysis"]
    allreport = shared_data["allreport"]
    output = shared_data["output"]
    #print(file_name)

    parser = PyEvtxParser(file_name)
    for record in parser.records():
        EventID = EventID_rex.findall(record['data'])
        Computer = Computer_rex.findall(record['data'])
        Channel = Channel_rex.findall(record['data'])
        timestamp=datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat()))
        if timestart is not None and timeend is not None :
            if not (timestamp>timestart and timestamp<timeend):
                continue
        if len(EventID) > 0:

            if frequencyanalysis==True and EventID[0] in Frequency_Analysis_SMB_Client:
                Frequency_Analysis_SMB_Client[EventID[0]]=Frequency_Analysis_SMB_Client[EventID[0]]+1
            else:
                Frequency_Analysis_SMB_Client[EventID[0]]=1
            ShareName=SMB_Client_ShareName_rex.findall(record['data'])
            FileName=SMB_Client_ObjectName_rex.findall(record['data'])
            if  EventID[0] == "31010" :
                try:
                #if 1==1:
                    lock.acquire()
                    Event_desc="This device tried to connect to share (%s) and accessed object (%s)"%(ShareName[0],FileName[0])
                    SMB_Client_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    SMB_Client_events[0]['Computer Name'].append(Computer[0])
                    SMB_Client_events[0]['Share Name'].append(ShareName[0])
                    SMB_Client_events[0]['File Name'].append(FileName[0])
                    SMB_Client_events[0]['Channel'].append(Channel[0])
                    SMB_Client_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    SMB_Client_events[0]['Detection Rule'].append("This device had issue trying to connect to share")
                    SMB_Client_events[0]['Detection Domain'].append("Audit")
                    SMB_Client_events[0]['Severity'].append("Medium")
                    SMB_Client_events[0]['Event Description'].append(Event_desc)
                    SMB_Client_events[0]['Event ID'].append(EventID[0])
                    SMB_Client_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()
                except Exception as e:
                    print("issue parsing event : %s \nwith error(%s)"%(str(record['data']).replace("\r"," "),str(e)))
    SMB_Client = pd.DataFrame(SMB_Client_events[0])
    if SMB_ClientInitial.value == 1:
        SMB_Client.to_csv(temp_dir + '_SMB_Client_report.csv', index=False)
        SMB_ClientInitial.value = 0
    else:
        SMB_Client.to_csv(temp_dir + '_SMB_Client_report.csv', mode='a', index=False, header=False)
    toc = time.time()
    print('SMB Client Logs Done in {:.4f} seconds'.format(toc - tic))

def detect_events_scheduled_task_log(file_name, shared_data):

    tic = time.time()
    input_timezone = shared_data["input_timezone"]
    timestart = shared_data["timestart"]
    timeend = shared_data["timeend"]
    objectaccess = shared_data["objectaccess"]
    processexec = shared_data["processexec"]
    logons = shared_data["logons"]
    frequencyanalysis = shared_data["frequencyanalysis"]
    allreport = shared_data["allreport"]
    output = shared_data["output"]
    parser = PyEvtxParser(file_name)
    for record in parser.records():
        EventID = EventID_rex.findall(record['data'])
        Computer = Computer_rex.findall(record['data'])
        Channel = Channel_rex.findall(record['data'])

        if timestart is not None and timeend is not None :
            timestamp=datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat()))
            if not (timestamp>timestart and timestamp<timeend):
                continue

        if len(EventID) > 0:
            task_name=Task_Name_rex.findall(record['data'])
            Register_User = Task_Registered_User_rex.findall(record['data'])
            Delete_User = Task_Deleted_User_rex.findall(record['data'])

            # if frequencyanalysis==True and EventID[0] in Frequency_Analysis_ScheduledTask:
            #     Frequency_Analysis_ScheduledTask[EventID[0]]=Frequency_Analysis_ScheduledTask[EventID[0]]+1
            # else:
            #     Frequency_Analysis_ScheduledTask[EventID[0]]=1
            #Detect any log that contain suspicious process name or argument
            for i in all_suspicious:

                if record['data'].lower().find(i.lower())>-1:

                    #print("##### " + record["timestamp"] + " ####  ", end='')
                    #print("## Found Suspicios Process ", end='')
                    #print("User Name : ( %s ) " % Account_Name[0][0].strip(), end='')
                    #print("with Command Line : ( " + Process_Command_Line[0][0].strip() + " )")
                    # print("###########")
                    lock.acquire()
                    Event_desc ="Found a log contain suspicious powershell command ( %s)"%i
                    ScheduledTask_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    ScheduledTask_events[0]['Computer Name'].append(Computer[0])
                    ScheduledTask_events[0]['Channel'].append(Channel[0])
                    ScheduledTask_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    ScheduledTask_events[0]['Detection Rule'].append("Suspicious Command or process found in the log")
                    ScheduledTask_events[0]['Detection Domain'].append("Threat")
                    ScheduledTask_events[0]['Severity'].append("Critical")
                    ScheduledTask_events[0]['Schedule Task Name'].append("None")
                    ScheduledTask_events[0]['Event Description'].append(Event_desc)
                    ScheduledTask_events[0]['Event ID'].append(EventID[0])
                    ScheduledTask_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                    lock.release()
                    break
            #schedule task registered
            if EventID[0]=="106" :

                try:
                    if len(Task_Name[0][0])>0:
                        task_name=Task_Name[0][0]
                        register_user=Register_User[0][0]
                    if len(Task_Name[0][1])>0:
                        task_name=Task_Name[0][1]
                        register_user=Register_User[0][1]
                    Event_desc ="schedule task registered with Name ( %s ) by user ( %s ) " % (task_name, register_user)
                except:
                    Event_desc ="schedule task registered"
                lock.acquire()
                ScheduledTask_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                ScheduledTask_events[0]['Computer Name'].append(Computer[0])
                ScheduledTask_events[0]['Channel'].append(Channel[0])
                ScheduledTask_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                ScheduledTask_events[0]['Detection Rule'].append("schedule task registered")
                ScheduledTask_events[0]['Detection Domain'].append("Audit")
                ScheduledTask_events[0]['Severity'].append("High")
                ScheduledTask_events[0]['Event Description'].append(Event_desc)
                ScheduledTask_events[0]['Schedule Task Name'].append(task_name[0][0])
                ScheduledTask_events[0]['Event ID'].append(EventID[0])
                ScheduledTask_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()
            #schedule task updated
            if EventID[0]=="140" :

                try:
                    if len(Task_Name[0][0])>0:
                        task_name=Task_Name[0][0]
                        delete_user=Delete_User[0][0]
                    if len(Task_Name[0][1])>0:
                        task_name=Task_Name[0][1]
                        delete_user=Delete_User[0][1]
                    Event_desc ="schedule task updated with Name ( %s ) by user ( %s ) " % (task_name, delete_user)
                except:
                    Event_desc ="schedule task updated"
                lock.acquire()
                ScheduledTask_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                ScheduledTask_events[0]['Computer Name'].append(Computer[0])
                ScheduledTask_events[0]['Channel'].append(Channel[0])
                ScheduledTask_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                ScheduledTask_events[0]['Detection Rule'].append("schedule task updated")
                ScheduledTask_events[0]['Detection Domain'].append("Audit")
                ScheduledTask_events[0]['Severity'].append("Medium")
                ScheduledTask_events[0]['Event Description'].append(Event_desc)
                ScheduledTask_events[0]['Event ID'].append(EventID[0])
                ScheduledTask_events[0]['Schedule Task Name'].append(task_name[0][0])
                ScheduledTask_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()
            # schedule task deleted
            if EventID[0]=="141" :
                try:
                    if len(Task_Name[0][0])>0:
                        task_name=Task_Name[0][0]
                        delete_user=Delete_User[0][0]
                    if len(Task_Name[0][1])>0:
                        task_name=Task_Name[0][1]
                        delete_user=Delete_User[0][1]
                    Event_desc ="schedule task deleted with Name ( %s ) by user ( %s ) " % (task_name, delete_user)
                except:
                    Event_desc ="schedule task deleted"
                lock.acquire()
                ScheduledTask_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                ScheduledTask_events[0]['Computer Name'].append(Computer[0])
                ScheduledTask_events[0]['Channel'].append(Channel[0])
                ScheduledTask_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                ScheduledTask_events[0]['Detection Rule'].append("schedule task deleted")
                ScheduledTask_events[0]['Detection Domain'].append("Audit")
                ScheduledTask_events[0]['Severity'].append("High")
                ScheduledTask_events[0]['Event Description'].append(Event_desc)
                ScheduledTask_events[0]['Schedule Task Name'].append(task_name[0][0])
                ScheduledTask_events[0]['Event ID'].append(EventID[0])
                ScheduledTask_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()
        else:
            print(record['data'])
    ScheduledTask = pd.DataFrame(ScheduledTask_events[0])
    if ScheduledTaskInitial.value == 1:
        ScheduledTask.to_csv(temp_dir + '_ScheduledTask_report.csv', index=False)
        ScheduledTaskInitial.value = 0
    else:
        ScheduledTask.to_csv(temp_dir + '_ScheduledTask_report.csv', mode='a', index=False, header=False)
    toc = time.time()
    print('ScheduledTask Logs Done in {:.4f} seconds'.format(toc - tic))

def detect_events_system_log(file_name, shared_data):
    tic = time.time()
    input_timezone = shared_data["input_timezone"]
    timestart = shared_data["timestart"]
    timeend = shared_data["timeend"]
    objectaccess = shared_data["objectaccess"]
    processexec = shared_data["processexec"]
    logons = shared_data["logons"]
    frequencyanalysis = shared_data["frequencyanalysis"]
    allreport = shared_data["allreport"]
    output = shared_data["output"]
    parser = PyEvtxParser(file_name)
    for record in parser.records():
        EventID = EventID_rex.findall(record['data'])
        Computer = Computer_rex.findall(record['data'])
        Channel = Channel_rex.findall(record['data'])

        if timestart is not None and timeend is not None :
            timestamp=datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat()))
            if not (timestamp>timestart and timestamp<timeend):
                continue

        if len(EventID) > 0:
            task_name=Task_Name_rex.findall(record['data'])
            Register_User = Task_Registered_User_rex.findall(record['data'])
            Delete_User = Task_Deleted_User_rex.findall(record['data'])
            Service_Account = Service_Account_rex.findall(record['data'])
            Service_File_Name = Service_File_Name_rex.findall(record['data'])
            Service_Type = Service_Type_rex.findall(record['data'])
            Service_Name = Service_Name_rex.findall(record['data'])
            Service_State_Old= State_Service_Old_rex.findall(record['data'])
            Service_State_New= State_Service_New_rex.findall(record['data'])
            Service_State_Name = State_Service_Name_rex.findall(record['data'])
            Service_Start_Type=Service_Start_Type_rex.findall(record['data'])

            # if frequencyanalysis==True and EventID[0] in Frequency_Analysis_System:
            #     Frequency_Analysis_System[EventID[0]]=Frequency_Analysis_System[EventID[0]]+1
            # else:
            #     Frequency_Analysis_System[EventID[0]]=1
            # System Logs cleared
            if (EventID[0]=="104") :
                Event_desc="System Logs Cleared"
                #System_events[0]['Date and Time'].append(datetime.strptime(record["timestamp"],'%Y-%m-%d %I:%M:%S.%f %Z').isoformat())
                lock.acquire()
                System_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                System_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                System_events[0]['Computer Name'].append(Computer[0])
                System_events[0]['Channel'].append(Channel[0])
                System_events[0]['Detection Rule'].append(
                    "System Logs Cleared")
                System_events[0]['Detection Domain'].append("Audit")
                System_events[0]['Severity'].append("High")
                System_events[0]['Event Description'].append(Event_desc)
                System_events[0]['Service Name'].append("None")
                System_events[0]['Event ID'].append(EventID[0])
                System_events[0]['Image Path'].append("None")
                System_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                lock.release()
            if (EventID[0]=="7045" or EventID[0]=="601") and (record['data'].strip().find("\\temp\\") > -1 or record['data'].strip().find(
                    "\\tmp\\") > -1):
                Event_desc="Service Installed with executable in TEMP Folder"
                #System_events[0]['Date and Time'].append(datetime.strptime(record["timestamp"],'%Y-%m-%d %I:%M:%S.%f %Z').isoformat())
                lock.acquire()
                System_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                System_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                System_events[0]['Computer Name'].append(Computer[0])
                System_events[0]['Channel'].append(Channel[0])
                System_events[0]['Detection Rule'].append(
                    "Service Installed with executable in TEMP Folder ")
                System_events[0]['Detection Domain'].append("Threat")
                System_events[0]['Severity'].append("Critical")
                System_events[0]['Event Description'].append(Event_desc)
                System_events[0]['Service Name'].append(Service_File_Name[0][0].strip())
                System_events[0]['Event ID'].append(EventID[0])
                System_events[0]['Image Path'].append("None")
                System_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                lock.release()
            #Service installed in the system
            #print(EventID[0])
            if EventID[0].strip()=="7045" or EventID[0].strip()=="601" :
                #print("##### " + record["timestamp"] + " ####  ", end='')
                #print("Service installed in the system with Name ( %s ) , File Name ( %s ) , Service Type ( %s ) , Service Start Type ( %s ) , Service Account ( %s )"%(Service_Name[0].strip(),Service_File_Name[0].strip(),Service_Type[0].strip(),Service_Start_Type[0].strip(),Service_Account[0]))
                try:
                    if len(Service_Name[0][0])>0:
                        service_name=Service_Name[0][0].strip()
                        service_file_name=Service_File_Name[0][0].strip()
                        service_type=Service_Type[0][0].strip()
                        service_start_type=Service_Start_Type[0][0].strip()
                        service_account=Service_Account[0][0].strip()
                    if len(Service_Name[0][1])>0:
                        service_name=Service_Name[0][1].strip()
                        service_file_name=Service_File_Name[0][1].strip()
                        service_type=Service_Type[0][1].strip()
                        service_start_type=Service_Start_Type[0][1].strip()
                        service_account=Service_Account[0][1].strip()
                    if service_name.lower() in whitelisted    or  service_file_name in whitelisted   :
                        Severity="Low"
                    else:
                        Severity = "High"
                    Event_desc="Service installed in the system with Name ( %s ) , File Name ( %s ) , Service Type ( %s ) , Service Start Type ( %s ) , Service Account ( %s )"%(service_name,service_file_name,service_type,service_start_type,service_account)
                except:
                    Event_desc="Service installed in the system "
                    print("issue parsing event : ",str(record['data']).replace("\r"," "))
                #System_events[0]['Date and Time'].append(datetime.strptime(record["timestamp"],'%Y-%m-%d %I:%M:%S.%f %Z').isoformat())
                lock.acquire()
                System_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                System_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                System_events[0]['Computer Name'].append(Computer[0])
                System_events[0]['Channel'].append(Channel[0])
                System_events[0]['Detection Rule'].append("Service installed in the system")
                System_events[0]['Detection Domain'].append("Audit")
                System_events[0]['Severity'].append(Severity)
                System_events[0]['Service Name'].append(service_name)
                System_events[0]['Image Path'].append(service_file_name)
                System_events[0]['Event Description'].append(Event_desc)
                System_events[0]['Event ID'].append(EventID[0])
                System_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            #detect psexec service
            if EventID[0].strip()=="7045" or EventID[0].strip()=="601" :
                #print("##### " + record["timestamp"] + " ####  ", end='')
                #print("Service installed in the system with Name ( %s ) , File Name ( %s ) , Service Type ( %s ) , Service Start Type ( %s ) , Service Account ( %s )"%(Service_Name[0].strip(),Service_File_Name[0].strip(),Service_Type[0].strip(),Service_Start_Type[0].strip(),Service_Account[0]))
                try:
                    if len(Service_Name[0][0])>0:
                        service_name=Service_Name[0][0].strip()
                        service_file_name=Service_File_Name[0][0].strip()
                        service_type=Service_Type[0][0].strip()
                        service_start_type=Service_Start_Type[0][0].strip()
                        service_account=Service_Account[0][0].strip()
                    if len(Service_Name[0][1])>0:
                        service_name=Service_Name[0][1].strip()
                        service_file_name=Service_File_Name[0][1].strip()
                        service_type=Service_Type[0][1].strip()
                        service_start_type=Service_Start_Type[0][1].strip()
                        service_account=Service_Account[0][1].strip()
                    if service_name.lower().find("psexec")>-1 or service_name.lower().find("psexesvc")>-1 or str(record['data']).lower().find("psexec")>-1 or str(record['data']).lower().find("psexesvc")>-1:
                        Event_desc="psexec service detected installed in the system"
                        lock.acquire()
                        System_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        System_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        System_events[0]['Computer Name'].append(Computer[0])
                        System_events[0]['Channel'].append(Channel[0])
                        System_events[0]['Detection Rule'].append("psexec service detected installed in the system")
                        System_events[0]['Detection Domain'].append("Threat")
                        System_events[0]['Severity'].append("Critical")
                        System_events[0]['Service Name'].append(service_name)
                        System_events[0]['Image Path'].append(service_file_name)
                        System_events[0]['Event Description'].append(Event_desc)
                        System_events[0]['Event ID'].append(EventID[0])
                        System_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                        lock.release()
                        return
                except:
                    continue
                    print("issue parsing event : ",str(record['data']).replace("\r"," "))
                #System_events[0]['Date and Time'].append(datetime.strptime(record["timestamp"],'%Y-%m-%d %I:%M:%S.%f %Z').isoformat())

            #detect cobalt strike service
            if EventID[0].strip()=="7045" or EventID[0].strip()=="601" :
                #print("##### " + record["timestamp"] + " ####  ", end='')
                #print("Service installed in the system with Name ( %s ) , File Name ( %s ) , Service Type ( %s ) , Service Start Type ( %s ) , Service Account ( %s )"%(Service_Name[0].strip(),Service_File_Name[0].strip(),Service_Type[0].strip(),Service_Start_Type[0].strip(),Service_Account[0]))
                try:
                    if len(Service_Name[0][0])>0:
                        service_name=Service_Name[0][0].strip()
                        service_file_name=Service_File_Name[0][0].strip()
                        service_type=Service_Type[0][0].strip()
                        service_start_type=Service_Start_Type[0][0].strip()
                        service_account=Service_Account[0][0].strip()
                    if len(Service_Name[0][1])>0:
                        service_name=Service_Name[0][1].strip()
                        service_file_name=Service_File_Name[0][1].strip()
                        service_type=Service_Type[0][1].strip()
                        service_start_type=Service_Start_Type[0][1].strip()
                        service_account=Service_Account[0][1].strip()
                    if  service_name.lower().find("meterpreter") > -1 or (
                            str(record['data']).lower().find("admin$") > -1 or str(record['data']).lower().find(
                        "%comspec%") > -1 or str(record['data']).lower().find("powershell.exe") > -1 or str(
                        record['data']).lower().find("\\pipe\\\\") > -1):
                        Event_desc="cobalt strike or meterpreter service detected installed in the system"
                        lock.acquire()
                        System_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        System_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        System_events[0]['Computer Name'].append(Computer[0])
                        System_events[0]['Channel'].append(Channel[0])
                        System_events[0]['Detection Rule'].append("cobalt strike service detected installed in the system")
                        System_events[0]['Detection Domain'].append("Threat")
                        System_events[0]['Severity'].append("Critical")
                        System_events[0]['Service Name'].append(service_name)
                        System_events[0]['Image Path'].append(service_file_name)
                        System_events[0]['Event Description'].append(Event_desc)
                        System_events[0]['Event ID'].append(EventID[0])
                        System_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                        lock.release()
                        return
                except:
                    continue
                    print("issue parsing event : ",str(record['data']).replace("\r"," "))
                #System_events[0]['Date and Time'].append(datetime.strptime(record["timestamp"],'%Y-%m-%d %I:%M:%S.%f %Z').isoformat())

            #Zerologon Exploitation Using Well-known Tools
            if EventID[0]=="5805" or EventID[0]=="5723" :
                #print("##### " + record["timestamp"] + " ####  ", end='')
                #print("Service with Name ( %s ) entered ( %s ) state "%(Service_and_state.group(1),Service_and_state.group(2)))
                for i in all_suspicious:
                    if record['data'].lower().find(i.lower())>-1:
                        Event_desc="Zerologon Exploitation Using Well-known Tools "
                        lock.acquire()
                        System_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        System_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        System_events[0]['Computer Name'].append(Computer[0])
                        System_events[0]['Channel'].append(Channel[0])
                        System_events[0]['Service Name'].append("None")
                        System_events[0]['Detection Rule'].append("Zerologon Exploitation Using Well-known Tools ")
                        System_events[0]['Detection Domain'].append("Threat")
                        System_events[0]['Severity'].append("High")
                        System_events[0]['Event Description'].append(Event_desc)
                        System_events[0]['Event ID'].append(EventID[0])
                        System_events[0]['Image Path'].append("None")
                        System_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                        lock.release()
                        break
                return
            #detect service with malicious executable or argument
            if EventID[0].strip()=="7045" or EventID[0].strip()=="601" :
                #print("##### " + record["timestamp"] + " ####  ", end='')
                #print("Service installed in the system with Name ( %s ) , File Name ( %s ) , Service Type ( %s ) , Service Start Type ( %s ) , Service Account ( %s )"%(Service_Name[0].strip(),Service_File_Name[0].strip(),Service_Type[0].strip(),Service_Start_Type[0].strip(),Service_Account[0]))
                try:
                    if len(Service_Name[0][0])>0:
                        service_name=Service_Name[0][0].strip()
                        service_file_name=Service_File_Name[0][0].strip()
                        service_type=Service_Type[0][0].strip()
                        service_start_type=Service_Start_Type[0][0].strip()
                        service_account=Service_Account[0][0].strip()
                    if len(Service_Name[0][1])>0:
                        service_name=Service_Name[0][1].strip()
                        service_file_name=Service_File_Name[0][1].strip()
                        service_type=Service_Type[0][1].strip()
                        service_start_type=Service_Start_Type[0][1].strip()
                        service_account=Service_Account[0][1].strip()
                    malicious=[]
                    for i in all_suspicious:

                        if record['data'].lower().find(i.lower())>-1:
                            malicious.append(i)
                            break
                    if len(malicious)>0 or str(record['data']).lower().find("powershell.exe")>-1 :
                        System_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        System_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        System_events[0]['Computer Name'].append(Computer[0])
                        System_events[0]['Channel'].append(Channel[0])
                        System_events[0]['Detection Rule'].append("suspicious service detected installed in the system")
                        System_events[0]['Detection Domain'].append("Threat")
                        System_events[0]['Severity'].append("Critical")
                        System_events[0]['Service Name'].append(service_name)
                        System_events[0]['Image Path'].append(service_file_name)
                        System_events[0]['Event Description'].append(Event_desc)
                        System_events[0]['Event ID'].append(EventID[0])
                        System_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))


                except:
                    continue
                    print("issue parsing event : ",str(record['data']).replace("\r"," "))
                #System_events[0]['Date and Time'].append(datetime.strptime(record["timestamp"],'%Y-%m-%d %I:%M:%S.%f %Z').isoformat())

            # Service start type changed
            if EventID[0]=="7040" :
                #print("##### " + record["timestamp"] + " ####  ", end='')
                #print("Service with Name ( %s ) entered ( %s ) state "%(Service_and_state.group(1),Service_and_state.group(2)))
                ServiceName=''
                try:
                    if len(Service_State_Name[0][0])>0:
                        service_state_old=Service_State_Old[0][0].strip()
                        service_state_new=Service_State_New[0][0].strip()
                        service_state_name=Service_State_Name[0][0].strip()
                    if len(Service_State_Name[0][1])>0:
                        service_state_old=Service_State_Old[0][1].strip()
                        service_state_new=Service_State_New[0][1].strip()
                        service_state_name=Service_State_Name[0][1].strip()

                    if service_state_name in critical_services :
                        try:
                            Event_desc="Service with Name ( %s ) start type was ( %s ) chnaged to ( %s )  "%(service_state_name,service_state_old,service_state_new)
                            #System_events[0]['Service Name'].append(service_state_name)
                            ServiceName=service_state_name
                        except:
                            Event_desc="Service start type changed"
                            ServiceName="NONE"
                    else:
                        continue
                except:
                        continue
                        #Event_desc="Service start type changed"
                        #System_events[0]['Service Name'].append("NONE")
                        #ServiceName="NONE"
                        #print("issue parsing event : ",str(record['data']).replace("\r"," "))

                System_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                System_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                System_events[0]['Computer Name'].append(Computer[0])
                System_events[0]['Channel'].append(Channel[0])
                System_events[0]['Service Name'].append(ServiceName)
                System_events[0]['Detection Rule'].append("Service start type changed")
                System_events[0]['Detection Domain'].append("Audit")
                System_events[0]['Severity'].append("Medium")
                System_events[0]['Event Description'].append(Event_desc)
                System_events[0]['Event ID'].append(EventID[0])
                System_events[0]['Image Path'].append("None")
                System_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))


            #service state changed
            """if EventID[0]=="7036" :
                #print("##### " + record["timestamp"] + " ####  ", end='')
                #print("Service with Name ( %s ) entered ( %s ) state "%(Service_and_state.group(1),Service_and_state.group(2)))
                ServiceName=''
                try:
                    if len(Service_State_Name[0][0])>0:
                        service_state=Service_State_Old[0][0].strip()
                        service_state_name=Service_State_Name[0][0].strip()
                    if len(Service_State_Name[0][1])>0:
                        service_state=Service_State_Old[0][1].strip()
                        service_state_name=Service_State_Name[0][1].strip()

                    if service_state_name in critical_services :
                        try:
                            Event_desc="Service with Name ( %s ) entered ( %s ) state "%(service_state_name,service_state)
                            #System_events[0]['Date and Time'].append(datetime.strptime(record["timestamp"],'%Y-%m-%d %I:%M:%S.%f %Z').isoformat())
                            ServiceName=service_state_name
                        except:
                            Event_desc="Service Changed State"
                            ServiceName="None"
                    else:
                        #System_events[0]['Service Name'].append(service_state_name)
                        #ServiceName=service_state_name
                        continue
                except:
                        print("issue parsing event : ",str(record['data']).replace("\r"," "))
                        #System_events[0]['Service Name'].append("NONE")
                        ServiceName="None"
                        continue
                        #Event_desc="Service State Changed"

                #Event_desc="Service State Changed"
                System_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                System_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                System_events[0]['Computer Name'].append(Computer[0])
                System_events[0]['Channel'].append(Channel[0])
                System_events[0]['Detection Rule'].append("Service State Changed")
                System_events[0]['Detection Domain'].append("Audit")
                System_events[0]['Severity'].append("Medium")
                System_events[0]['Event Description'].append(Event_desc)
                System_events[0]['Event ID'].append(EventID[0])
                System_events[0]['Image Path'].append("None")
                System_events[0]['Service Name'].append(ServiceName)
                System_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
            """

        else:
            print(record['data'])
    System = pd.DataFrame(System_events[0])
    if SystemInitial.value == 1:
        System.to_csv(temp_dir + '_System_report.csv', index=False)
        SystemInitial.value = 0
    else:
        System.to_csv(temp_dir + '_System_report.csv', mode='a', index=False, header=False)

    toc = time.time()
    print('System Logs Done in {:.4f} seconds'.format(toc - tic))

def detect_events_powershell_operational_log(file_name, shared_data):
    tic = time.time()
    input_timezone = shared_data["input_timezone"]
    timestart = shared_data["timestart"]
    timeend = shared_data["timeend"]
    objectaccess = shared_data["objectaccess"]
    processexec = shared_data["processexec"]
    logons = shared_data["logons"]
    frequencyanalysis = shared_data["frequencyanalysis"]
    allreport = shared_data["allreport"]
    output = shared_data["output"]
    #if os.path.exists(temp_dir + "_Executed_Powershell_report.csv"):
    #    Executed_Powershell_Summary[0] = pd.DataFrame(pd.read_csv(temp_dir + "_Executed_Powershell_report.csv")).to_dict(orient='list')

    parser = PyEvtxParser(file_name)
    for record in parser.records():
        EventID = EventID_rex.findall(record['data'])
        Computer = Computer_rex.findall(record['data'])
        Channel = Channel_rex.findall(record['data'])

        if timestart is not None and timeend is not None :
            timestamp=datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat()))
            if not (timestamp>timestart and timestamp<timeend):
                continue

        if len(EventID) > 0:

            # if frequencyanalysis==True and EventID[0] in Frequency_Analysis_Powershell_Operational:
            #     Frequency_Analysis_Powershell_Operational[EventID[0]]=Frequency_Analysis_Powershell_Operational[EventID[0]]+1
            # else:
            #     Frequency_Analysis_Powershell_Operational[EventID[0]]=1
            ContextInfo=Powershell_ContextInfo.findall(record['data'])
            Payload=Powershell_Payload.findall(record['data'])
            Host_Application = Host_Application_rex.findall(record['data'])
            User =User_rex.findall(record['data'])
            Engine_Version = Engine_Version_rex.findall(record['data'])
            Command_Name = Command_Name_rex.findall(record['data'])
            Command_Type = Command_Type_rex.findall(record['data'])
            Error_Message = Error_Message_rex.findall(record['data'])
            Suspicious=[]
            host_app=""


            #Summary of Powershell Commands
            if EventID[0]=="4103" or EventID[0]=="4100" :
                try:
                    if len(Host_Application) == 0:
                        host_app = ""
                    else:
                        host_app = Host_Application[0].strip()
                    if host_app not in Executed_Powershell_Summary[0]['Command']:
                        Executed_Powershell_Summary[0]['Command'].append(host_app.strip())
                        Executed_Powershell_Summary[0]['Number of Execution'].append(1)
                    else :
                        Executed_Powershell_Summary[0]['Number of Execution'][Executed_Powershell_Summary[0]['Command'].index(host_app.strip())]=Executed_Powershell_Summary[0]['Number of Execution'][Executed_Powershell_Summary[0]['Command'].index(host_app.strip())]+1
                except:
                    pass


            if record['data'].strip().find("\\temp\\") > -1 or record['data'].strip().find(
                    "\\tmp\\") > -1:
                Event_desc="Powershell  Operation including TEMP Folder"
                Powershell_Operational_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Powershell_Operational_events[0]['Computer Name'].append(Computer[0])
                Powershell_Operational_events[0]['Channel'].append(Channel[0])
                Powershell_Operational_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Powershell_Operational_events[0]['Detection Rule'].append(
                    "Powershell Module logging - Operation including TEMP folder ")
                Powershell_Operational_events[0]['Detection Domain'].append("Threat")
                Powershell_Operational_events[0]['Severity'].append("High")
                Powershell_Operational_events[0]['Event Description'].append(Event_desc)
                Powershell_Operational_events[0]['Event ID'].append(EventID[0])
                Powershell_Operational_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))

            #Powershell Module logging will record portions of scripts, some de-obfuscated code
            if EventID[0]=="4103" :
                if len(Host_Application) == 0:
                    host_app = ""
                else:
                    host_app = Host_Application[0].strip()
                for i in all_suspicious_powershell:
                    if record['data'].lower().find(i)>-1:
                        Suspicious.append(i)

                if len(Suspicious)>0:
                    #print("##### " + record["timestamp"] + " #### EventID=4103 ### Powershell Module logging #### ", end='')
                    #print("Found User ("+User[0].strip()+") run Suspicious PowerShell commands that include ("+",".join(Suspicious)+") in event with Command Name ("+Command_Name[0].strip()+") and full command ("+Host_Application[0].strip()+") ", end='')#, check event details "+record['data'])
                    #print(record['data'])
                    Event_desc = "Found User (" + User[
                        0].strip() + ") run Suspicious PowerShell commands that include (" + ",".join(
                        Suspicious) + ") in event with Command Name (" + Command_Name[
                                     0].strip() + ") and full command (" + host_app + ") "

                    if len(Error_Message)>0:
                        #print("Error Message ("+Error_Message[0].strip()+")")
                        Event_desc =Event_desc+"Error Message ("+Error_Message[0].strip()+")"
                    #else:
                        #print("")

                    Powershell_Operational_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Powershell_Operational_events[0]['Computer Name'].append(Computer[0])
                    Powershell_Operational_events[0]['Channel'].append(Channel[0])
                    Powershell_Operational_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Powershell_Operational_events[0]['Detection Rule'].append("Powershell Module logging - Malicious Commands Detected")
                    Powershell_Operational_events[0]['Detection Domain'].append("Threat")

                    Powershell_Operational_events[0]['Event Description'].append(Event_desc)
                    Powershell_Operational_events[0]['Event ID'].append(EventID[0])
                    Powershell_Operational_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                    if len(Suspicious)<3:
                        Powershell_Operational_events[0]['Severity'].append("Medium")
                    if len(Suspicious)>2 and len(Suspicious)<6:
                        Powershell_Operational_events[0]['Severity'].append("High")
                    if len(Suspicious)>5:
                        Powershell_Operational_events[0]['Severity'].append("Critical")


            Suspicious = []
            #captures powershell script block Execute a Remote Command
            if EventID[0]=="4104"  or EventID[0]=="24577" :
                for i in all_suspicious_powershell:
                    if record['data'].lower().find(i.lower())>-1:
                        Suspicious.append(i)

                if len(Suspicious)>0:
                    #print("##### " + record["timestamp"] + " #### EventID=4104 #### powershell script block ####", end='')
                    #print("Found Suspicious PowerShell commands that include ("+",".join(Suspicious)+") , check event details "+record['data'])

                    Event_desc ="Found Suspicious PowerShell commands that include ("+",".join(Suspicious)+") , check event details "#+record['data']
                    Powershell_Operational_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Powershell_Operational_events[0]['Computer Name'].append(Computer[0])
                    Powershell_Operational_events[0]['Channel'].append(Channel[0])
                    Powershell_Operational_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Powershell_Operational_events[0]['Detection Rule'].append("powershell script block - Found Suspicious PowerShell commands ")
                    Powershell_Operational_events[0]['Detection Domain'].append("Threat")

                    Powershell_Operational_events[0]['Event Description'].append(Event_desc)
                    Powershell_Operational_events[0]['Event ID'].append(EventID[0])
                    Powershell_Operational_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                    if len(Suspicious)<3:
                        Powershell_Operational_events[0]['Severity'].append("Medium")
                    if len(Suspicious)>2 and len(Suspicious)<6:
                        Powershell_Operational_events[0]['Severity'].append("High")
                    if len(Suspicious)>5:
                        Powershell_Operational_events[0]['Severity'].append("Critical")
            Suspicious = []

            #capture PowerShell ISE Operation
            if EventID[0]=="24577" :
                for i in all_suspicious_powershell:
                    if record['data'].lower().find(i.lower())>-1:
                        Suspicious.append(i)

                if len(Suspicious)>0:
                    #print("##### " + record["timestamp"] + " #### EventID=4104 #### PowerShell ISE Operation ####  ", end='')
                    #print("Found Suspicious PowerShell commands that include ("+",".join(Suspicious)+") , check event details "+record['data'])


                    Event_desc ="Found Suspicious PowerShell commands that include ("+",".join(Suspicious)+") , check event details "+record['data']
                    Powershell_Operational_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Powershell_Operational_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Powershell_Operational_events[0]['Computer Name'].append(Computer[0])
                    Powershell_Operational_events[0]['Channel'].append(Channel[0])
                    Powershell_Operational_events[0]['Detection Rule'].append("PowerShell ISE Operation - Found Suspicious PowerShell commands")
                    Powershell_Operational_events[0]['Detection Domain'].append("Threat")

                    Powershell_Operational_events[0]['Event Description'].append(Event_desc)
                    Powershell_Operational_events[0]['Event ID'].append(EventID[0])
                    Powershell_Operational_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                    if len(Suspicious)<3:
                        Powershell_Operational_events[0]['Severity'].append("Medium")
                    if len(Suspicious)>2 and len(Suspicious)<6:
                        Powershell_Operational_events[0]['Severity'].append("High")
                    if len(Suspicious)>5:
                        Powershell_Operational_events[0]['Severity'].append("Critical")
            Suspicious = []

            #Executing Pipeline
            if EventID[0]=="4100":
                print(record['data'])
                if len(Host_Application) == 0:
                    host_app = ""
                else:
                    host_app = Host_Application[0].strip()
                for i in all_suspicious_powershell:
                    if record['data'].lower().find(i.lower())>-1:
                        Suspicious.append(i)
                if len(Suspicious)>0:
                    #print("##### " + record["timestamp"] + " #### EventID=4100 #### Executing Pipeline ####", end='')
                    #print("Found User ("+User[0].strip()+") run Suspicious PowerShell commands that include ("+",".join(Suspicious)+") in event with Command Name ("+Command_Name[0].strip()+") and full command ("+Host_Application[0].strip()+") ", end='')#, check event details "+record['data'])
                    try:
                        if len(User)==0:
                            User=" "
                        else:
                            User=User[0].strip()

                        Event_desc = "Found User (" + User + ") run Suspicious PowerShell commands that include (" + ",".join(
                            Suspicious) + ") in event with Command Name (" + Command_Name[
                                         0].strip() + ") and full command (" + host_app + ") "

                        if len(Error_Message)>0:
                            #print(Error_Message[0].strip())
                            Event_desc = Event_desc + "Error Message (" + Error_Message[0].strip() + ")"
                        #else:
                            #print("")
                    except:
                        Event_desc= "Found Suspicious PowerShell commands that include (" + ",".join(
                            Suspicious) + ")"
                    Powershell_Operational_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Powershell_Operational_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Powershell_Operational_events[0]['Computer Name'].append(Computer[0])
                    Powershell_Operational_events[0]['Channel'].append(Channel[0])
                    Powershell_Operational_events[0]['Detection Rule'].append("Powershell Executing Pipeline - Suspicious Powershell Commands detected")
                    Powershell_Operational_events[0]['Detection Domain'].append("Threat")

                    Powershell_Operational_events[0]['Event Description'].append(Event_desc)
                    Powershell_Operational_events[0]['Event ID'].append(EventID[0])
                    Powershell_Operational_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                    if len(Suspicious)<3:
                        Powershell_Operational_events[0]['Severity'].append("Medium")
                    if len(Suspicious)>2 and len(Suspicious)<6:
                        Powershell_Operational_events[0]['Severity'].append("High")
                    if len(Suspicious)>5:
                        Powershell_Operational_events[0]['Severity'].append("Critical")
                else:
                    #print("##### " + record["timestamp"] + " #### EventID=4100 #### Executing Pipeline #### ", end='')
                    #print("Found User ("+User[0].strip()+") run PowerShell with Command Name ("+Command_Name[0].strip()+") and full command ("+Host_Application[0].strip()+") ", end='')#, check event details "+record['data'])
                    try:
                        Event_desc = "Found User (" + User[0].strip() + ") run PowerShell with Command Name (" + \
                                     Command_Name[0].strip() + ") and full command (" + host_app + ") "
                        if len(Error_Message)>0:
                            #print("Error Message ("+Error_Message[0].strip()+")")
                            Event_desc = Event_desc + "Error Message ("+Error_Message[0].strip()+")"
                    except:
                        Event_desc ="User running Powershell command"

                    Powershell_Operational_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Powershell_Operational_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Powershell_Operational_events[0]['Computer Name'].append(Computer[0])
                    Powershell_Operational_events[0]['Channel'].append(Channel[0])
                    Powershell_Operational_events[0]['Detection Rule'].append("Powershell Executing Pipeline - User Powershell Commands ")
                    Powershell_Operational_events[0]['Detection Domain'].append("Audit")
                    Powershell_Operational_events[0]['Severity'].append("Medium")
                    Powershell_Operational_events[0]['Event Description'].append(Event_desc)
                    Powershell_Operational_events[0]['Event ID'].append(EventID[0])
                    Powershell_Operational_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
            Suspicious = []
            #Detect any log that contain suspicious process name or argument
            for i in Suspicious_executables:

                if record['data'].lower().find(i.lower())>-1:

                    #print("##### " + record["timestamp"] + " ####  ", end='')
                    #print("## Found Suspicios Process ", end='')
                    #print("User Name : ( %s ) " % Account_Name[0][0].strip(), end='')
                    #print("with Command Line : ( " + Process_Command_Line[0][0].strip() + " )")
                    # print("###########")

                    Event_desc ="Found a log contain suspicious powershell command ( %s)"%i
                    Powershell_Operational_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Powershell_Operational_events[0]['Computer Name'].append(Computer[0])
                    Powershell_Operational_events[0]['Channel'].append(Channel[0])
                    Powershell_Operational_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Powershell_Operational_events[0]['Detection Rule'].append("Suspicious Command or process found in the log")
                    Powershell_Operational_events[0]['Detection Domain'].append("Threat")
                    Powershell_Operational_events[0]['Severity'].append("Critical")
                    Powershell_Operational_events[0]['Event Description'].append(Event_desc)
                    Powershell_Operational_events[0]['Event ID'].append(EventID[0])
                    Powershell_Operational_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                    break
        else:
            print(record['data'])
    Powershell_Operational = pd.DataFrame(Powershell_Operational_events[0])
    #Executed_Powershell= pd.DataFrame(Executed_Powershell_Summary[0])
    Powershell_Execution_dataframes=[]
    lock.acquire()
    if os.path.exists(temp_dir + "Powershell_Execution_Events.pickle"):
        with open(temp_dir + "Powershell_Execution_Events.pickle", 'rb') as handle:
            # lock.acquire()
            try:
                Powershell_Execution_dataframes = pickle.load(handle)
                handle.close()
                # lock.release()
                # print("Read:" + str(Security_Authentication_dataframes))
            except Exception as e:
                print("Powershell Erorr : " + str(e))
                # lock.release()
    else:
        with open(temp_dir + "Powershell_Execution_Events.pickle", 'wb') as handle:

            Powershell_Execution_dataframes.append(pd.DataFrame(Executed_Powershell_Summary[0]))
            # print("Write:" + str(Security_Authentication_dataframes))
            # lock.acquire()
            pickle.dump(Powershell_Execution_dataframes, handle, protocol=pickle.HIGHEST_PROTOCOL)
            handle.close()
            # lock.release()
    with open(temp_dir + "Powershell_Execution_Events.pickle", 'wb') as handle:

        Powershell_Execution_dataframes.append(pd.DataFrame(Executed_Powershell_Summary[0]))
        # print("Write:" + str(Security_Authentication_dataframes))
        # lock.acquire()
        pickle.dump(Powershell_Execution_dataframes, handle, protocol=pickle.HIGHEST_PROTOCOL)
        handle.close()
        # lock.release()
    lock.release()
    if Powershell_OperationalInitial.value == 1:
        Powershell_Operational.to_csv(temp_dir + '_Powershell_Operational_report.csv', index=False)
        #Executed_Powershell.to_csv(temp_dir + '_Executed_Powershell_report.csv', index=False)
        Powershell_OperationalInitial.value = 0
    else:
        Powershell_Operational.to_csv(temp_dir + '_Powershell_Operational_report.csv', mode='a', index=False, header=False)
        #Executed_Powershell.to_csv(temp_dir + '_Executed_Powershell_report.csv', mode='a', index=False, header=False)

    toc = time.time()
    print('Powershell Operational Done in {:.4f} seconds'.format(toc - tic))
def detect_events_powershell_log(file_name, shared_data):
    input_timezone = shared_data["input_timezone"]
    timestart = shared_data["timestart"]
    timeend = shared_data["timeend"]
    objectaccess = shared_data["objectaccess"]
    processexec = shared_data["processexec"]
    logons = shared_data["logons"]
    frequencyanalysis = shared_data["frequencyanalysis"]
    allreport = shared_data["allreport"]
    output = shared_data["output"]

    parser = PyEvtxParser(file_name)
    for record in parser.records():
        EventID = EventID_rex.findall(record['data'])
        Computer = Computer_rex.findall(record['data'])
        Channel = Channel_rex.findall(record['data'])

        if timestart is not None and timeend is not None :
            timestamp=datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat()))
            if not (timestamp>timestart and timestamp<timeend):
                continue

        if len(EventID) > 0:

            # if frequencyanalysis==True and EventID[0] in Frequency_Analysis_Powershell:
            #     Frequency_Analysis_Powershell[EventID[0]]=Frequency_Analysis_Powershell[EventID[0]]+1
            # else:
            #     Frequency_Analysis_Powershell[EventID[0]]=1
            Host_Application = HostApplication_rex.findall(record['data'])
            User =UserId_rex.findall(record['data'])
            Engine_Version = EngineVersion_rex.findall(record['data'])
            ScriptName = ScriptName_rex.findall(record['data'])
            CommandLine= CommandLine_rex.findall(record['data'])
            Error_Message = ErrorMessage_rex.findall(record['data'])
            Suspicious=[]
            #Powershell Pipeline Execution details
            host_app=""


            #Summary of Powershell Commands
            if EventID[0]=="600" or EventID[0]=="400" or EventID[0]=="300" or EventID[0]=="800" or EventID[0]=="403":
                try:
                    if len(Host_Application) == 0:
                        host_app = ""
                    else:
                        host_app = Host_Application[0].strip()
                    if host_app not in Executed_Powershell_Summary[0]['Command']:
                        Executed_Powershell_Summary[0]['Command'].append(host_app.strip())
                        Executed_Powershell_Summary[0]['Number of Execution'].append(1)
                    else :
                        Executed_Powershell_Summary[0]['Number of Execution'][Executed_Powershell_Summary[0]['Command'].index(host_app.strip())]=Executed_Powershell_Summary[0]['Number of Execution'][Executed_Powershell_Summary[0]['Command'].index(host_app.strip())]+1
                except:
                    pass

            if record['data'].strip().find("\\temp\\") > -1 or record['data'].strip().find(
                    "\\tmp\\") > -1:
                Event_desc="Powershell Operation including TEMP Folder"
                Powershell_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Powershell_events[0]['Computer Name'].append(Computer[0])
                Powershell_events[0]['Channel'].append(Channel[0])
                Powershell_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Powershell_events[0]['Detection Rule'].append(
                    "Powershell Executing Pipeline - Operation including TEMP folder ")
                Powershell_events[0]['Detection Domain'].append("Threat")
                Powershell_events[0]['Severity'].append("High")
                Powershell_events[0]['Event Description'].append(Event_desc)
                Powershell_events[0]['Event ID'].append(EventID[0])
                Powershell_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))




            if EventID[0]=="800" :
                if len(Host_Application) == 0:
                    host_app = ""
                else:
                    host_app = Host_Application[0].strip()
                for i in all_suspicious_powershell:
                    if record['data'].lower().find(i.lower())>-1:
                        Suspicious.append(i)

                if len(Suspicious)>0:
                    #print("##### " + record["timestamp"] + " #### EventID=800 ### Powershell Pipeline Execution details #### ", end='')
                    #print("Found User ("+User[0].strip()+") run Suspicious PowerShell commands that include ("+",".join(Suspicious)+") in event with Command Line ("+CommandLine[0].strip()+") and full command ("+Host_Application[0].strip()+") ", end='')#, check event details "+record['data'])
                    Event_desc ="Found User ("+User[0].strip()+") run Suspicious PowerShell commands that include ("+",".join(Suspicious)+") in event with Command Line ("+CommandLine[0].strip()+") and full command ("+host_app+") "
                    if len(Error_Message)>0:
                        Event_desc = Event_desc +"Error Message ("+Error_Message[0].strip()+")"
                        #print("Error Message ("+Error_Message[0].strip()+")")
                    #else:
                    #    print("")

                    Powershell_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Powershell_events[0]['Computer Name'].append(Computer[0])
                    Powershell_events[0]['Channel'].append(Channel[0])
                    Powershell_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Powershell_events[0]['Detection Rule'].append("Powershell Executing Pipeline - Suspicious Powershell Commands detected")
                    Powershell_events[0]['Detection Domain'].append("Threat")

                    Powershell_events[0]['Event Description'].append(Event_desc)
                    Powershell_events[0]['Event ID'].append(EventID[0])
                    Powershell_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                    if len(Suspicious)<3:
                        Powershell_events[0]['Severity'].append("Medium")
                    if len(Suspicious)>2 and len(Suspicious)<6:
                        Powershell_events[0]['Severity'].append("High")
                    if len(Suspicious)>5:
                        Powershell_events[0]['Severity'].append("Critical")
                    continue
            Suspicious = []

            if EventID[0]=="600" or EventID[0]=="400" or EventID[0]=="403" :
                if len(Host_Application) == 0:
                    host_app = ""
                else:
                    host_app = Host_Application[0].strip()
                for i in all_suspicious_powershell:
                    if record['data'].lower().find(i.lower())>-1:
                        Suspicious.append(i)

                if len(Suspicious)>0:
                    #print("##### " + record["timestamp"] + " #### EventID="+EventID[0].strip()+" ### Engine state is changed #### ", end='')
                    #print("Found  Suspicious PowerShell commands that include ("+",".join(Suspicious)+") in event with Command Line ("+CommandLine[0].strip()+") and full command ("+Host_Application[0].strip()+") ", end='')#, check event details "+record['data'])
                    Event_desc ="Found  Suspicious PowerShell commands that include (" + ",".join(
                        Suspicious) + ") in event with Command Line (" + CommandLine[
                        0].strip() + ") and full command (" + host_app + ") "

                    if len(Error_Message)>0:
                        Event_desc = Event_desc + "Error Message (" + Error_Message[0].strip() + ")"
                        #print("Error Message ("+Error_Message[0].strip()+")")
                    #else:
                    #    print("")
                    Powershell_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Powershell_events[0]['Computer Name'].append(Computer[0])
                    Powershell_events[0]['Channel'].append(Channel[0])
                    Powershell_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Powershell_events[0]['Detection Rule'].append("Suspicious PowerShell commands Detected")
                    Powershell_events[0]['Detection Domain'].append("Threat")

                    Powershell_events[0]['Event Description'].append(Event_desc)
                    Powershell_events[0]['Event ID'].append(EventID[0])
                    Powershell_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    if len(Suspicious)<3:
                        Powershell_events[0]['Severity'].append("Medium")
                    if len(Suspicious)>2 and len(Suspicious)<6:
                        Powershell_events[0]['Severity'].append("High")
                    if len(Suspicious)>5:
                        Powershell_events[0]['Severity'].append("Critical")
                    continue
            Suspicious = []
            if EventID[0]!="600" and EventID[0]!="400" or EventID[0]!="403" or EventID[0]!="800":
                for i in all_suspicious_powershell:
                    if record['data'].lower().find(i.lower())>-1:
                        Suspicious.append(i)

                if len(Suspicious)>0:
                    Event_desc ="Found  Suspicious PowerShell commands that include (" + ",".join(Suspicious) + ") in event "
                    Powershell_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Powershell_events[0]['Computer Name'].append(Computer[0])
                    Powershell_events[0]['Channel'].append(Channel[0])
                    Powershell_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Powershell_events[0]['Detection Rule'].append("Suspicious PowerShell commands Detected")
                    Powershell_events[0]['Detection Domain'].append("Threat")

                    Powershell_events[0]['Event Description'].append(Event_desc)
                    Powershell_events[0]['Event ID'].append(EventID[0])
                    Powershell_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    if len(Suspicious)<3:
                        Powershell_events[0]['Severity'].append("Medium")
                    if len(Suspicious)>2 and len(Suspicious)<6:
                        Powershell_events[0]['Severity'].append("High")
                    if len(Suspicious)>5:
                        Powershell_events[0]['Severity'].append("Critical")
                    continue
            Suspicious = []

            #Detect any log that contain suspicious process name or argument
            """for i in all_suspicious_powershell:
                if record['data'].lower().find(i.lower())>-1:
                    Suspicious.append(i)

            if len(Suspicious)>0:


                    #print("##### " + record["timestamp"] + " ####  ", end='')
                    #print("## Found Suspicios Process ", end='')
                    #print("User Name : ( %s ) " % Account_Name[0][0].strip(), end='')
                    #print("with Command Line : ( " + Process_Command_Line[0][0].strip() + " )")
                    # print("###########")

                    Event_desc ="Found a log contain suspicious powershell command ( %s)"%i
                    Powershell_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Powershell_events[0]['Computer Name'].append(Computer[0])
                    Powershell_events[0]['Channel'].append(Channel[0])
                    Powershell_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Powershell_events[0]['Detection Rule'].append("Suspicious Command or process found in the log")
                    Powershell_events[0]['Detection Domain'].append("Threat")
                    Powershell_events[0]['Event Description'].append(Event_desc)
                    Powershell_events[0]['Event ID'].append(EventID[0])
                    Powershell_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                    if len(Suspicious)<3:
                        Powershell_events[0]['Severity'].append("Medium")
                    if len(Suspicious)>2 and len(Suspicious)<6:
                        Powershell_events[0]['Severity'].append("High")
                    if len(Suspicious)>5:
                        Powershell_events[0]['Severity'].append("Critical")
                    continue"""

        else:
            print(record['data'])

    Powershell = pd.DataFrame(Powershell_events[0])
    if PowershellInitial.value == 1:
        Powershell.to_csv(temp_dir + '_Powershell_report.csv', index=False)
        PowershellInitial.value = 0
    else:
        Powershell.to_csv(temp_dir + '_Powershell_report.csv', mode='a', index=False, header=False)
def detect_events_TerminalServices_RDPClient_log(file_name, shared_data):
    input_timezone = shared_data["input_timezone"]
    timestart = shared_data["timestart"]
    timeend = shared_data["timeend"]
    objectaccess = shared_data["objectaccess"]
    processexec = shared_data["processexec"]
    logons = shared_data["logons"]
    frequencyanalysis = shared_data["frequencyanalysis"]
    allreport = shared_data["allreport"]
    output = shared_data["output"]

    parser = PyEvtxParser(file_name)
    for record in parser.records():
        EventID = EventID_rex.findall(record['data'])
        Computer = Computer_rex.findall(record['data'])
        Channel = Channel_rex.findall(record['data'])

        if timestart is not None and timeend is not None :
            timestamp=datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat()))
            if not (timestamp>timestart and timestamp<timeend):
                continue

        if len(EventID) > 0:

            UserID =UserID_RDPCLIENT_rex.findall(record['data'])
            DestIP=IP_RDPCLIENT_rex.findall(record['data'])
            Server_Name=ServerName_RDPCLIENT_rex.findall(record['data'])
            TraceMessage=TraceMessage_RDPCLIENT_rex.findall(record['data'])

            if EventID[0]=="1024" :
                Event_desc ="Found User with ID ("+UserID[0].strip()+") trying to access server ( %s ) with IP ( %s ) "%(Server_Name[0],DestIP[0])
                lock.acquire()
                TerminalServices_RDPClient_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                TerminalServices_RDPClient_events[0]['Computer Name'].append(Computer[0])
                TerminalServices_RDPClient_events[0]['Channel'].append(Channel[0])
                TerminalServices_RDPClient_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                TerminalServices_RDPClient_events[0]['Detection Rule'].append("User initiated a multi-transport connection to a server ")
                TerminalServices_RDPClient_events[0]['Detection Domain'].append("Threat")
                TerminalServices_RDPClient_events[0]['Severity'].append("High")
                TerminalServices_RDPClient_events[0]['UserID'].append(UserID[0].strip())
                TerminalServices_RDPClient_events[0]['Source IP'].append(DestIP[0].strip())
                TerminalServices_RDPClient_events[0]['Event Description'].append(Event_desc)
                TerminalServices_RDPClient_events[0]['Event ID'].append(EventID[0])
                TerminalServices_RDPClient_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                lock.release()

            if EventID[0]=="1029" :
                Event_desc ="Found User with ID ("+UserID[0].strip()+") trying to initiate RDP Connection. TraceMessage is ( %s ) "%TraceMessage[0]
                lock.acquire()
                TerminalServices_RDPClient_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                TerminalServices_RDPClient_events[0]['Computer Name'].append(Computer[0])
                TerminalServices_RDPClient_events[0]['Channel'].append(Channel[0])
                TerminalServices_RDPClient_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                TerminalServices_RDPClient_events[0]['Detection Rule'].append("User initiated an RDP connection to a server ")
                TerminalServices_RDPClient_events[0]['Detection Domain'].append("Threat")
                TerminalServices_RDPClient_events[0]['Severity'].append("High")
                TerminalServices_RDPClient_events[0]['UserID'].append(UserID[0].strip())
                TerminalServices_RDPClient_events[0]['Source IP'].append("UNKNOWN")
                TerminalServices_RDPClient_events[0]['Event Description'].append(Event_desc)
                TerminalServices_RDPClient_events[0]['Event ID'].append(EventID[0])
                TerminalServices_RDPClient_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                lock.release()

    TerminalServices_RDPClient = pd.DataFrame(TerminalServices_RDPClient_events[0])
    if TerminalServices_RDPClientInitial.value == 1:
        TerminalServices_RDPClient.to_csv(temp_dir + '_TerminalServices_RDPClient_report.csv', index=False)
        TerminalServices_RDPClientInitial.value = 0
    else:
        TerminalServices_RDPClient.to_csv(temp_dir + '_TerminalServices_RDPClient_report.csv', mode='a', index=False, header=False)

def detect_events_TerminalServices_LocalSessionManager_log(file_name, shared_data):
    input_timezone = shared_data["input_timezone"]
    timestart = shared_data["timestart"]
    timeend = shared_data["timeend"]
    objectaccess = shared_data["objectaccess"]
    processexec = shared_data["processexec"]
    logons = shared_data["logons"]
    frequencyanalysis = shared_data["frequencyanalysis"]
    allreport = shared_data["allreport"]
    output = shared_data["output"]

    parser = PyEvtxParser(file_name)
    for record in parser.records():
        EventID = EventID_rex.findall(record['data'])
        Computer = Computer_rex.findall(record['data'])
        Channel = Channel_rex.findall(record['data'])

        if timestart is not None and timeend is not None :
            timestamp=datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat()))
            if not (timestamp>timestart and timestamp<timeend):
                continue

        if len(EventID) > 0:

            # if frequencyanalysis==True and EventID[0] in Frequency_Analysis_TerminalServices:
            #     Frequency_Analysis_TerminalServices[EventID[0]]=Frequency_Analysis_TerminalServices[EventID[0]]+1
            # else:
            #     Frequency_Analysis_TerminalServices[EventID[0]]=1
            User =User_Terminal_rex.findall(record['data'])
            Source_Network_Address=Source_Network_Address_Terminal_rex.findall(record['data'])
            Source_Network_Address_Terminal_NotIP=Source_Network_Address_Terminal_NotIP_rex.findall(record['data'])


            if (EventID[0]=="21" or EventID[0]=="25" ) :
                if User[0].strip() not in TerminalServices_Summary[0]['User']:
                    TerminalServices_Summary[0]['User'].append(User[0].strip())
                    TerminalServices_Summary[0]['Number of Logins'].append(1)
                else :
                    TerminalServices_Summary[0]['Number of Logins'][TerminalServices_Summary[0]['User'].index(User[0].strip())]=TerminalServices_Summary[0]['Number of Logins'][TerminalServices_Summary[0]['User'].index(User[0].strip())]+1


            # Remote Desktop Services: Session logon succeeded
            if EventID[0]=="21" or EventID[0]=="25" :
                #print(Source_Network_Address[0][0])
                #print(len(Source_Network_Address))
                if len(Source_Network_Address)>0:
                    #print(IPAddress(Source_Network_Address[0][0].strip()).is_private())
                    if  Source_Network_Address[0][0].strip()=="127.0.0.1":
                        #print("##### " + record["timestamp"] + " #### EventID=" + EventID[0].strip() + " ### Remote Desktop Services: Session logon succeeded: #### ", end='')
                        #print("Found User ("+User[0].strip()+") connecting from Local Host ( 127.0.0.1 ) which means attacker is using tunnel to connect RDP ")

                        Event_desc ="Found User ("+User[0].strip()+") connecting from Local Host ( 127.0.0.1 ) which means attacker is using tunnel to connect RDP "
                        lock.acquire()
                        TerminalServices_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        TerminalServices_events[0]['Computer Name'].append(Computer[0])
                        TerminalServices_events[0]['Channel'].append(Channel[0])
                        TerminalServices_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        TerminalServices_events[0]['Detection Rule'].append("User connected RDP from Local host - Possible Socks Proxy being used")
                        TerminalServices_events[0]['Detection Domain'].append("Threat")
                        TerminalServices_events[0]['Severity'].append("Critical")
                        TerminalServices_events[0]['User'].append(User[0].strip())
                        TerminalServices_events[0]['Source IP'].append(Source_Network_Address[0][0].strip())
                        TerminalServices_events[0]['Event Description'].append(Event_desc)
                        TerminalServices_events[0]['Event ID'].append(EventID[0])
                        TerminalServices_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                        lock.release()
                    if Source_Network_Address[0][0].strip()!="127.0.0.1" and not IPAddress(Source_Network_Address[0][0].strip()).is_private():
                        #print("##### " + record["timestamp"] + " #### EventID=" + EventID[0].strip() + " ### Remote Desktop Services: Session logon succeeded: #### ", end='')
                        #print("Found User ("+User[0].strip()+") connecting from public IP (" +Source_Network_Address[0][0].strip()+") ")

                        Event_desc ="Found User ("+User[0].strip()+") connecting from public IP (" +Source_Network_Address[0][0].strip()+") "
                        lock.acquire()
                        TerminalServices_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        TerminalServices_events[0]['Computer Name'].append(Computer[0])
                        TerminalServices_events[0]['Channel'].append(Channel[0])
                        TerminalServices_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        TerminalServices_events[0]['Detection Rule'].append("User Connecting RDP from Public IP")
                        TerminalServices_events[0]['Detection Domain'].append("Audit")
                        TerminalServices_events[0]['User'].append(User[0].strip())
                        TerminalServices_events[0]['Source IP'].append(Source_Network_Address[0][0].strip())
                        TerminalServices_events[0]['Severity'].append("Critical")
                        TerminalServices_events[0]['Event Description'].append(Event_desc)
                        TerminalServices_events[0]['Event ID'].append(EventID[0])
                        TerminalServices_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                        lock.release()
                    elif Source_Network_Address[0][0].strip()!="127.0.0.1" and (parse(record["timestamp"]).astimezone(input_timzone).hour>20 or parse(record["timestamp"]).astimezone(input_timzone).hour<8) :
                        #print("##### " + record["timestamp"] + " #### EventID=" + EventID[0].strip() + " ### Remote Desktop Services: Session logon succeeded: #### ", end='')
                        #print("Found User ("+User[0].strip()+") connecting from public IP (" +Source_Network_Address[0][0].strip()+") ")
                        Event_desc = "Found User (" + User[
                            0].strip() + ") connecting from IP (" +Source_Network_Address[0][0]+ ") after working hours"
                        lock.acquire()
                        TerminalServices_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        TerminalServices_events[0]['Computer Name'].append(Computer[0])
                        TerminalServices_events[0]['Channel'].append(Channel[0])
                        TerminalServices_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        TerminalServices_events[0]['Detection Rule'].append(
                            "User connected RDP to this machine after working hours")
                        TerminalServices_events[0]['Detection Domain'].append("Audit")
                        TerminalServices_events[0]['User'].append(User[0].strip())
                        TerminalServices_events[0]['Source IP'].append(Source_Network_Address[0][0].strip())
                        TerminalServices_events[0]['Severity'].append("High")
                        TerminalServices_events[0]['Event Description'].append(Event_desc)
                        TerminalServices_events[0]['Event ID'].append(EventID[0])
                        TerminalServices_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                        lock.release()
                    else:
                        Event_desc = "Found User (" + User[
                            0].strip() + ") connecting from IP (" +Source_Network_Address[0][0]+ ") "
                        lock.acquire()
                        TerminalServices_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        TerminalServices_events[0]['Computer Name'].append(Computer[0])
                        TerminalServices_events[0]['Channel'].append(Channel[0])
                        TerminalServices_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        TerminalServices_events[0]['Detection Rule'].append(
                            "User connected RDP to this machine")
                        TerminalServices_events[0]['Detection Domain'].append("Audit")
                        TerminalServices_events[0]['User'].append(User[0].strip())
                        TerminalServices_events[0]['Source IP'].append(Source_Network_Address[0][0].strip())
                        TerminalServices_events[0]['Severity'].append("Medium")
                        TerminalServices_events[0]['Event Description'].append(Event_desc)
                        TerminalServices_events[0]['Event ID'].append(EventID[0])
                        TerminalServices_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                        lock.release()


            # Remote Desktop Services: Session logon succeeded
            if EventID[0]=="21" or EventID[0]=="25" :
                #print(Source_Network_Address[0][0])
                #print(len(Source_Network_Address))
                if len(Source_Network_Address)<1:
                    #print(IPAddress(Source_Network_Address[0][0].strip()).is_private())
                    Event_desc ="User ("+User[0].strip()+") connecting from ( "+Source_Network_Address_Terminal_NotIP[0]+" ) "
                    lock.acquire()
                    TerminalServices_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    TerminalServices_events[0]['Computer Name'].append(Computer[0])
                    TerminalServices_events[0]['Channel'].append(Channel[0])
                    TerminalServices_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    TerminalServices_events[0]['Detection Rule'].append("User Loggedon to machine")
                    TerminalServices_events[0]['User'].append(User[0].strip())
                    TerminalServices_events[0]['Source IP'].append(Source_Network_Address_Terminal_NotIP[0])
                    TerminalServices_events[0]['Detection Domain'].append("Access")
                    TerminalServices_events[0]['Severity'].append("Low")
                    TerminalServices_events[0]['Event Description'].append(Event_desc)
                    TerminalServices_events[0]['Event ID'].append(EventID[0])
                    TerminalServices_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                    lock.release()
            # Remote Desktop Services: Session logon succeeded after working hours
            if ( EventID[0]=="21" or EventID[0]=="25") and (parse(record["timestamp"]).astimezone(input_timzone).hour>20 or parse(record["timestamp"]).astimezone(input_timzone).hour<8) :
                #print(Source_Network_Address[0][0])
                #print(len(Source_Network_Address))
                if len(Source_Network_Address)<1:
                    #print(IPAddress(Source_Network_Address[0][0].strip()).is_private())
                    Event_desc ="User ("+User[0].strip()+") connecting from ( "+Source_Network_Address_Terminal_NotIP[0]+" ) after working hours"
                    lock.acquire()
                    TerminalServices_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    TerminalServices_events[0]['Computer Name'].append(Computer[0])
                    TerminalServices_events[0]['Channel'].append(Channel[0])
                    TerminalServices_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    TerminalServices_events[0]['Detection Rule'].append("User Loggedon to machine after working hours")
                    TerminalServices_events[0]['User'].append(User[0].strip())
                    TerminalServices_events[0]['Source IP'].append(Source_Network_Address_Terminal_NotIP[0])
                    TerminalServices_events[0]['Detection Domain'].append("Access")
                    TerminalServices_events[0]['Severity'].append("High")
                    TerminalServices_events[0]['Event Description'].append(Event_desc)
                    TerminalServices_events[0]['Event ID'].append(EventID[0])
                    TerminalServices_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                    lock.release()
        else:
            print(record['data'])

    TerminalServices = pd.DataFrame(TerminalServices_events[0])
    if TerminalServicesInitial.value == 1:
        TerminalServices.to_csv(temp_dir + '_TerminalServices_report.csv', index=False)
        TerminalServicesInitial.value = 0
    else:
        TerminalServices.to_csv(temp_dir + '_TerminalServices_report.csv', mode='a', index=False, header=False)

def detect_events_Microsoft_Windows_WinRM(file_name, shared_data):
    input_timezone = shared_data["input_timezone"]
    timestart = shared_data["timestart"]
    timeend = shared_data["timeend"]
    objectaccess = shared_data["objectaccess"]
    processexec = shared_data["processexec"]
    logons = shared_data["logons"]
    frequencyanalysis = shared_data["frequencyanalysis"]
    allreport = shared_data["allreport"]
    output = shared_data["output"]
    parser = PyEvtxParser(file_name)
    for record in parser.records():
        EventID = EventID_rex.findall(record['data'])
        Computer = Computer_rex.findall(record['data'])
        Channel = Channel_rex.findall(record['data'])

        if timestart is not None and timeend is not None :
            timestamp=datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat()))
            if not (timestamp>timestart and timestamp<timeend):
                continue

        if len(EventID) > 0:

            # if frequencyanalysis==True and EventID[0] in Frequency_Analysis_WinRM:
            #     Frequency_Analysis_WinRM[EventID[0]]=Frequency_Analysis_WinRM[EventID[0]]+1
            # else:
            #     Frequency_Analysis_WinRM[EventID[0]]=1
            Connection=Connection_rex.findall(record['data'])
            User_ID = Winrm_UserID_rex.findall(record['data'])
            #src_device=src_device_rex.findall(record['data'])
            #User_ID=User_ID_rex.findall(record['data'])


            #connection is initiated using WinRM - Powershell remoting
            if EventID[0]=="6":

                try:
                    if len(Connection[0])>1:
                        connection=Connection[0][1].strip()
                    else:
                        connection=Connection[0][0].strip()
                    #print("##### " + record["timestamp"] + " #### EventID=" + EventID[0].strip() + " ### connection is initiated using WinRM from this machine - Powershell remoting  #### ", end='')
                    #print("User Connected to ("+ Connection[0].strip() +") using WinRM - powershell remote ")
                    Event_desc="User ("+User_ID[0].strip()+") Connected to ("+ connection.strip() +") using WinRM - powershell remote "
                except:
                    Event_desc="User Connected to another machine using WinRM - powershell remote "
                lock.acquire()
                WinRM_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                WinRM_events[0]['Computer Name'].append(Computer[0])
                WinRM_events[0]['Channel'].append(Channel[0])
                WinRM_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                WinRM_events[0]['Detection Rule'].append("connection is initiated using WinRM from this machine - Powershell remoting")
                WinRM_events[0]['Detection Domain'].append("Audit")
                WinRM_events[0]['Severity'].append("High")
                WinRM_events[0]['UserID'].append(User_ID[0].strip())
                WinRM_events[0]['Event Description'].append(Event_desc)
                WinRM_events[0]['Event ID'].append(EventID[0])
                WinRM_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()


            if EventID[0]=="91":

                #print("##### " + record["timestamp"] + " #### EventID=" + EventID[0].strip() + " ### connection is initiated using WinRM to this machine - Powershell remoting  #### ", end='')
                #print("User Connected to this machine using WinRM - powershell remote - check the system logs for more information")
                try:
                    Event_desc="User ("+User_ID[0].strip()+") Connected to this machine using WinRM - powershell remote - check eventlog viewer"
                except:
                    Event_desc="User Connected to this machine using WinRM - powershell remote - check eventlog viewer"
                lock.acquire()
                WinRM_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                WinRM_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                WinRM_events[0]['Computer Name'].append(Computer[0])
                WinRM_events[0]['Channel'].append(Channel[0])
                WinRM_events[0]['Detection Rule'].append("connection is initiated using WinRM to this machine - Powershell remoting")
                WinRM_events[0]['Detection Domain'].append("Audit")
                WinRM_events[0]['Severity'].append("High")
                WinRM_events[0]['UserID'].append(User_ID[0].strip())
                WinRM_events[0]['Event Description'].append(Event_desc)
                WinRM_events[0]['Event ID'].append(EventID[0])
                WinRM_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()
        else:
            print(record['data'])
    WinRM = pd.DataFrame(WinRM_events[0])
    if WinRMInitial.value == 1:
        WinRM.to_csv(temp_dir + '_WinRM_events_report.csv', index=False)
        WinRMInitial.value = 0
    else:
        WinRM.to_csv(temp_dir + '_WinRM_events_report.csv', mode='a', index=False, header=False)

def detect_events_Sysmon_log(file_name, shared_data):
    input_timezone = shared_data["input_timezone"]
    timestart = shared_data["timestart"]
    timeend = shared_data["timeend"]
    objectaccess = shared_data["objectaccess"]
    processexec = shared_data["processexec"]
    logons = shared_data["logons"]
    frequencyanalysis = shared_data["frequencyanalysis"]
    allreport = shared_data["allreport"]
    output = shared_data["output"]
    parser = PyEvtxParser(file_name)
    for record in parser.records():
        EventID = EventID_rex.findall(record['data'])
        Computer = Computer_rex.findall(record['data'])
        Channel = Channel_rex.findall(record['data'])

        if timestart is not None and timeend is not None :
            timestamp=datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat()))
            if not (timestamp>timestart and timestamp<timeend):
                continue

        if len(EventID) > 0:

            # if frequencyanalysis==True and EventID[0] in Frequency_Analysis_Sysmon:
            #     Frequency_Analysis_Sysmon[EventID[0]]=Frequency_Analysis_Sysmon[EventID[0]]+1
            # else:
            #     Frequency_Analysis_Sysmon[EventID[0]]=1
            CommandLine=Sysmon_CommandLine_rex.findall(record['data'])
            ProcessGuid=Sysmon_ProcessGuid_rex.findall(record['data'])
            ProcessId=Sysmon_ProcessId_rex.findall(record['data'])
            Image=Sysmon_Image_rex.findall(record['data'])
            FileVersion=Sysmon_FileVersion_rex.findall(record['data'])
            Company=Sysmon_Company_rex.findall(record['data'])
            Product=Sysmon_Product_rex.findall(record['data'])
            Description=Sysmon_Description_rex.findall(record['data'])
            User=Sysmon_User_rex.findall(record['data'])
            LogonGuid=Sysmon_LogonGuid_rex.findall(record['data'])
            TerminalSessionId=Sysmon_TerminalSessionId_rex.findall(record['data'])
            MD5=Sysmon_Hashes_MD5_rex.findall(record['data'])
            SHA256=Sysmon_Hashes_SHA256_rex.findall(record['data'])
            ParentProcessGuid=Sysmon_ParentProcessGuid_rex.findall(record['data'])
            ParentProcessId=Sysmon_ParentProcessId_rex.findall(record['data'])
            ParentImage=Sysmon_ParentImage_rex.findall(record['data'])
            ParentCommandLine=Sysmon_ParentCommandLine_rex.findall(record['data'])
            CurrentDirectory=Sysmon_CurrentDirectory_rex.findall(record['data'])
            OriginalFileName=Sysmon_OriginalFileName_rex.findall(record['data'])
            TargetObject=Sysmon_TargetObject_rex.findall(record['data'])
            Protocol=Sysmon_Protocol_rex.findall(record['data'])
            SourceIp=Sysmon_SourceIp_rex.findall(record['data'])
            SourceHostname=Sysmon_SourceHostname_rex.findall(record['data'])
            SourcePort=Sysmon_SourcePort_rex.findall(record['data'])
            DestinationIp=Sysmon_DestinationIp_rex.findall(record['data'])
            DestinationHostname=Sysmon_DestinationHostname_rex.findall(record['data'])
            DestinationPort=Sysmon_DestinationPort_rex.findall(record['data'])
            StartFunction=Sysmon_StartFunction_rex.findall(record['data'])
            SourceImage=Sysmon_SourceImage_rex.findall(record['data'])
            TargetImage=Sysmon_TargetImage_rex.findall(record['data'])

            ImageLoaded=Sysmon_ImageLoaded_rex.findall(record['data'])
            GrantedAccess=Sysmon_GrantedAccess_rex.findall(record['data'])
            CallTrace=Sysmon_CallTrace_rex.findall(record['data'])
            Details=Sysmon_Details_rex.findall(record['data'])
            PipeName=Sysmon_PipeName_rex.findall(record['data'])

            temp=[]
            #Powershell with Suspicious Argument covers [ T1086 ,
            if EventID[0]=="1" and Image[0].strip().find("powershell.exe")>-1:
                #print(CommandLine[0])
                Suspicious = []
                for i in Suspicious_powershell_Arguments:
                    if CommandLine[0].strip().find(i)>-1:
                        Suspicious.append(i)

                for i in Suspicious_powershell_Arguments:
                    if ParentCommandLine[0].strip().find(i)>-1:
                        Suspicious.append(i)
                if len(Suspicious) > 0:
                    """print("##### " + row[
                        'Date and Time'] + " #### EventID=1 ### [ T1086 ]  Powershell with Suspicious Argument #### ", end='')
                    print(
                        "Found User (" + User[0].strip() + ") run Suspicious PowerShell commands that include (" + ",".join(
                            Suspicious) + ") in event with Command Line (" + CommandLine[
                            0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )")"""

                    Event_desc="Found User (" + User[0].strip() + ") run Suspicious PowerShell commands that include (" + ",".join(
                                Suspicious) + ") in event with Command Line (" + CommandLine[
                                0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Detection Rule'].append('[ T1086 ]  Powershell with Suspicious Argument')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("Critical")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #[  T1543 ] Sc.exe manipulating windows services
            if EventID[0]=="1" and Image[0].strip().find("\\sc.exe")>-1 and ( CommandLine[0].find("create")>-1 or CommandLine[0].find("start")>-1 or CommandLine[0].find("config")>-1 ):

                """print("##### " + row[
                    'Date and Time'] + " #### EventID=1 ### [  T1543 ] Sc.exe manipulating windows services #### ", end='')
                print(
                    "Found User (" + User[0].strip() + ") Trying to manipulate windows services usign Sc.exe with Command Line (" + CommandLine[
                        0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )")"""

                Event_desc="Found User (" + User[0].strip() + ") Trying to manipulate windows services usign Sc.exe with Command Line (" + CommandLine[
                        0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[  T1543 ] Sc.exe manipulating windows services')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [ T1059 ] wscript or cscript runing script
            if EventID[0]=="1" and ( Image[0].strip().find("\\wscript.exe")>-1 or Image[0].strip().find("\\cscript.exe")>-1 ):

                """print("##### " + record["timestamp"] + " #### EventID=1 ### [  T1059 ] wscript or cscript runing script #### ", end='')
                print(
                    "Found User (" + User[0].strip() + ") Trying to run wscript or cscript with Command Line (" + CommandLine[
                        0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )")"""

                Event_desc="Found User (" + User[0].strip() + ") Trying to run wscript or cscript with Command Line (" + CommandLine[
                        0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[ T1059 ] wscript or cscript runing script')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()


            #  [T1170] Detecting  Mshta
            if EventID[0]=="1" and ( Image[0].strip().find("\\mshta.exe")>-1  ):

                """print("##### " + record["timestamp"] + " #### EventID=1 ### [ T1218.005 ] Detecting  Mshta #### ", end='')
                print(
                    "Found User (" + User[0].strip() + ") Trying to run mshta with Command Line (" + CommandLine[
                        0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )")"""

                Event_desc="Found User (" + User[0].strip() + ") Trying to run mshta with Command Line (" + CommandLine[
                        0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[ T1218.005 ] Mshta found running in the system')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            #Detect Psexec with accepteula flag
            if  EventID[0] == "13" and (
                    TargetObject[0].strip().find("psexec") > -1 ) :
                """print("##### " + row[
                    'Date and Time'] + " #### EventID=13 ### Psexec Detected in the system #### ", end='')
                print(
                    "Found User (" + User[0].strip() + ") Trying to run psexec with process Image :" + Image[0].strip() )"""

                Event_desc="Found User (" + User[0].strip() + ") Trying to run psexec with process Image :" + Image[0].strip()
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('Psexec Detected in the system')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("Critical")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()


            # [T1053] Scheduled Task - Process
            if EventID[0]=="1" and ( Image[0].strip().find("\\taskeng.exe")>-1 or Image[0].strip().find("\\svchost.exe")>-1 ) and ParentImage[0].strip().find("services.exe")==-1 and ParentImage[0].strip().find("?")==-1 :

                """
                print("##### " + record["timestamp"] + " #### EventID=1 ### [T1053] Scheduled Task - Process #### ", end='')
                print(
                    "Found User (" + User[0].strip() + ") Trying to run taskeng.exe or svchost.exe with Command Line (" + CommandLine[
                        0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )")
                """
                Event_desc="Found User (" + User[0].strip() + ") Trying to run taskeng.exe or svchost.exe with Command Line (" + CommandLine[
                        0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )"

                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1053] Scheduled Task manipulation ')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("Medium")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()


            #Prohibited Process connecting to internet
            if EventID[0]=="3" and ( Image[0].strip().find("powershell.exe")>-1 or Image[0].strip().find("mshta.exe")>-1 or Image[0].strip().find("cscript.exe")>-1 or Image[0].strip().find("regsvr32.exe")>-1  or Image[0].strip().find("certutil.exe")>-1 ):
                #temp.append()
                #print("##### " + row[
                #    'Date and Time'] + " #### EventID=3 ### Prohibited Process connecting to internet #### ", end='')
                #print(
                #    "Found User (" + User[0].strip() + ") run process "+Image[0].strip()+" and initiated network connection from hostname ( "+ SourceHostname[0].strip()+" and IP ( "+SourceIp[0].strip() +" ) to hostname ( "+ DestinationHostname[0].strip()+" ) , IP ( " +DestinationIp[0].strip()+" ) and port ( "+DestinationPort[0].strip()+" )")

                Event_desc="User (" + User[0].strip() + ") run process "+Image[0].strip()+" and initiated network connection from hostname ( "+ SourceHostname[0].strip()+" and IP ( "+SourceIp[0].strip() +" ) to hostname ( "+ DestinationHostname[0].strip()+" ) , IP ( " +DestinationIp[0].strip()+" ) and port ( "+DestinationPort[0].strip()+" )"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('Prohibited Process connecting to internet')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("Critical")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            #Detecting WMI attacks
            if EventID[0]=="1" and ( ParentCommandLine[0].strip().find("WmiPrvSE.exe")>-1 or Image[0].strip().find("WmiPrvSE.exe")>-1 ):

                Event_desc="User (" + User[0].strip() + ") run command through WMI with process ("+Image[0].strip()+ ") and commandline ( "+CommandLine[
                        0].strip() +" )"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('Command run remotely Using WMI')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("Critical")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            #Detecting IIS/Exchange Exploitation
            if EventID[0]=="1" and ( ParentCommandLine[0].strip().find("w3wp.exe")>-1  ):

                Event_desc="IIS run command with user (" + User[0].strip() + ") and process name ("+Image[0].strip()+ ") and commandline ( "+CommandLine[
                        0].strip() +" )"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('Detect IIS/Exchange Exploitation')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("Critical")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [T1082] System Information Discovery
            if EventID[0]=="1" and ( CommandLine[0].strip().find("sysinfo.exe")>-1 or Image[0].strip().find("sysinfo.exe")>-1 or CommandLine[0].strip().find("whoami.exe")>-1 or Image[0].strip().find("whoami.exe")>-1 ):

                Event_desc="System Information Discovery Process ( %s) ith commandline ( %s) "%(Image[0],CommandLine[0])
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1082] System Information Discovery')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("Critical")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            #  [T1117] Bypassing Application Whitelisting
            if EventID[0]=="1" and ( Image[0].strip().find("regsvr32.exe")>-1 or Image[0].strip().find("rundll32.exe")>-1 or Image[0].strip().find("certutil.exe")>-1 ):

                Event_desc="[T1117] Bypassing Application Whitelisting , Process ( %s) with commandline ( %s)"%(Image[0],CommandLine[0])
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1117] Bypassing Application Whitelisting')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [T1055] Process Injection
            if EventID[0]=="8" and ( StartFunction[0].strip().lower().find("loadlibrary")>-1  ):

                Event_desc="Process ( %s) attempted process injection on process ( %s)"%(SourceImage,TargetImage)
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1055] Process Injection')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("Critical")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [T1003.001] Credential dump Thread Open to Lsass
            if EventID[0]=="8" and ( TargetImage[0].strip().lower().find("lsass.exe")>-1  ):

                Event_desc="Process ( %s) attempted to access lsass process ( %s)"%(SourceImage[0],TargetImage[0])
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1003.001] Credential dump Thread Open to Lsass')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("Critical")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [T0000] Console History
            if EventID[0]=="1" and ( CommandLine[0].strip().find("get-history")>-1 or
                                    CommandLine[0].strip().find("appdata\\roaming\\microsoft\\windows\\powershell\\psreadline\\consolehost_history.txt")>-1 or
                                    CommandLine[0].strip().find("(get-psreadlineoption).historysavepath")>-1 ):

                Event_desc="Found User (" + User[0].strip() + ") through process name ("+Image[0].strip()+ ") tried accessing powershell history through commandline ( "+CommandLine[0].strip() +" )"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T0000] Console History')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("Medium")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()


            # [ T0000 ] Remotely Query Login Sessions - Network
            if EventID[0]=="3" and Image[0].strip().find("qwinsta.exe")>-1:

                Event_desc="Found User (" + User[0].strip() + ") Trying to run query login session through network using Command Line (" + CommandLine[0].strip() + ")"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[  T0000 ] Remotely Query Login Sessions - Network')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [ T0000 ] Remotely Query Login Sessions - Process
            if EventID[0]=="3" and Image[0].strip().find("qwinsta.exe")>-1:

                Event_desc="Found User (" + User[0].strip() + ") Trying to run query login session Command Line (" + CommandLine[0].strip() + ")"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[  T0000 ] Remotely Query Login Sessions - Process')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [ T0000 ] Suspicious process name detected
            if EventID[0]=="1":

                #detect suspicious process
                for sProcessName in Suspicious_executables:

                    if CommandLine[0].lower().find(sProcessName.lower())>-1:
                        lock.acquire()
                        Event_desc ="User Name : ( %s ) " % User[0].strip()+"with Command Line : ( " + CommandLine[0].strip() + " ) contain suspicious command ( %s)"%sProcessName
                        Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Sysmon_events[0]['Computer Name'].append(Computer[0])
                        Sysmon_events[0]['Channel'].append(Channel[0])
                        Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Sysmon_events[0]['Detection Rule'].append("[ T0000 ] Suspicious process name detected")
                        Sysmon_events[0]['Detection Domain'].append("Threat")
                        Sysmon_events[0]['Severity'].append("High")
                        Sysmon_events[0]['Event Description'].append(Event_desc)
                        Sysmon_events[0]['Event ID'].append(EventID[0])
                        Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                        lock.release()

            #[  T1002 ] Data Compressed
            if EventID[0]=="1" and ((Image[0].strip().find("powershell.exe")>-1 and CommandLine[0].find("-recurse | compress-archive")>-1) or (Image[0].strip().find("rar.exe")>-1 and CommandLine[0].find("rar*a*")>-1)):
                lock.acquire()
                Event_desc="Found User (" + User[0].strip() + ") trying to compress data using (" + Image[0].strip() + ") with Command Line (" + CommandLine[0].strip() + ")"
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])

                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['Detection Rule'].append("[  T1002 ] Data Compressed")
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("Medium")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                lock.release()
            #[  T1003 ] Credential Dumping ImageLoad
            if EventID[0]=="7" and ((ImageLoaded[0].strip().find("\\samlib.dll")>-1 or
                                     ImageLoaded[0].strip().find("\\winscard.dll")>-1 or
                                     ImageLoaded[0].strip().find("\\cryptdll.dll")>-1 or
                                     ImageLoaded[0].strip().find("\\hid.dll")>-1 or
                                     ImageLoaded[0].strip().find("\\vaultcli.dll")>-1) and
                                    (Image[0].strip().find("\\sysmon.exe")==-1 and
                                     Image[0].strip().find("\\svchost.exe")==-1 and
                                     Image[0].strip().find("\\logonui.exe")==-1)):

                try:
                    Event_desc="Found User (" + User[0].strip() + ") through process name ("+Image[0].strip()+ ") tried loading credential dumping image ( "+ImageLoaded[0].strip() +" )"
                except:
                    Event_desc="[  T1003 ] Credential Dumping ImageLoad"
                lock.acquire()
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])

                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['Detection Rule'].append("[  T1003 ] Credential Dumping ImageLoad")
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("Medium")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                lock.release()
            # [T1003] Credential Dumping - Process
            if EventID[0]=="1" and (
                CommandLine[0].strip().find("Invoke-Mimikatz -DumpCreds")>-1 or
                CommandLine[0].strip().find("gsecdump -a")>-1 or
                CommandLine[0].strip().find("wce -o")>-1 or
                CommandLine[0].strip().find("procdump -ma lsass.exe")>-1 or
                CommandLine[0].strip().find("ntdsutil*ac i ntds*ifm*create full")>-1):
                try:
                    Event_desc="Found User (" + User[0].strip() + ") through process name ("+Image[0].strip()+ ") tried dumping credentials through commandline ( "+CommandLine[0].strip() +" )"
                except:
                    Event_desc="[T1003] Credential Dumping - Process"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1003] Credential Dumping - Process')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [T1003] Credential Dumping - Process Access

            if EventID[0]=="10" and TargetImage[0].strip().find("\\lsass.exe")>-1 and (
                GrantedAccess[0].strip().find("0x1010")>-1 or
                GrantedAccess[0].strip().find("0x1410")>-1 or
                GrantedAccess[0].strip().find("0x147a")>-1 or
                GrantedAccess[0].strip().find("0x143a")>-1 or
                GrantedAccess[0].strip().find("0x1fffff")>-1) and (
                CallTrace[0].strip().find("\\ntdll.dll")>-1 and (
                CallTrace[0].strip().find("\\kernelbase.dll")>-1 or CallTrace[0].strip().find("\\kernel32.dll")>-1)):
                #print(User[0].strip())
                try:
                    Event_desc="Found User (" + User[0].strip() + ") accessed target image ("+TargetImage[0].strip()+ ") through source image ( "+ SourceImage[0].strip() +" )"
                except:
                    Event_desc="[T1003] Credential Dumping - Process Access"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1003] Credential Dumping - Process Access')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [T1003] Credential Dumping - Registry
            if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") and Image[0].strip().find("\\lsass.exe")==-1 and (
                TargetObject[0].strip().find("\\software\\microsoft\\windows\\currentversion\\authentication\\credential provider\\")>-1 or
                TargetObject[0].strip().find("\\system\\currentcontrolset\\control\\ssa\\")>-1 or
                TargetObject[0].strip().find("\\system\\currentcontrolset\\control\\securityproviders\\securityproviders\\")>-1 or
                TargetObject[0].strip().find("\\control\\securityrroviders\\wdigest\\")>-1):
                try:

                    Event_desc="Found User (" + User[0].strip() + ") accessed target image ("+TargetImage[0].strip()+ ") through source image ( "+ SourceImage[0].strip() +" )"
                except:
                    Event_desc="[T1003] Credential Dumping - Registry"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1003] Credential Dumping - Registry')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [T1003] Credential Dumping - Registry Save
            if (EventID[0]=="1") and Image[0].strip().find("reg.exe")==-1 and (
                CommandLine[0].strip().find("*save*HKLM\\sam*")>-1 or
                CommandLine[0].strip().find("*save*HKLM\\system*")>-1):
                try:
                    Event_desc="Found User (" + User[0].strip() + ") Tried to dump registry "+CommandLine[0]+ SourceImage[0].strip() +" )"
                except:
                    Event_desc="[T1003] Credential Dumping - Registry Save"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1003] Credential Dumping - Registry Save')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [T1004] Winlogon Helper DLL
            if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") and (
                TargetObject[0].strip().find("\\software\\microsoft\\windows nt\\currentversion\\winlogon\\user_nameinit\\")>-1 or
                TargetObject[0].strip().find("\\software\\microsoft\\windows nt\\currentversion\\winlogon\\shell\\")>-1 or
                TargetObject[0].strip().find("\\software\\microsoft\\windows nt\\currentversion\\winlogon\\notify\\")>-1):
                try:
                    Event_desc="Found User (" + User[0].strip() + ") accessed target image ("+TargetImage[0].strip()+ ") through source image ( "+ SourceImage[0].strip() +" )"
                except:
                    Event_desc="[T1004] Winlogon Helper DLL"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1004] Winlogon Helper DLL')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [T1004] Winlogon Helper DLL
            if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") and (
                TargetObject[0].strip().find("\\software\\microsoft\\windows nt\\currentversion\\winlogon\\user_nameinit\\")>-1 or
                TargetObject[0].strip().find("\\software\\microsoft\\windows nt\\currentversion\\winlogon\\shell\\")>-1 or
                TargetObject[0].strip().find("\\software\\microsoft\\windows nt\\currentversion\\winlogon\\notify\\")>-1):
                try:
                    Event_desc="Found User (" + User[0].strip() + ") accessed target image ("+TargetImage[0].strip()+ ") through source image ( "+ SourceImage[0].strip() +" )"
                except:
                    Event_desc="[T1004] Winlogon Helper DLL"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1004] Winlogon Helper DLL')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [ T1007 ] System Service Discovery
            #if EventID[0]=="1" and ((Image[0].strip().find("net.exe")>-1 or
            #                         Image[0].strip().find("tasklist.exe")>-1 or
            #                         Image[0].strip().find("sc.exe")>-1 or
            #                         Image[0].strip().find("wmic.exe")>-1) and
            #                         CommandLine[0].find("-recurse | compress-archive")>-1) ):

            #    Event_desc="Found User (" + User[0].strip() + ") trying to compress data using (" + Image[0].strip() + ") with Command Line (" + CommandLine[0].strip() + ")"
            #    Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
            #    Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
            #    Security_events[0]['Detection Rule'].append("[ T1007 ] System Service Discovery")
            #    Security_events[0]['Detection Domain'].append("Threat")
            #    Security_events[0]['Severity'].append("Medium")
            #    Security_events[0]['Event Description'].append(Event_desc)
            #    Security_events[0]['Event ID'].append(EventID[0])
            #    Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))

            # [T1223] Compiled HTML File
            if (EventID[0]=="1") and Image[0].strip().find("\\hh.exe")>-1:

                try:
                    Event_desc="Found User (" + User[0].strip() + ") running image ( "+ Image[0].strip() +" )"
                except:
                    Event_desc="[T1223] Compiled HTML File"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1223] Compiled HTML File')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [T1218] Signed Binary Proxy Execution - Process
            if (EventID[0]=="1") and (CommandLine[0].strip().find("mavinject*\\/injectrunning")>-1 or
                                    CommandLine[0].strip().find("mavinject32*\\/injectrunning*")>-1 or
                                    CommandLine[0].strip().find("*certutil*script\\:http\\[\\:\\]\\/\\/*")>-1 or
                                    CommandLine[0].strip().find("*certutil*script\\:https\\[\\:\\]\\/\\/*")>-1 or
                                    CommandLine[0].strip().find("*msiexec*http\\[\\:\\]\\/\\/*")>-1 or
                                    CommandLine[0].strip().find("*msiexec*https\\[\\:\\]\\/\\/*")>-1):
                try:
                    Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                except:
                    Event_desc="[T1218] Signed Binary Proxy Execution - Process"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1218] Signed Binary Proxy Execution - Process')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [T1218] Signed Binary Proxy Execution - Process
            if (EventID[0]=="1") and (CommandLine[0].strip().find("mavinject*\\/injectrunning")>-1 or
                                    CommandLine[0].strip().find("mavinject32*\\/injectrunning*")>-1 or
                                    CommandLine[0].strip().find("*certutil*script\\:http\\[\\:\\]\\/\\/*")>-1 or
                                    CommandLine[0].strip().find("*certutil*script\\:https\\[\\:\\]\\/\\/*")>-1 or
                                    CommandLine[0].strip().find("*msiexec*http\\[\\:\\]\\/\\/*")>-1 or
                                    CommandLine[0].strip().find("*msiexec*https\\[\\:\\]\\/\\/*")>-1):
                try:
                    Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                except:
                    Event_desc="[T1218] Signed Binary Proxy Execution - Process"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1218] Signed Binary Proxy Execution - Process')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()


            # [T1218] Signed Binary Proxy Execution - Network
            if (EventID[0] == "3") and len(CommandLine)>0 and (Image[0].strip().find("certutil.exe")>-1 or
                                    CommandLine[0].strip().find("*certutil*script\\:http\\[\\:\\]\\/\\/*")>-1 or
                                    Image[0].strip().find("*\\replace.exe")>-1):

                try:
                    Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                except:
                    Event_desc="[T1218] Signed Binary Proxy Execution - Network"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1218] Signed Binary Proxy Execution - Network')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [T1216] Signed Script Proxy Execution
            #if (EventID[0]=="1") and (CommandLine[0].strip().find("*firefox*places.sqlite*")>-1):

            #    Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) trying to discover browser bookmark"
            #    lock.release()
                    #Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
            #    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                #Sysmon_events[0]['Computer Name'].append(Computer[0])
                #Sysmon_events[0]['Channel'].append(Channel[0])
            #    Sysmon_events[0]['Detection Rule'].append('[T1216] Signed Script Proxy Execution')
            #    Sysmon_events[0]['Detection Domain'].append("Threat")
            #    Sysmon_events[0]['Severity'].append("High")
            #    Sysmon_events[0]['Event Description'].append(Event_desc)
            #    Sysmon_events[0]['Event ID'].append(EventID[0])
            #    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))


            # [T1214] Credentials in Registry
            if (EventID[0]=="1") and (CommandLine[0].strip().find("*certutil*script\\:http\\[\\:\\]\\/\\/*")>-1 or
                                    CommandLine[0].strip().find("reg query HKCU \\/f password \\/t REG_SZ \\/s")>-1 or
                                    CommandLine[0].strip().find("Get-UnattendedInstallFile")>-1 or
                                    CommandLine[0].strip().find("Get-Webconfig")>-1 or
                                    CommandLine[0].strip().find("Get-ApplicationHost")>-1 or
                                    CommandLine[0].strip().find("Get-SiteListPassword")>-1 or
                                    CommandLine[0].strip().find("Get-CachedGPPPassword")>-1 or
                                    CommandLine[0].strip().find("Get-RegistryAutoLogon")>-1):
                try:
                    Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) to access credentials"
                except:
                    Event_desc="[T1214] Credentials in Registry"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1214] Credentials in Registry')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [T1209] Boot or Logon Autostart Execution: Time Providers
            if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") and (
                TargetObject[0].strip().find("\\system\\currentcontrolset\\services\\w32time\\timeproviders\\")>-1):
                try:
                    Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) to hijack time provider"
                except:
                    Event_desc="[T1209] Boot or Logon Autostart Execution: Time Providers"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1209] Boot or Logon Autostart Execution: Time Providers')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [T1202] Indirect Command Execution
            if EventID[0]=="1":
                Event_desc=''
                if ParentImage[0].strip().find("pcalua.exe")>-1:
                    Event_desc="Found User (" + User[0].strip() + ") through process name ("+ParentImage[0].strip()+ ") tried indirect command execution through commandline ( "+CommandLine[0].strip() +" )"

                if (Image[0].strip().find("pcalua.exe")>-1 or
                    Image[0].strip().find("bash.exe")>-1 or
                    Image[0].strip().find("forfiles.exe")>-1):
                    Event_desc="Found User (" + User[0].strip() + ") through process name ("+Image[0].strip()+ ") tried accessing powershell history through commandline ( "+CommandLine[0].strip() +" )"
                if Event_desc!='':
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1202] Indirect Command Execution')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("Medium")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            # [T1201] Password Policy Discovery
            if (EventID[0]=="1") :
                if (CommandLine[0].strip().find("net accounts")>-1 or CommandLine[0].strip().find("net accounts \\/domain")>-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) tried discovering password policy through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1201] Password Policy Discovery"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1201] Password Policy Discovery')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            # [T1197] BITS Jobs - Process
            if (EventID[0]=="1") :
                if (Image[0].strip().find("bitsamin.exe")>-1 or CommandLine[0].strip().find("Start-BitsTransfer")>-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1197] BITS Jobs - Process"

                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1197] BITS Jobs - Process')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            # [T1197] BITS Jobs - Network
            if (EventID[0]=="3") :
                if (Image[0].strip().find("bitsadmin.exe")>-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1197] BITS Jobs - Network"
                    lock.release()
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1197] BITS Jobs - Network')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            # [T1196] Control Panel Items - Registry
            if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") :
                if (
                TargetObject[0].strip().find("\\software\\microsoft\\windows\\currentversion\\explorer\\controlpanel\\namespace")>-1 or
                TargetObject[0].strip().find("\\software\\microsoft\\windows\\currentversion\\controls folder\\*\\shellex\\propertysheethandlers\\")>-1 or
                TargetObject[0].strip().find("\\software\\microsoft\\windows\\currentversion\\control panel\\")>-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) modifying registry control panel items"
                    except:
                        Event_desc="[T1196] Control Panel Items - Registry"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1196] Control Panel Items - Registry')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            # [T1196] Control Panel Items - Process
            if (EventID[0]=="1") :
                if (CommandLine[0].strip().find("control \\/name")>-1 or
                                    CommandLine[0].strip().find("rundll32 shell32.dll,Control_RunDLL")>-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " to acess control panel)"
                    except:
                        Event_desc="[T1196] Control Panel Items - Process"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1196] Control Panel Items - Process')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            # [T1191] Signed Binary Proxy Execution: CMSTP
            if (EventID[0]=="1") :
                if (Image[0].strip().find("CMSTP.exe")>-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " )"
                    except:
                        Event_desc="[T1191] Signed Binary Proxy Execution: CMSTP"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1191] Signed Binary Proxy Execution: CMSTP')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            # [T1183] Image File Execution Options Injection
            if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") :
                if (
                TargetObject[0].strip().find("\\software\\microsoft\\windows nt\\currentversion\\image file execution options\\")>-1 or
                TargetObject[0].strip().find("\\wow6432node\\microsoft\\windows nt\\currentversion\\image file execution options\\")>-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") accessed target image ("+TargetImage[0].strip()+ ") through source image ( "+ SourceImage[0].strip() +" )"
                    except:
                        Event_desc="[T1183] Image File Execution Options Injection"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1183] Image File Execution Options Injection')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            # [T1182] AppCert DLLs Registry Modification
            if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") :
                if (
                TargetObject[0].strip().find("\\system\\currentcontrolset\\control\\session manager\\appcertdlls\\")>-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") accessed target image ("+TargetImage[0].strip()+ ") through source image ( "+ SourceImage[0].strip() +" )"
                    except:
                        Event_desc="[T1182] AppCert DLLs Registry Modification"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1182] AppCert DLLs Registry Modification')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            # [T1180] Screensaver Hijack
            if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") :
                if (
                TargetObject[0].strip().find("*\\control panel\\desktop\\scrnsave.exe")>-1) and (
                    ParentCommandLine[0].strip().find("explorer.exe")==-1 or
                    Image[0].strip().find("rundll32.exe")==-1 or
                    CommandLine[0].strip().find("*shell32.dll,Control_RunDLL desk.cpl,ScreenSaver,*")==-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") accessed target image ("+TargetImage[0].strip()+ ")"
                    except:
                        Event_desc="[T1180] Screensaver Hijack"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1180] Screensaver Hijack')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("Medium")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            # [T1179] Hooking detected
            if (EventID[0]=="1") :
                if (Image[0].strip().find("mavinject.exe")>-1 or CommandLine[0].strip().find("/INJECTRUNNING")>-1):
                    try:

                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1179] Hooking detected"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1179] Hooking detected')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1170] Detecting  Mshta - Process
            if EventID[0]=="1" :
                if ( Image[0].strip().find("\\mshta.exe")>-1 or CommandLine[0].strip().find("\\mshta.exe")>-1 ):

                    try:

                        Event_desc="Found User (" + User[0].strip() + ") Trying to run mshta with Command Line (" + CommandLine[0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )"
                    except:
                        Event_desc="[T1170] Detecting Mshta Exection "
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1170] Detecting  Mshta')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1170] Detecting  Mshta - Network
            if EventID[0]=="3" :
                if  (len(CommandLine)>0 and len(ParentCommandLine)>0) and( ParentCommandLine[0].strip().find("\\mshta.exe")>-1 or CommandLine[0].strip().find("\\mshta.exe")>-1 ):

                    try:

                        Event_desc="Found User (" + User[0].strip() + ") Trying to run mshta with Command Line (" + CommandLine[0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )"
                    except:
                        Event_desc="[T1170] Detecting  Mshta"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1170] Detecting  Mshta')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1158] Hidden Files and Directories - VSS
            if EventID[0]=="1" and ( Image[0].strip().find("*\\volumeshadowcopy*\\*")>-1 or CommandLine[0].strip().find("*\\volumeshadowcopy*\\*")>-1 ):

                Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) accessing volume shadow copy hidden files and directories"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1158] Hidden Files and Directories - VSS')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            #  [T1158] Hidden Files and Directories
            if EventID[0]=="1" and ( Image[0].strip().find("attrib.exe")>-1 and (CommandLine[0].strip().find("+h")>-1 or CommandLine[0].strip().find("+s")>-1) ):

                Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) accessing hidden files and directories"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1158] Hidden Files and Directories')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [T1146] Clear Command History
            if EventID[0]=="1" and ( CommandLine[0].strip().find("*rm (Get-PSReadlineOption).HistorySavePath*")>-1 or
                                    CommandLine[0].strip().find("*del (Get-PSReadlineOption).HistorySavePath*")>-1 or
                                    CommandLine[0].strip().find("*Set-PSReadlineOption –HistorySaveStyle SaveNothing*")>-1 or
                                    CommandLine[0].strip().find("*Remove-Item (Get-PSReadlineOption).HistorySavePath*")>-1 ):

                Event_desc="Found User (" + User[0].strip() + ") through process name ("+Image[0].strip()+ ") tried clearing powershell history through commandline ( "+CommandLine[0].strip() +" )"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1146] Clear Command History')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("Medium")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            #  [T1140] Deobfuscate/Decode Files or Information
            if EventID[0]=="1" and ( Image[0].strip().find("certutil.exe")>-1 and (CommandLine[0].strip().find("decode")>-1) ):

                Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) tried decoding file or information"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1140] Deobfuscate/Decode Files or Information')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [T1138] Application Shimming - Registry
            if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") and (
                TargetObject[0].strip().find("\\software\\microsoft\\windows nt\\currentversion\\appcompatflags\\installedsdb\\")>-1):

                Event_desc="Found User (" + User[0].strip() + ") accessed target image ("+TargetImage[0].strip()+ ") through source image ( "+ SourceImage[0].strip() +" ) shimming application through registry"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1138] Application Shimming - Registry')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [T1138] Application Shimming - process
            if (EventID[0]=="1") and (Image[0].strip().find("sdbinst.exe")>-1):
                try:
                    Event_desc="Found User (" + User[0].strip() + ") accessed target image ("+TargetImage[0].strip()+ ") through source image ( "+ SourceImage[0].strip() +" ) shimming application through process"
                except:
                    Event_desc="[T1138] Application Shimming - process , please check raw log"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1138] Application Shimming - process')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [T1136] Create Account
            if EventID[0]=="1" and ( CommandLine[0].strip().find("New-LocalUser")>-1 or
                                    CommandLine[0].strip().find("net user add")>-1 ):

                Event_desc="Found User (" + User[0].strip() + ") through process name ("+Image[0].strip()+ ") tried creating user through commandline ( "+CommandLine[0].strip() +" )"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1136] Create Account')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("Medium")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            #  [T1135] Network Share Discovery - Process
            if EventID[0]=="1" and ( Image[0].strip().find("net.exe")>-1 and
                                   ( CommandLine[0].strip().find("net view")>-1 or
                                     CommandLine[0].strip().find("net share")>-1 or
                                     CommandLine[0].strip().find("get-smbshare -Name")>-1)):

                Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) tried discovering network share through process"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1135] Network Share Discovery - Process')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [T1131] Authentication Package
            if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") and (
                TargetObject[0].strip().find("*\\system\\currentcontrolset\\control\\lsa\\*")>-1 and (
                Image[0].strip().find("c:\\windows\\system32\\lsass.exe")==-1 or
                Image[0].strip().find("c:\\windows\\system32\\svchost.exe")==-1 or
                Image[0].strip().find("c:\\windows\\system32\\services.exe")==-1)):

                Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) to access authentication services by modifying registry"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1131] Authentication Package')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            # [T1130]  Install Root Certificate
            if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") and (
                Image[0].strip().find("c:\\windows\\system32\\lsass.exe")==-1 and (
                TargetObject[0].strip().find("*\\software\\microsoft\\enterprisecertificates\\root\\certificates\\*")>-1 or
                TargetObject[0].strip().find("*\\microsoft\\systemcertificates\\root\\certificates\\*")>-1)):

                Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) tried to install root certificates"
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1130]  Install Root Certificate')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            #  [T1128] Netsh Helper DLL - Process
            if EventID[0]=="1" and ( Image[0].strip().find("netsh.exe")>-1 and (CommandLine[0].strip().find("*helper*")>-1) ):

                Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + ") "
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1128] Netsh Helper DLL - Process')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            #  [T1128] Netsh Helper DLL - Registry
            if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") and (
                TargetObject[0].strip().find("*\\software\\microsoft\\netsh\\*")>-1):

                Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + ") "
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1128] Netsh Helper DLL - Registry')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()

            #  [T1127] Trusted Developer Utilities
            if EventID[0]=="1" and ( Image[0].strip().find("msbuild.exe")>-1 or Image[0].strip().find("msxsl.exe")>-1 ):

                Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + ") "
                lock.acquire()
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                Sysmon_events[0]['Computer Name'].append(Computer[0])
                Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1127] Trusted Developer Utilities')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
                Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                lock.release()


#######################################

            #  [T1126] Network Share Connection Removal
            if EventID[0]=="1" :
                if ( Image[0].strip().find("net.exe")>-1 and
                                       ( CommandLine[0].strip().find("net view")>-1 or
                                         CommandLine[0].strip().find("remove-smbshare")>-1 or
                                         CommandLine[0].strip().find("remove-fileshare")>-1)):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) to delete network share"
                    except:
                        Event_desc="Found User trying to delete network share"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1126] Network Share Connection Removal')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1124] System Time Discovery
            try:
                if EventID[0]=="1":
                    if  ( Image[0].strip().find("*\\net.exe")>-1 and CommandLine[0].strip().find("*net* time*")>-1 ) or (
                                             Image[0].strip().find("w32tm.exe")>-1 and CommandLine[0].strip().find("*get-date*")>-1 ):
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) to alter system time"
                        lock.release()
                        Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Sysmon_events[0]['Computer Name'].append(Computer[0])
                        Sysmon_events[0]['Channel'].append(Channel[0])
                        Sysmon_events[0]['Detection Rule'].append('[T1124] System Time Discovery')
                        Sysmon_events[0]['Detection Domain'].append("Threat")
                        Sysmon_events[0]['Severity'].append("High")
                        Sysmon_events[0]['Event Description'].append(Event_desc)
                        Sysmon_events[0]['Event ID'].append(EventID[0])
                        Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                        lock.release()
            except:
                print("issue with event : \n"+str(record['data']))
            #  [T1115] Audio Capture
            if EventID[0]=="1" :

                if ( Image[0].strip().find("soundrecorder.exe")>-1 and ( CommandLine[0].strip().find("*get-audiodevice*")>-1 or CommandLine[0].strip().find("*windowsaudiodevice-powershell-cmdlet*")>-1 ) ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) to capture audio"
                    except:
                        Event_desc="Found User trying to capture audio"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1115] Audio Capture')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1122] Component Object Model Hijacking
            if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") :
                if TargetObject[0].strip().find("\\Software\\Classes\\CLSID\\")>-1:
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + ") to hijack COM"
                    except:
                        Event_desc="Found User trying to hijack COM"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1122] Component Object Model Hijacking')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1121] Regsvcs/Regasm
            if EventID[0]=="1":
                if ( Image[0].strip().find("regsvcs.exe")>-1 or Image[0].strip().find("regasm.exe")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1121] Regsvcs/Regasm execution"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1121] Regsvcs/Regasm')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1118] InstallUtil
            if EventID[0]=="1" :
                if ( Image[0].strip().find("installutil.exe")>-1 and ( CommandLine[0].strip().find("\\/logfile= \\/LogToConsole=false \\/U")>-1 ) ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1118] InstallUtil Execution"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1118] InstallUtil')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1117] Regsvr32
            if EventID[0]=="1" :
                if ( ParentImage[0].strip().find("\\regsvr32.exe")>-1 or Image[0].strip().find("\\regsvr32.exe")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1117] Regsvr32 Execution"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1117] Regsvr32')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1117] Bypassing Application Whitelisting
            if EventID[0]=="1" :
                if ( Image[0].strip().find("regsvr32.exe")>-1 or Image[0].strip().find("rundll32.exe")>-1 or Image[0].strip().find("certutil.exe")>-1 ) or ( CommandLine[0].strip().find("scrobj.dll")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1117] Bypassing Application Whitelisting "
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1117] Bypassing Application Whitelisting with Regsvr32,rundll32,certutil or scrobj ')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1115] Clipboard Data
            if EventID[0]=="1" :
                if ( Image[0].strip().find("clip.exe")>-1 or CommandLine[0].strip().find("*Get-Clipboard*")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1115] Clipboard Data Collection "
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1115] Clipboard Data Collection')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            # [T1107] Indicator Removal on Host
            if (EventID[0]=="1") :
                if (CommandLine[0].strip().find("*remove-item*")>-1 or
                                    CommandLine[0].strip().find("vssadmin*Delete Shadows /All /Q*")>-1 or
                                    CommandLine[0].strip().find("*wmic*shadowcopy delete*")>-1 or
                                    CommandLine[0].strip().find("*wbdadmin* delete catalog -q*")>-1 or
                                    CommandLine[0].strip().find("*bcdedit*bootstatuspolicy ignoreallfailures*")>-1 or
                                    CommandLine[0].strip().find("*bcdedit*recoveryenabled no*")>-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) to delete file"
                    except:
                        Event_desc="[T1115] Indicator Removal on Host "
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1107] Indicator Removal on Host')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            # [T1103]  AppInit DLLs Usage
            if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") :
                if (
                TargetObject[0].strip().find("\\software\\microsoft\\windows nt\\currentversion\\windows\\appinit_dlls\\")>-1 or
                TargetObject[0].strip().find("\\software\\wow6432node\\microsoft\\windows nt\\currentversion\\windows\\appinit_dlls\\")>-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1103]  AppInit DLLs Usage"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append(' [T1103]  AppInit DLLs Usage')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

##############################################reached
            #  [T1096] Hide Artifacts: NTFS File Attributes
            if EventID[0]=="1" :
                if ( Image[0].strip().find("fsutil.exe")>-1 or
                                     CommandLine[0].strip().find("*usn*deletejournal*")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1096] Hide Artifacts: NTFS File Attributes"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1096] Hide Artifacts: NTFS File Attributes')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            # [T1088] Bypass User Account Control - Registry
            if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") :
                if (
                TargetObject[0].strip().find("*\\mscfile\\shell\\open\\command\\*")>-1 or
                TargetObject[0].strip().find("*\\ms-settings\\shell\\open\\command\\*")>-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1088] Bypass User Account Control - Registry"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1088] Bypass User Account Control - Registry')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1088] Bypass User Account Control - Process
            if EventID[0]=="1" :
                if ( Image[0].strip().find("ShellRunas.exe")>-1 or
                                     ParentCommandLine[0].strip().find("eventvwr.exe")>-1 or
                                     ParentCommandLine[0].strip().find("fodhelper.exe")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1088] Bypass User Account Control - Process"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1088] Bypass User Account Control - Process')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1087] Account Discovery
            if EventID[0]=="1" :
                if ( Image[0].strip().find("net.exe")>-1 or
                                     Image[0].strip().find("powershell.exe")>-1 ) and (
                                     CommandLine[0].strip().find("*net* user*")>-1 or
                                     CommandLine[0].strip().find("*net* group*")>-1 or
                                     CommandLine[0].strip().find("*net* localgroup*")>-1 or
                                     CommandLine[0].strip().find("cmdkey*\\/list*")>-1 or
                                     CommandLine[0].strip().find("*get-localgroupmembers*")>-1 or
                                     CommandLine[0].strip().find("*get-localuser*")>-1 or
                                     CommandLine[0].strip().find("*get-aduser*")>-1 or
                                     CommandLine[0].strip().find("query*user*")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1087] Account Discovery"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1087] Account Discovery')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1086] PowerShell Downloads - Process
            if EventID[0]=="1" :
                if ( ParentCommandLine[0].strip().find("*.Download*")>-1 or
                                     ParentCommandLine[0].strip().find("*Net.WebClient*")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1086] PowerShell Downloads - Process"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1086] PowerShell Downloads - Process')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1086] PowerShell Process found
            if EventID[0]=="1" :
                if ( Image[0].strip().find("powershell.exe")>-1 or
                                     Image[0].strip().find("powershell_ise.exe")>-1  ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1086] PowerShell Process found "
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1086] PowerShell Process found')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1085] Rundll32 Execution detected
            if EventID[0]=="1" :
                if ( Image[0].strip().find("\\rundll32.exe")>-1 or
                                     Image[0].strip().find("rundll32.exe")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1085] Rundll32 Execution detected"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1085] Rundll32 Execution detected')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1082] System Information Discovery
            if EventID[0]=="1" :
                if ( Image[0].strip().find("sysinfo.exe")>-1 or
                                     Image[0].strip().find("reg.exe")>-1 ) and CommandLine[0].strip().find("reg*query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum")>-1:
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc='[T1082] System Information Discovery'
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1082] System Information Discovery')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1081] Credentials in Files
            if EventID[0]=="1" :
                if ( CommandLine[0].strip().find("*findstr* /si pass*")>-1 or
                                     CommandLine[0].strip().find("*select-string -Pattern pass*")>-1 or
                                     CommandLine[0].strip().find("*list vdir*/text:password*")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1081] Credentials in Files"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1081] Credentials in Files')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1077] Windows Admin Shares - Process - Created
            if EventID[0]=="1" :
                if ( Image[0].strip().find("net.exe")>-1 or
                                     CommandLine[0].strip().find("net share")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1077] Windows Admin Shares - Process - Created"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1077] Windows Admin Shares - Process - Created')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1077] Windows Admin Shares - Process
            if EventID[0]=="1" :
                if ( Image[0].strip().find("net.exe")>-1 or
                                     Image[0].strip().find("powershell.exe")>-1 ) and  (
                                     CommandLine[0].strip().find("*net* use*$")>-1 or
                                     CommandLine[0].strip().find("*net* session*$")>-1 or
                                     CommandLine[0].strip().find("*net* file*$")>-1 or
                                     CommandLine[0].strip().find("*New-PSDrive*root*")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1077] Windows Admin Shares - Process"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1077] Windows Admin Shares - Process')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1077] Windows Admin Shares - Network
            if EventID[0]=="1" :
                if ( Image[0].strip().find("net.exe")>-1 ) and  (
                                     CommandLine[0].strip().find("use")>-1 or
                                     CommandLine[0].strip().find("session")>-1 or
                                     CommandLine[0].strip().find("file")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1077] Windows Admin Shares - Network"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1077] Windows Admin Shares - Network')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            # [T1076] Remote Desktop Protocol - Process
            if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") :
                if ( Image[0].strip().find("logonui.exe")>-1 or TargetObject[0].strip().find("\\software\\policies\\microsoft\\windows nt\\terminal services\\")>-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1076] Remote Desktop Protocol - Process"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1076] Remote Desktop Protocol - Process')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            # [T1076] Remote Desktop Protocol - Registry
            if EventID[0]=="1" :
                if ( Image[0].strip().find("tscon.exe")>-1 or
                                     Image[0].strip().find("mstsc.exe")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1076] Remote Desktop Protocol - Registry"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1076] Remote Desktop Protocol - Registry')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1074] Data Staged - Process
            if EventID[0]=="1" :
                if ( CommandLine[0].strip().find("DownloadString")>-1 or
                                     CommandLine[0].strip().find("Net.WebClient")>-1 ) and (
                                     CommandLine[0].strip().find("New-Object")>-1 or
                                     CommandLine[0].strip().find("IEX")>-1 ):
                    try:

                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1074] Data Staged - Process"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1074] Data Staged - Process')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1070] Indicator removal on host
            if EventID[0]=="1" :
                if ( Image[0].strip().find("wevtutil")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1070] Indicator removal on host"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1070] Indicator removal on host')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1069] Permission Groups Discovery - Process
            if EventID[0]=="1" :
                if ( Image[0].strip().find("net.exe")>-1 ) and  (
                                     CommandLine[0].strip().find("*net* user*")>-1 or
                                     CommandLine[0].strip().find("*net* group*")>-1 or
                                     CommandLine[0].strip().find("*net* localgroup*")>-1 or
                                     CommandLine[0].strip().find("*get-localgroup*")>-1 or
                                     CommandLine[0].strip().find("*get-ADPrinicipalGroupMembership*")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1069] Permission Groups Discovery - Process"

                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1069] Permission Groups Discovery - Process')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1063] Security Software Discovery
            if EventID[0]=="1" :
                if ( Image[0].strip().find("netsh.exe")>-1 or
                                     Image[0].strip().find("reg.exe")>-1 or
                                     Image[0].strip().find("tasklist.exe")>-1 ) and  (
                                     CommandLine[0].strip().find("*reg* query*")>-1 or
                                     CommandLine[0].strip().find("*tasklist *")>-1 or
                                     CommandLine[0].strip().find("*netsh*")>-1 or
                                     CommandLine[0].strip().find("*fltmc*|*findstr*")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1063] Security Software Discovery"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1063] Security Software Discovery')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            # [T1060] Registry Run Keys or Start Folder
            if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") :
                if (
                TargetObject[0].strip().find("*\\software\\microsoft\\windows\\currentversion\\run*")>-1 or
                TargetObject[0].strip().find("*\\software\\microsoft\\windows\\currentversion\\explorer\\*shell folders")>-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1060] Registry Run Keys or Start Folder"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1060] Registry Run Keys or Start Folder')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("Medium")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1059] Command-Line Interface
            if EventID[0]=="1" :
                if ( Image[0].strip().find("cmd.exe")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1059] Command-Line Interface"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1059] Command-Line Interface')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("Low")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [1057] Running Process Discovery
            if EventID[0]=="1" :
                if ( CommandLine[0].strip().find("tasklist")>-1 or CommandLine[0].strip().find("get-process")>-1  ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[1057] Process Discovery"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[1057] Running Process Discovery')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("Low")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()



            # [T1054] Indicator Blocking - Sysmon registry edited from other source
            if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") :
                if (
                TargetObject[0].strip().find("hklm\\system\\currentcontrolset\\services\\sysmondrv\\*")>-1 or
                TargetObject[0].strip().find("*\\software\\microsoft\\windows\\currentversion\\explorer\\*shell folders")>-1 or
                TargetObject[0].strip().find("hklm\\system\\currentcontrolset\\services\\sysmon\\*")>-1) and (
                Image[0].strip().find("sysmon64.exe")==-1 and
                Image[0].strip().find("sysmon.exe")==-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1054] Indicator Blocking - Sysmon registry edited from other source"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1054] Indicator Blocking - Sysmon registry edited from other source')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("Medium")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1054] Indicator Blocking - Driver unloaded
            if EventID[0]=="1" :
                if ( Image[0].strip().find("fltmc.exe")>-1 or CommandLine[0].strip().find("*fltmc*unload*")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1054] Indicator Blocking - Driver unloaded"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1054] Indicator Blocking - Driver unloaded')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1053] Scheduled Task - Process
            if EventID[0]=="1" :
                if ( Image[0].strip().find("taskeng.exe")>-1 or
                                     Image[0].strip().find("schtasks.exe")>-1 or
                                     Image[0].strip().find("svchost.exe")>-1 ) and ParentImage[0].lower().strip().find("C:\\Windows\\System32\\services.exe".lower())==-1  :
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1053] Scheduled Task - Process"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1053] Scheduled Task - Process')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("Low")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1050] New Service - Process
            if EventID[0]=="1" :
                if ( Image[0].strip().find("sc.exe")>-1 or
                                     Image[0].strip().find("powershell.exe")>-1 or
                                     Image[0].strip().find("cmd.exe")>-1 ) and  (
                                     CommandLine[0].strip().find("*new-service*binarypathname*")>-1 or
                                     CommandLine[0].strip().find("*sc*create*binpath*")>-1 or
                                     CommandLine[0].strip().find("*get-wmiobject*win32_service*create*")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1050] New Service - Process"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1050] New Service - Process')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1049] System Network Connections Discovery
            if EventID[0]=="1" :
                if ( Image[0].strip().find("net.exe")>-1 or
                                     Image[0].strip().find("netstat.exe")>-1 ) and  (
                                     CommandLine[0].strip().find("*net* use*")>-1 or
                                     CommandLine[0].strip().find("*net* sessions*")>-1 or
                                     CommandLine[0].strip().find("*net* file*")>-1 or \
                                     CommandLine[0].strip().find("*netstat*")>-1 or
                                     CommandLine[0].strip().find("*get-nettcpconnection*")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1049] System Network Connections Discovery"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1049] System Network Connections Discovery')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1047] Windows Management Instrumentation - Process
            if EventID[0]=="1" :
                if ( ParentCommandLine[0].strip().find("wmiprvse.exe")>-1 or
                                     Image[0].strip().find("wmic.exe")>-1 or
                                     CommandLine[0].strip().find("wmic")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1047] Windows Management Instrumentation - Process"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1047] Windows Management Instrumentation - Process')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1047] Windows Management Instrumentation - Network
            if EventID[0]=="3" :
                if len(CommandLine)>0 and( Image[0].strip().find("wmic.exe")>-1 or
                                     CommandLine[0].strip().find("wmic")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1047] Windows Management Instrumentation - Network"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1047] Windows Management Instrumentation - Network')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1047] Windows Management Instrumentation - Instances of an Active Script Event Consumer - Process
            if EventID[0]=="1" :
                if ( ParentCommandLine[0].strip().find("wmiprvse.exe")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1047] Windows Management Instrumentation - Instances of an Active Script Event Consumer - Process"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1047] Windows Management Instrumentation - Instances of an Active Script Event Consumer - Process')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1047] Windows Management Instrumentation - Instances of an Active Script Event Consumer - FileAccess
            if EventID[0]=="1" :
                if ( CommandLine[0].strip().find("c:\\windows\\system32\\wbem\\scrcons.exe")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1047] Windows Management Instrumentation - Instances of an Active Script Event Consumer - FileAccess"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1047] Windows Management Instrumentation - Instances of an Active Script Event Consumer - FileAccess')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1040] Network Sniffing
            if EventID[0]=="1" :
                if ( Image[0].strip().find("tshark.exe")>-1 or
                                     Image[0].strip().find("windump.exe")>-1 or
                                     Image[0].strip().find("logman.exe")>-1 or
                                     Image[0].strip().find("tcpdump.exe")>-1 or
                                     Image[0].strip().find("wprui.exe")>-1 or
                                     Image[0].strip().find("wpr.exe")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1040] Network Sniffing Detected"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1040] Network Sniffing Detected')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1037] Boot or Logon Initialization Scripts
            if EventID[0]=="1" :
                if ( CommandLine[0].strip().find("*reg*add*hkcu\\environment*userinitmprlogonscript*")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1037] Boot or Logon Initialization Scripts"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1037] Boot or Logon Initialization Scripts')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1036] Masquerading - Extension
            if EventID[0]=="1" :
                if ( Image[0].strip().find(".doc.")>-1 or
                                     Image[0].strip().find(".docx.")>-1 or
                                     Image[0].strip().find(".xls.")>-1 or
                                     Image[0].strip().find(".xlsx.")>-1 or
                                     Image[0].strip().find(".pdf.")>-1 or
                                     Image[0].strip().find(".rtf.")>-1 or
                                     Image[0].strip().find(".jpg.")>-1 or
                                     Image[0].strip().find(".png.")>-1 or
                                     Image[0].strip().find(".jpeg.")>-1 or
                                     Image[0].strip().find(".zip.")>-1 or
                                     Image[0].strip().find(".rar.")>-1 or
                                     Image[0].strip().find(".ppt.")>-1 or
                                     Image[0].strip().find(".pptx.")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1036] Masquerading - Extension"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1036] Masquerading - Extension')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1031] Modify Existing Service
            if EventID[0]=="1" :
                if ( Image[0].strip().find("sc.exe")>-1 or
                                     Image[0].strip().find("powershell.exe")>-1 or
                                     Image[0].strip().find("cmd.exe")>-1 ) and (
                                     CommandLine[0].strip().find("*sc*config*binpath*")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1031] Modify Existing Service"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1031] Modify Existing Service')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1028] Windows Remote Management
            if EventID[0]=="1" :
                if ( Image[0].strip().find("wsmprovhost.exe")>-1 or
                                     Image[0].strip().find("winrm.cmd")>-1 ) and (
                                     CommandLine[0].strip().find("Enable-PSRemoting -Force")>-1 or
                                     CommandLine[0].strip().find("Invoke-Command -computer_name")>-1 or
                                     CommandLine[0].strip().find("wmic*node*process call create")>-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1028] Windows Remote Management"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1028] Windows Remote Management')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1027] Obfuscated Files or Information
            if EventID[0]=="1" :
                if ( Image[0].strip().find("certutil.exe")>-1 and
                                     CommandLine[0].strip().find("encode")>-1 ) or (
                                     CommandLine[0].strip().find("tobase64string")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1027] Obfuscated Files or Information"
                        lock.release()
                        Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Sysmon_events[0]['Computer Name'].append(Computer[0])
                        Sysmon_events[0]['Channel'].append(Channel[0])
                        Sysmon_events[0]['Detection Rule'].append('[T1027] Obfuscated Files or Information')
                        Sysmon_events[0]['Detection Domain'].append("Threat")
                        Sysmon_events[0]['Severity'].append("High")
                        Sysmon_events[0]['Event Description'].append(Event_desc)
                        Sysmon_events[0]['Event ID'].append(EventID[0])
                        Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                        lock.release()

            #  [T1018] Remote System Discovery - Process
            if EventID[0]=="1" and ( Image[0].strip().find("net.exe")>-1 or
                                     Image[0].strip().find("ping.exe")>-1 ) and (
                                     CommandLine[0].strip().find("view")>-1 or
                                     CommandLine[0].strip().find("png")>-1 ):
                    try:

                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1018] Remote System Discovery - Process"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1018] Remote System Discovery - Process')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1018] Remote System Discovery - Network
            if EventID[0]=="3" :
                if ( Image[0].strip().find("net.exe")>-1 or
                                     Image[0].strip().find("ping.exe")>-1 ) and (
                                     CommandLine[0].strip().find("view")>-1 or
                                     CommandLine[0].strip().find("png")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1018] Remote System Discovery - Network"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1018] Remote System Discovery - Network')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            # [T1015] Accessibility Features - Registry
            if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") :
                if (
                TargetObject[0].strip().find("hklm\\software\\microsoft\\windows nt\\currentversion\\image file execution options\\*")>-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") accessed target image ("+TargetImage[0].strip()+ ") through source image ( "+ SourceImage[0].strip() +" )"
                    except:
                        Event_desc="[T1015] Accessibility Features - Registry"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1015] Accessibility Features - Registry')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1015] Accessibility features
            if EventID[0]=="3" :
                if len(ParentImage)>0 and ParentImage[0].strip().find("winlogon.exe")>-1 and (
                                     Image[0].strip().find("sethc.exe")>-1 or
                                     Image[0].strip().find("utilman.exe")>-1 or
                                     Image[0].strip().find("osk.exe")>-1 or
                                     Image[0].strip().find("magnify.exe")>-1 or
                                     Image[0].strip().find("displayswitch.exe")>-1 or
                                     Image[0].strip().find("narrator.exe")>-1 or
                                     Image[0].strip().find("atbroker.exe")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1015] Accessibility features"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1015] Accessibility features')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            # [T1013] Local Port Monitor
            if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") :
                if (
                TargetObject[0].strip().find("\system\\currentcontrolset\\control\\print\\monitors\\")>-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") accessed target image ("+TargetImage[0].strip()+ ") through source image ( "+ SourceImage[0].strip() +" )"
                    except:
                        Event_desc="[T1013] Local Port Monitor"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1013] Local Port Monitor')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1012] Query Registry - Process
            if EventID[0]=="1" :
                if ( Image[0].strip().find("reg.exe")>-1 and
                                     CommandLine[0].strip().find("reg query")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1012] Query Registry - Process"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1012] Query Registry - Process')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1012] Query Registry - Network
            if EventID[0]=="3" :
                if ( Image[0].strip().find("reg.exe")>-1 and
                                     CommandLine[0].strip().find("reg query")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1012] Query Registry - Network"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1012] Query Registry - Network')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1012] Processes opening handles and accessing Lsass with potential dlls in memory (i.e UNKNOWN in CallTrace)
            if EventID[0]=="10" :
                if ( TargetImage[0].strip().find("lsass.exe")>-1 and
                                      CallTrace[0].strip().find("unknown")>-1 ):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc='[T1012] Processes opening handles and accessing Lsass with potential dlls in memory'
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1012] Processes opening handles and accessing Lsass with potential dlls in memory')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1003] Processes opening handles and accessing Lsass with potential dlls in memory (i.e UNKNOWN in CallTrace)
            if EventID[0]=="7" :
                if ( ImageLoaded[0].strip().find("samlib.dll")>-1 or
                                     ImageLoaded[0].strip().find("vaultcli.dll")>-1 or
                                     ImageLoaded[0].strip().find("hid.dll")>-1 or
                                     ImageLoaded[0].strip().find("winscard.dll")>-1 or
                                     ImageLoaded[0].strip().find("cryptdll.dll")>-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) opening handles and accessing Lsass with potential dlls in memory ( " + ImageLoaded[0] + " )"
                    except:
                        Event_desc="[T1003] Processes opening handles and accessing Lsass with potential dlls in memory"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1003] Processes opening handles and accessing Lsass with potential dlls in memory')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            ##############################################
            # 18-05-2021 : Addition of new sysmon events #
            ##############################################

            ##############################################
            # 19-05-2021 : Addition of new sysmon events #
            ##############################################

            #  [T1112] process updating fDenyTSConnections or UserAuthentication registry key values
            if EventID[0]=="13" :
                if (TargetObject[0].strip().find("DenyTSConnections")>-1 or TargetObject[0].strip().find("UserAuthentication")>-1) and Details[0].strip().find("DWORD (0x00000000)")>-1:
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) opening updating registry key values to enable remote desktop connection."
                    except:
                        Event_desc="[T1112] process updating fDenyTSConnections or UserAuthentication registry key values"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1112] process updating fDenyTSConnections or UserAuthentication registry key values')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1059] processes loading PowerShell DLL *system.management.automation*
            if EventID[0]=="7" :
                if (Description[0].strip().find("system.management.automation")>-1 or ImageLoaded[0].strip().find("system.management.automation")>-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) loaded ( " + ImageLoaded[0].strip() + " )."
                    except:
                        Event_desc="[T1059] processes loading PowerShell DLL *system.management.automation*"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1059] processes loading PowerShell DLL *system.management.automation*')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

            #  [T1059] PSHost* pipes found in PowerShell execution
            if EventID[0]=="17" :
                if PipeName[0].strip().find("\\pshost")>-1:
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) started command ( " + PipeName[0].strip() + " )."
                    except:
                        Event_desc="[T1059] PSHost* pipes found in PowerShell execution"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1059] PSHost* pipes found in PowerShell execution')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()


            #  [T1112] process updating UseLogonCredential registry key value
            if EventID[0]=="13" :
                if TargetObject[0].strip().find("UseLogonCredential")>-1:
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) updating ( " + TargetObject[0].strip() + " )."
                    except:
                        Event_desc="[T1112] process updating UseLogonCredential registry key value"
                    lock.acquire()
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1112] process updating UseLogonCredential registry key value')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    lock.release()

        else:
            print(record['data'])


    Sysmon = pd.DataFrame(Sysmon_events[0])
    if SysmonInitial.value == 1:
        Sysmon.to_csv(temp_dir + '_Sysmon_report.csv', index=False)
        SysmonInitial.value = 0
    else:
        Sysmon.to_csv(temp_dir + '_Sysmon_report.csv', mode='a', index=False, header=False)

def detect_events_UserProfileService_log(file_name, shared_data):
    input_timezone = shared_data["input_timezone"]
    timestart = shared_data["timestart"]
    timeend = shared_data["timeend"]
    objectaccess = shared_data["objectaccess"]
    processexec = shared_data["processexec"]
    logons = shared_data["logons"]
    frequencyanalysis = shared_data["frequencyanalysis"]
    allreport = shared_data["allreport"]
    output = shared_data["output"]
    # if os.path.exists(temp_dir + "_User_SIDs_report.csv"):
    #     User_SIDs[0] = pd.DataFrame(pd.read_csv(temp_dir + "_User_SIDs_report.csv")).to_dict(orient='list')

    parser = PyEvtxParser(file_name)
    for record in parser.records():
        EventID = EventID_rex.findall(record['data'])
        Computer = Computer_rex.findall(record['data'])
        Channel = Channel_rex.findall(record['data'])

        timestamp=datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat()))
        if timestart is not None and timeend is not None :
            if not (timestamp>timestart and timestamp<timeend):
                continue

        if len(EventID) > 0:
            SID=UserProfile_SID_rex.findall(record['data'])
            File=UserProfile_File_rex.findall(record['data'])

            if EventID[0]=="5" :
                #print("in")
                SID=SID[0].strip().split("_")[0]
                if not SID in User_SIDs[0]['SID']:
                    User=File[0].strip().split("\\")[2]
                    User_SIDs[0]['User'].append(User)
                    User_SIDs[0]['SID'].append(SID)


    User_SIDs_report = pd.DataFrame(User_SIDs[0])
    lock.acquire()
    if User_SIDsInitial.value == 1:
        User_SIDs_report.to_csv(temp_dir + '_User_SIDs_report.csv', index=False)
        User_SIDsInitial.value = 0
    else:
        User_SIDs_report.to_csv(temp_dir + '_User_SIDs_report.csv', mode='a', index=False, header=False)
    lock.release()
def init(l):
    global lock
    lock = l

def multiprocess(file_names,function,input_timezone,timestarts,timeends,objectacces=False,processexe=False,logon=False,frequencyanalysi=False,allreports=False,Output='',CpuCount=0,temp="temp/"):
    multiprocessing.freeze_support()
    #try:
    global input_timzone, timestart, timeend,objectaccess,processexec,logons,frequencyanalysis,allreport,output,temp_dir
    temp_dir=temp
    #print("allreports values is " +str(allreports))
    #print("filename values is " + str(file_names))
    #print("in multiprocess")
    if 1==1:

        input_timzone=input_timezone
        timestart=timestarts
        timeend=timeends
        objectaccess=objectacces
        processexec=processexe
        logons=logon
        frequencyanalysis=frequencyanalysi
        allreport=allreports
        output=Output

        shared_data = {
            "input_timezone": input_timezone,
            "timestart": timestarts,
            "timeend": timeends,
            "objectaccess": objectacces,
            "processexec": processexe,
            "logons": logon,
            "frequencyanalysis": frequencyanalysi,
            "allreport": allreports,
            "output": Output
        }
        #print(f"output value is {output}")
        CPU_Count=0
        if CpuCount!=0:
            CPU_Count=CpuCount
        else:
            if multiprocessing.cpu_count()>1:
                CPU_Count=int(multiprocessing.cpu_count()/2)
            else:
                CPU_Count=multiprocessing.cpu_count()

        l = multiprocessing.Lock()
        pool = multiprocessing.Pool(CPU_Count,initializer=init, initargs=(l,))

        tasks = [(file_name, shared_data) for file_name in file_names]
        #print(f" tasks is {tasks}")
        pool.starmap(function,tasks )
        pool.close()

    #except Exception as e:
        #print("Issue proccessing files ( %s )"%str(e))

if __name__ == '__main__':
    if  platform.system().lower()=="windows":
        multiprocessing.freeze_support()
