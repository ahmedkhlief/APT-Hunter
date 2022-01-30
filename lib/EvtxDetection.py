import csv
import re
from netaddr import *
import xml.etree.ElementTree as ET
import pandas as pd
from datetime import datetime , timezone
from evtx import PyEvtxParser
from dateutil.parser import parse
from dateutil.parser import isoparse
from pytz import timezone
minlength=1000

account_op={}
PasswordSpray={}
Suspicious_executables=["\\mshta.exe","\\regsvr32.exe","\\csc.exe",'whoami.exe','\\pl.exe','\\nc.exe','nmap.exe','psexec.exe','plink.exe','mimikatz','procdump.exe',' dcom.exe',' Inveigh.exe',' LockLess.exe',' Logger.exe',' PBind.exe',' PS.exe',' Rubeus.exe',' RunasCs.exe',' RunAs.exe',' SafetyDump.exe',' SafetyKatz.exe',' Seatbelt.exe',' SExec.exe',' SharpApplocker.exe',' SharpChrome.exe',' SharpCOM.exe',' SharpDPAPI.exe',' SharpDump.exe',' SharpEdge.exe',' SharpEDRChecker.exe',' SharPersist.exe',' SharpHound.exe',' SharpLogger.exe',' SharpPrinter.exe',' SharpRoast.exe',' SharpSC.exe',' SharpSniper.exe',' SharpSocks.exe',' SharpSSDP.exe',' SharpTask.exe',' SharpUp.exe',' SharpView.exe',' SharpWeb.exe',' SharpWMI.exe',' Shhmon.exe',' SweetPotato.exe',' Watson.exe',' WExec.exe','7zip.exe']

Suspicious_powershell_commands=['FromBase64String','DomainPasswordSpray','PasswordSpray','Password','Get-WMIObject','Get-GPPPassword','Get-Keystrokes','Get-TimedScreenshot','Get-VaultCredential','Get-ServiceUnquoted','Get-ServiceEXEPerms','Get-ServicePerms','Get-RegAlwaysInstallElevated','Get-RegAutoLogon','Get-UnattendedInstallFiles','Get-Webconfig','Get-ApplicationHost','Get-PassHashes','Get-LsaSecret','Get-Information','Get-PSADForestInfo','Get-KerberosPolicy','Get-PSADForestKRBTGTInfo','Get-PSADForestInfo','Get-KerberosPolicy','Invoke-Command','Invoke-Expression','iex(','Invoke-Shellcode','Invoke--Shellcode','Invoke-ShellcodeMSIL','Invoke-MimikatzWDigestDowngrade','Invoke-NinjaCopy','Invoke-CredentialInjection','Invoke-TokenManipulation','Invoke-CallbackIEX','Invoke-PSInject','Invoke-DllEncode','Invoke-ServiceUserAdd','Invoke-ServiceCMD','Invoke-ServiceStart','Invoke-ServiceStop','Invoke-ServiceEnable','Invoke-ServiceDisable','Invoke-FindDLLHijack','Invoke-FindPathHijack','Invoke-AllChecks','Invoke-MassCommand','Invoke-MassMimikatz','Invoke-MassSearch','Invoke-MassTemplate','Invoke-MassTokens','Invoke-ADSBackdoor','Invoke-CredentialsPhish','Invoke-BruteForce','Invoke-PowerShellIcmp','Invoke-PowerShellUdp','Invoke-PsGcatAgent','Invoke-PoshRatHttps','Invoke-PowerShellTcp','Invoke-PoshRatHttp','Invoke-PowerShellWmi','Invoke-PSGcat','Invoke-Encode','Invoke-Decode','Invoke-CreateCertificate','Invoke-NetworkRelay','EncodedCommand','New-ElevatedPersistenceOption','wsman','Enter-PSSession','DownloadString','DownloadFile','Out-Word','Out-Excel','Out-Java','Out-Shortcut','Out-CHM','Out-HTA','Out-Minidump','HTTP-Backdoor','Find-AVSignature','DllInjection','ReflectivePEInjection','Base64','System.Reflection','System.Management','Restore-ServiceEXE','Add-ScrnSaveBackdoor','Gupt-Backdoor','Execute-OnTime','DNS_TXT_Pwnage','Write-UserAddServiceBinary','Write-CMDServiceBinary','Write-UserAddMSI','Write-ServiceEXE','Write-ServiceEXECMD','Enable-DuplicateToken','Remove-Update','Execute-DNSTXT-Code','Download-Execute-PS','Execute-Command-MSSQL','Download_Execute','Copy-VSS','Check-VM','Create-MultipleSessions','Run-EXEonRemote','Port-Scan','Remove-PoshRat','TexttoEXE','Base64ToString','StringtoBase64','Do-Exfiltration','Parse_Keys','Add-Exfiltration','Add-Persistence','Remove-Persistence','Find-PSServiceAccounts','Discover-PSMSSQLServers','Discover-PSMSExchangeServers','Discover-PSInterestingServices','Discover-PSMSExchangeServers','Discover-PSInterestingServices','Mimikatz','powercat','powersploit','PowershellEmpire','GetProcAddress','ICM','.invoke',' -e ','hidden','-w hidden','Invoke-Obfuscation-master','Out-EncodedWhitespaceCommand','Out-Encoded',"-EncodedCommand","-enc","-w hidden","[Convert]::FromBase64String","iex(","New-Object","Net.WebClient","-windowstyle hidden","DownloadFile","DownloadString","Invoke-Expression","Net.WebClient","-Exec bypass" ,"-ExecutionPolicy bypass"]

Suspicious_powershell_Arguments=["-EncodedCommand","-enc","-w hidden","[Convert]::FromBase64String","iex(","New-Object","Net.WebClient","-windowstyle hidden","DownloadFile","DownloadString","Invoke-Expression","Net.WebClient","-Exec bypass" ,"-ExecutionPolicy bypass"]

all_suspicious=["\\csc.exe",'whoami.exe','\\pl.exe','\\nc.exe','nmap.exe','psexec.exe','plink.exe','kali','mimikatz','procdump.exe',' dcom.exe',' Inveigh.exe',' LockLess.exe',' Logger.exe',' PBind.exe',' PS.exe',' Rubeus.exe',' RunasCs.exe',' RunAs.exe',' SafetyDump.exe',' SafetyKatz.exe',' Seatbelt.exe',' SExec.exe',' SharpApplocker.exe',' SharpChrome.exe',' SharpCOM.exe',' SharpDPAPI.exe',' SharpDump.exe',' SharpEdge.exe',' SharpEDRChecker.exe',' SharPersist.exe',' SharpHound.exe',' SharpLogger.exe',' SharpPrinter.exe',' SharpRoast.exe',' SharpSC.exe',' SharpSniper.exe',' SharpSocks.exe',' SharpSSDP.exe',' SharpTask.exe',' SharpUp.exe',' SharpView.exe',' SharpWeb.exe',' SharpWMI.exe',' Shhmon.exe',' SweetPotato.exe',' Watson.exe',' WExec.exe','7zip.exe','FromBase64String','DomainPasswordSpray','PasswordSpray','Password','Get-WMIObject','Get-GPPPassword','Get-Keystrokes','Get-TimedScreenshot','Get-VaultCredential','Get-ServiceUnquoted','Get-ServiceEXEPerms','Get-ServicePerms','Get-RegAlwaysInstallElevated','Get-RegAutoLogon','Get-UnattendedInstallFiles','Get-Webconfig','Get-ApplicationHost','Get-PassHashes','Get-LsaSecret','Get-Information','Get-PSADForestInfo','Get-KerberosPolicy','Get-PSADForestKRBTGTInfo','Get-PSADForestInfo','Get-KerberosPolicy','Invoke-Command','Invoke-Expression','iex(','Invoke-Shellcode','Invoke--Shellcode','Invoke-ShellcodeMSIL','Invoke-MimikatzWDigestDowngrade','Invoke-NinjaCopy','Invoke-CredentialInjection','Invoke-TokenManipulation','Invoke-CallbackIEX','Invoke-PSInject','Invoke-DllEncode','Invoke-ServiceUserAdd','Invoke-ServiceCMD','Invoke-ServiceStart','Invoke-ServiceStop','Invoke-ServiceEnable','Invoke-ServiceDisable','Invoke-FindDLLHijack','Invoke-FindPathHijack','Invoke-AllChecks','Invoke-MassCommand','Invoke-MassMimikatz','Invoke-MassSearch','Invoke-MassTemplate','Invoke-MassTokens','Invoke-ADSBackdoor','Invoke-CredentialsPhish','Invoke-BruteForce','Invoke-PowerShellIcmp','Invoke-PowerShellUdp','Invoke-PsGcatAgent','Invoke-PoshRatHttps','Invoke-PowerShellTcp','Invoke-PoshRatHttp','Invoke-PowerShellWmi','Invoke-PSGcat','Invoke-Encode','Invoke-Decode','Invoke-CreateCertificate','Invoke-NetworkRelay','EncodedCommand','New-ElevatedPersistenceOption','wsman','Enter-PSSession','DownloadString','DownloadFile','Out-Word','Out-Excel','Out-Java','Out-Shortcut','Out-CHM','Out-HTA','Out-Minidump','HTTP-Backdoor','Find-AVSignature','DllInjection','ReflectivePEInjection','Base64','System.Reflection','System.Management','Restore-ServiceEXE','Add-ScrnSaveBackdoor','Gupt-Backdoor','Execute-OnTime','DNS_TXT_Pwnage','Write-UserAddServiceBinary','Write-CMDServiceBinary','Write-UserAddMSI','Write-ServiceEXE','Write-ServiceEXECMD','Enable-DuplicateToken','Remove-Update','Execute-DNSTXT-Code','Download-Execute-PS','Execute-Command-MSSQL','Download_Execute','Copy-VSS','Check-VM','Create-MultipleSessions','Run-EXEonRemote','Port-Scan','Remove-PoshRat','TexttoEXE','Base64ToString','StringtoBase64','Do-Exfiltration','Parse_Keys','Add-Exfiltration','Add-Persistence','Remove-Persistence','Find-PSServiceAccounts','Discover-PSMSSQLServers','Discover-PSMSExchangeServers','Discover-PSInterestingServices','Discover-PSMSExchangeServers','Discover-PSInterestingServices','Mimikatz','powercat','powersploit','PowershellEmpire','GetProcAddress','ICM','.invoke',' -e ','hidden','-w hidden','Invoke-Obfuscation-master','Out-EncodedWhitespaceCommand','Out-Encoded',"-EncodedCommand","-enc","-w hidden","[Convert]::FromBase64String","iex(","New-Object","Net.WebClient","-windowstyle hidden","DownloadFile","DownloadString","Invoke-Expression","Net.WebClient","-Exec bypass" ,"-ExecutionPolicy bypass","-EncodedCommand","-enc","-w hidden","[Convert]::FromBase64String","iex(","New-Object","Net.WebClient","-windowstyle hidden","DownloadFile","DownloadString","Invoke-Expression","Net.WebClient","-Exec bypass" ,"-ExecutionPolicy bypass"]

Suspicious_Path=['\\temp\\','//temp//','/temp/','//windows//temp//','/windows/temp/','\\windows\\temp\\','\\appdata\\','/appdata/','//appdata//','//programdata//','\\programdata\\','/programdata/']
Usual_Path=['\\Windows\\','/Windows/','//Windows//','Program Files','\\Windows\\SysWOW64\\','/Windows/SysWOW64/','//Windows//SysWOW64//','\\Windows\\Cluster\\','/Windows/Cluster/','//Windows//Cluster//']
Pass_the_hash_users=[{'User':[],'Number of Logins':[],'Reached':[]}]
Logon_Events=[{'Date and Time':[],'timestamp':[],'Event ID':[],'Account Name':[],'Account Domain':[],'Logon Type':[],'Logon Process':[],'Source IP':[],'Workstation Name':[],'Computer Name':[],'Channel':[],'Original Event Log':[]}]
TerminalServices_Summary=[{'User':[],'Number of Logins':[]}]
Security_Authentication_Summary=[{'User':[],'Number of Failed Logins':[],'Number of Successful Logins':[]}]
Executed_Process_Summary=[{'Process Name':[],'Number of Execution':[]}]

critical_services=["Software Protection","Network List Service","Network Location Awareness","Windows Event Log"]

whitelisted=['MpKslDrv','CreateExplorerShellUnelevatedTask']

Sysmon_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[],'Computer Name':[],'Channel':[]}]
WinRM_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[],'Computer Name':[],'Channel':[]}]
Security_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[],'Computer Name':[],'Channel':[]}]
System_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Service Name':[],'Event Description':[],'Event ID':[],'Original Event Log':[],'Computer Name':[],'Channel':[]}]
ScheduledTask_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Schedule Task Name':[],'Event Description':[],'Event ID':[],'Original Event Log':[],'Computer Name':[],'Channel':[]}]
Powershell_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[],'Computer Name':[],'Channel':[]}]
Powershell_Operational_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[],'Computer Name':[],'Channel':[]}]
TerminalServices_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'User':[],'Source IP':[],'Original Event Log':[],'Computer Name':[],'Channel':[]}]
Windows_Defender_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[],'Computer Name':[],'Channel':[]}]
Timesketch_events=[{'message':[],'timestamp':[],'datetime':[],'timestamp_desc':[],'Event Description':[],'Severity':[],'Detection Domain':[],'Event ID':[],'Original Event Log':[],'Computer Name':[],'Channel':[]}]

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


def detect_events_security_log(file_name,input_timzone):
    #global Logon_Type_rex,Account_Name_rex,Account_Domain_rex,Workstation_Name_rex,Source_Network_Address_rex
    for file in file_name:
        parser = PyEvtxParser(file)
        for record in parser.records():
            EventID = EventID_rex.findall(record['data'])
            Computer = Computer_rex.findall(record['data'])
            Channel = Channel_rex.findall(record['data'])
            #print(EventID[0])
            #print(f'Event Record ID: {record["event_record_id"]}')
            #print(f'Event Timestamp: {record["timestamp"]}')
            if len(EventID) > 0:
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
                        for i in Suspicious_Path:
                            if str(record['data']).lower().find(i.lower())>-1:#process_name.strip().lower().find(i.lower())>-1 or process_command_line.lower().find(i.lower())>-1 :
                                # print("test")
                                #print("##### " + record["timestamp"] + " ####  ", end='')
                                #print("## Process running in temp ", end='')
                                #print("User Name : ( %s ) " % Account_Name[0][0].strip(), end='')
                                #print("with Command Line : ( " + Process_Command_Line[0][0].strip() + " )")
                                # print("###########")
                                try:
                                    Event_desc ="User Name : ( %s ) " % user+" with process : ( " + process_name.strip() + " ) run from suspcious location"
                                except:
                                    Event_desc =" Process run from suspicious location "
                                Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                                Security_events[0]['Computer Name'].append(Computer[0])
                                Security_events[0]['Channel'].append(Channel[0])
                                Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                                Security_events[0]['Detection Rule'].append("Process running in suspicious location")
                                Security_events[0]['Detection Domain'].append("Threat")
                                Security_events[0]['Severity'].append("Critical")
                                Security_events[0]['Event Description'].append(Event_desc)
                                Security_events[0]['Event ID'].append(EventID[0])
                                Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))

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
                            try:
                                Event_desc ="User Name : ( %s ) " % user+" with process : ( " + process_name.strip() + " ) run from Unusual location"
                            except:
                                Event_desc =" Process run from Unusual location "
                            Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                            Security_events[0]['Computer Name'].append(Computer[0])
                            Security_events[0]['Channel'].append(Channel[0])
                            Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                            Security_events[0]['Detection Rule'].append("Process running in Unusual location")
                            Security_events[0]['Detection Domain'].append("Threat")
                            Security_events[0]['Severity'].append("Critical")
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
                        """if len(Process_Name[0])>2 and Process_Name[0][1].strip() is None and Process_Name[0][0].strip() is None:
                            process_name=Process_Name[0][2].strip()
                        if len(Process_Name[0])>1 and  Process_Name[0][0].strip() is None:
                            process_name=Process_Name[0][1].strip()
                        elif len(Process_Name[0])<2:
                            process_name=Process_Name[0][0].strip()
                        """
                        #print(process_name)
                        #print(len(Process_Name[0]),Process_Name[0])
                        if process_name not in Executed_Process_Summary[0]['Process Name']:
                            Executed_Process_Summary[0]['Process Name'].append(process_name.strip())
                            Executed_Process_Summary[0]['Number of Execution'].append(1)
                        else :
                            Executed_Process_Summary[0]['Number of Execution'][Executed_Process_Summary[0]['Process Name'].index(process_name.strip())]=Executed_Process_Summary[0]['Number of Execution'][Executed_Process_Summary[0]['Process Name'].index(process_name.strip())]+1
                    except:
                        pass

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
                        if len(Target_Account_Name[0][1])>0:
                            target_user=Target_Account_Name[0][1].strip()
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
                if EventID[0] == "4625" or EventID[0] == "4624":
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
                                    Security_events[0]['Severity'].append("Critical")
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
                                Security_events[0]['Severity'].append("Critical")
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
                                Security_events[0]['Severity'].append("Critical")
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
                if EventID[0] == "4798" or EventID[0] == "4799" and record['data'].find("System32\\svchost.exe")==-1:
                        """print("##### " + record["timestamp"] + " ####  ", end='')
                        print(
                                "Suspicious Attempt to enumerate groups by user ( %s ) using process ( %s )" % (
                                Account_Name[0][0].strip(),Process_Name[0][0].strip()))
                        """
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
                        Security_events[0]['Severity'].append("Critical")
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
                    print("##### " + record["timestamp"] + " ####  ", end='')

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
                    Security_events[0]['Severity'].append("High")
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


                # non-system accounts with process requested accessing to object 4656
                if EventID[0]=="4656" or EventID[0]=="4663" :
                    #try :
                    if 1==1:
                            if len(Account_Name[0][0])>0:
                                user        = Account_Name[0][0].strip()
                                processname = Process_Name[0][0].strip()
                                objectname  = Object_Name[0][0].strip()
                                objecttype  = Object_Type[0][0].strip()
                            if len(Account_Name[0][1])>0:
                                user        = Account_Name[0][1].strip()
                                processname = Process_Name[0][1].strip()
                                objectname  = Object_Name[0][1].strip()
                                objecttype  = Object_Type[0][1].strip()


                                if len(Security_ID[0][0])>30 and objectname.lower().find("lsass.exe")>-1:
                                    try:
                                        Event_desc ="Non-system account ( %s ) with process ( %s ) got access to object ( %s ) of type ( %s )" % (user,processname,objectname,objecttype)
                                    except:
                                        Event_desc = "Non-system account with process got access to object"
                                    Security_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                                    Security_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                                    Security_events[0]['Detection Rule'].append("non-system accounts getting a handle to and accessing lsass")
                                    Security_events[0]['Detection Domain'].append("Audit")
                                    Security_events[0]['Severity'].append("High")
                                    Security_events[0]['Event Description'].append(Event_desc)
                                    Security_events[0]['Event ID'].append(EventID[0])
                                    Security_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                    #except Exception as e :
                        #print("error parsing fields for "+str(record['data']))

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

def detect_events_windows_defender_log(file_name,input_timzone):
    for file in file_name:
        parser = PyEvtxParser(file)
        for record in parser.records():
            EventID = EventID_rex.findall(record['data'])
            Computer = Computer_rex.findall(record['data'])
            Channel = Channel_rex.findall(record['data'])
            #print(f'Event Record ID: {record["event_record_id"]}')
            #print(f'Event Timestamp: {record["timestamp"]}')
            if len(EventID) > 0:


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
                    Windows_Defender_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Windows_Defender_events[0]['Computer Name'].append(Computer[0])
                    Windows_Defender_events[0]['Channel'].append(Channel[0])
                    Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Windows_Defender_events[0]['Detection Rule'].append("Windows Defender deleted history of malwares")
                    Windows_Defender_events[0]['Detection Domain'].append("Audit")
                    Windows_Defender_events[0]['Severity'].append("High")
                    Windows_Defender_events[0]['Event Description'].append(Event_desc)
                    Windows_Defender_events[0]['Event ID'].append(EventID[0])
                    Windows_Defender_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

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

                if  EventID[0] == "5001" :
                    #print("##### " + record["timestamp"] + " ####  ", end='')
                    #print("Windows Defender real-time protection disabled")

                    Event_desc="Windows Defender real-time protection disabled"
                    Windows_Defender_events[0]['Computer Name'].append(Computer[0])
                    Windows_Defender_events[0]['Channel'].append(Channel[0])
                    Windows_Defender_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Windows_Defender_events[0]['Detection Rule'].append("Windows Defender real-time protection disabled")
                    Windows_Defender_events[0]['Detection Domain'].append("Audit")
                    Windows_Defender_events[0]['Severity'].append("Critical")
                    Windows_Defender_events[0]['Event Description'].append(Event_desc)
                    Windows_Defender_events[0]['Event ID'].append(EventID[0])
                    Windows_Defender_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                if  EventID[0] == "5004" :
                    #print("##### " + record["timestamp"] + " ####  ", end='')
                    #print(" Windows Defender real-time protection configuration changed")

                    Event_desc="Windows Defender real-time protection configuration changed"
                    Windows_Defender_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Windows_Defender_events[0]['Computer Name'].append(Computer[0])
                    Windows_Defender_events[0]['Channel'].append(Channel[0])
                    Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Windows_Defender_events[0]['Detection Rule'].append("Windows Defender real-time protection configuration changed")
                    Windows_Defender_events[0]['Detection Domain'].append("Audit")
                    Windows_Defender_events[0]['Severity'].append("High")
                    Windows_Defender_events[0]['Event Description'].append(Event_desc)
                    Windows_Defender_events[0]['Event ID'].append(EventID[0])
                    Windows_Defender_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                if  EventID[0] == "5007" :
                    #print("##### " + record["timestamp"] + " ####  ", end='')
                    #print(" Windows Defender antimalware platform configuration changed")

                    Event_desc="Windows Defender antimalware platform configuration changed"
                    Windows_Defender_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Windows_Defender_events[0]['Computer Name'].append(Computer[0])
                    Windows_Defender_events[0]['Channel'].append(Channel[0])
                    Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Windows_Defender_events[0]['Detection Rule'].append("Windows Defender antimalware platform configuration changed")
                    Windows_Defender_events[0]['Detection Domain'].append("Audit")
                    Windows_Defender_events[0]['Severity'].append("High")
                    Windows_Defender_events[0]['Event Description'].append(Event_desc)
                    Windows_Defender_events[0]['Event ID'].append(EventID[0])
                    Windows_Defender_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

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
                    Windows_Defender_events[0]['Severity'].append("Critical")
                    Windows_Defender_events[0]['Event Description'].append(Event_desc)
                    Windows_Defender_events[0]['Event ID'].append(EventID[0])
                    Windows_Defender_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                if  EventID[0] == "5012" :
                    #print("##### " + record["timestamp"] + " ####  ", end='')
                    #print(" Windows Defender scanning for viruses is disabled")

                    Event_desc="Windows Defender scanning for viruses is disabled"
                    Windows_Defender_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Windows_Defender_events[0]['Computer Name'].append(Computer[0])
                    Windows_Defender_events[0]['Channel'].append(Channel[0])
                    Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Windows_Defender_events[0]['Detection Rule'].append("Windows Defender scanning for viruses is disabled")
                    Windows_Defender_events[0]['Detection Domain'].append("Audit")
                    Windows_Defender_events[0]['Severity'].append("Critical")
                    Windows_Defender_events[0]['Event Description'].append(Event_desc)
                    Windows_Defender_events[0]['Event ID'].append(EventID[0])
                    Windows_Defender_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

            else:
                print(record['data'])
def detect_events_scheduled_task_log(file_name,input_timzone):
    for file in file_name:
        parser = PyEvtxParser(file)
        for record in parser.records():
            EventID = EventID_rex.findall(record['data'])
            Computer = Computer_rex.findall(record['data'])
            Channel = Channel_rex.findall(record['data'])

            if len(EventID) > 0:
                task_name=Task_Name_rex.findall(record['data'])
                Register_User = Task_Registered_User_rex.findall(record['data'])
                Delete_User = Task_Deleted_User_rex.findall(record['data'])

                #Detect any log that contain suspicious process name or argument
                for i in all_suspicious:

                    if record['data'].lower().find(i.lower())>-1:

                        #print("##### " + record["timestamp"] + " ####  ", end='')
                        #print("## Found Suspicios Process ", end='')
                        #print("User Name : ( %s ) " % Account_Name[0][0].strip(), end='')
                        #print("with Command Line : ( " + Process_Command_Line[0][0].strip() + " )")
                        # print("###########")

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

                    ScheduledTask_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    ScheduledTask_events[0]['Computer Name'].append(Computer[0])
                    ScheduledTask_events[0]['Channel'].append(Channel[0])
                    ScheduledTask_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    ScheduledTask_events[0]['Detection Rule'].append("schedule task registered")
                    ScheduledTask_events[0]['Detection Domain'].append("Audit")
                    ScheduledTask_events[0]['Severity'].append("High")
                    ScheduledTask_events[0]['Event Description'].append(Event_desc)
                    ScheduledTask_events[0]['Schedule Task Name'].append(task_name)
                    ScheduledTask_events[0]['Event ID'].append(EventID[0])
                    ScheduledTask_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

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

                    ScheduledTask_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    ScheduledTask_events[0]['Computer Name'].append(Computer[0])
                    ScheduledTask_events[0]['Channel'].append(Channel[0])
                    ScheduledTask_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    ScheduledTask_events[0]['Detection Rule'].append("schedule task updated")
                    ScheduledTask_events[0]['Detection Domain'].append("Audit")
                    ScheduledTask_events[0]['Severity'].append("Medium")
                    ScheduledTask_events[0]['Event Description'].append(Event_desc)
                    ScheduledTask_events[0]['Event ID'].append(EventID[0])
                    ScheduledTask_events[0]['Schedule Task Name'].append(task_name)
                    ScheduledTask_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

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

                    ScheduledTask_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    ScheduledTask_events[0]['Computer Name'].append(Computer[0])
                    ScheduledTask_events[0]['Channel'].append(Channel[0])
                    ScheduledTask_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    ScheduledTask_events[0]['Detection Rule'].append("schedule task deleted")
                    ScheduledTask_events[0]['Detection Domain'].append("Audit")
                    ScheduledTask_events[0]['Severity'].append("High")
                    ScheduledTask_events[0]['Event Description'].append(Event_desc)
                    ScheduledTask_events[0]['Schedule Task Name'].append(task_name)
                    ScheduledTask_events[0]['Event ID'].append(EventID[0])
                    ScheduledTask_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

            else:
                print(record['data'])
def detect_events_system_log(file_name,input_timzone):
    for file in file_name:
        parser = PyEvtxParser(file)
        for record in parser.records():
            EventID = EventID_rex.findall(record['data'])
            Computer = Computer_rex.findall(record['data'])
            Channel = Channel_rex.findall(record['data'])

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


                # System Logs cleared
                if (EventID[0]=="104") :
                    Event_desc="System Logs Cleared"
                    #System_events[0]['Date and Time'].append(datetime.strptime(record["timestamp"],'%Y-%m-%d %I:%M:%S.%f %Z').isoformat())
                    System_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    System_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    System_events[0]['Computer Name'].append(Computer[0])
                    System_events[0]['Channel'].append(Channel[0])
                    System_events[0]['Detection Rule'].append(
                        "System Logs Cleared")
                    System_events[0]['Detection Domain'].append("Audit")
                    System_events[0]['Severity'].append("Critical")
                    System_events[0]['Event Description'].append(Event_desc)
                    System_events[0]['Service Name'].append("None")
                    System_events[0]['Event ID'].append(EventID[0])
                    System_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))

                if (EventID[0]=="7045" or EventID[0]=="601") and (record['data'].strip().find("\\temp\\") > -1 or record['data'].strip().find(
                        "\\tmp\\") > -1):
                    Event_desc="Service Installed with executable in TEMP Folder"
                    #System_events[0]['Date and Time'].append(datetime.strptime(record["timestamp"],'%Y-%m-%d %I:%M:%S.%f %Z').isoformat())
                    System_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    System_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    System_events[0]['Computer Name'].append(Computer[0])
                    System_events[0]['Channel'].append(Channel[0])
                    System_events[0]['Detection Rule'].append(
                        "Service Installed with executable in TEMP Folder ")
                    System_events[0]['Detection Domain'].append("Threat")
                    System_events[0]['Severity'].append("Critical")
                    System_events[0]['Event Description'].append(Event_desc)
                    System_events[0]['Service Name'].append("None")
                    System_events[0]['Event ID'].append(EventID[0])
                    System_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))

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
                    System_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    System_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    System_events[0]['Computer Name'].append(Computer[0])
                    System_events[0]['Channel'].append(Channel[0])
                    System_events[0]['Detection Rule'].append("Service installed in the system")
                    System_events[0]['Detection Domain'].append("Audit")
                    System_events[0]['Severity'].append(Severity)
                    System_events[0]['Service Name'].append(service_name)
                    System_events[0]['Event Description'].append(Event_desc)
                    System_events[0]['Event ID'].append(EventID[0])
                    System_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

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

                            System_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                            System_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                            System_events[0]['Computer Name'].append(Computer[0])
                            System_events[0]['Channel'].append(Channel[0])
                            System_events[0]['Detection Rule'].append("psexec service detected installed in the system")
                            System_events[0]['Detection Domain'].append("Threat")
                            System_events[0]['Severity'].append("Critical")
                            System_events[0]['Service Name'].append(service_name)
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

                            Event_desc="Service with Name ( %s ) start type was ( %s ) chnaged to ( %s )  "%(service_state_name,service_state_old,service_state_new)
                            System_events[0]['Service Name'].append(service_state_name)
                        else:
                            continue
                    except:
                            Event_desc="Service start type changed"
                            System_events[0]['Service Name'].append("NONE")
                            print("issue parsing event : ",str(record['data']).replace("\r"," "))

                    System_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    System_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    System_events[0]['Computer Name'].append(Computer[0])
                    System_events[0]['Channel'].append(Channel[0])
                    System_events[0]['Detection Rule'].append("Service start type changed")
                    System_events[0]['Detection Domain'].append("Audit")
                    System_events[0]['Severity'].append("Medium")
                    System_events[0]['Event Description'].append(Event_desc)
                    System_events[0]['Event ID'].append(EventID[0])
                    System_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                #service state changed
                if EventID[0]=="7036" :
                    #print("##### " + record["timestamp"] + " ####  ", end='')
                    #print("Service with Name ( %s ) entered ( %s ) state "%(Service_and_state.group(1),Service_and_state.group(2)))
                    try:
                        if len(Service_State_Name[0][0])>0:
                            service_state=Service_State_Old[0][0].strip()
                            service_state_name=Service_State_Name[0][0].strip()
                        if len(Service_State_Name[0][1])>0:
                            service_state=Service_State_Old[0][1].strip()
                            service_state_name=Service_State_Name[0][1].strip()

                        if service_state_name in critical_services :

                            Event_desc="Service with Name ( %s ) entered ( %s ) state "%(service_state_name,service_state)
                            #System_events[0]['Date and Time'].append(datetime.strptime(record["timestamp"],'%Y-%m-%d %I:%M:%S.%f %Z').isoformat())
                            System_events[0]['Service Name'].append(service_state_name)
                        else:
                            continue
                    except:
                            print("issue parsing event : ",str(record['data']).replace("\r"," "))
                            System_events[0]['Service Name'].append("NONE")
                            Event_desc="Service State Changed"

                    System_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    System_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    System_events[0]['Computer Name'].append(Computer[0])
                    System_events[0]['Channel'].append(Channel[0])
                    System_events[0]['Detection Rule'].append("Service State Changed")
                    System_events[0]['Detection Domain'].append("Audit")
                    System_events[0]['Severity'].append("Medium")
                    System_events[0]['Event Description'].append(Event_desc)
                    System_events[0]['Event ID'].append(EventID[0])
                    System_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                #Zerologon Exploitation Using Well-known Tools
                if EventID[0]=="5805" or EventID[0]=="5723" :
                    #print("##### " + record["timestamp"] + " ####  ", end='')
                    #print("Service with Name ( %s ) entered ( %s ) state "%(Service_and_state.group(1),Service_and_state.group(2)))
                    for i in all_suspicious:
                        if record['data'].lower().find(i.lower())>-1:
                            Event_desc="Zerologon Exploitation Using Well-known Tools "
                            System_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                            System_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                            System_events[0]['Computer Name'].append(Computer[0])
                            System_events[0]['Channel'].append(Channel[0])
                            System_events[0]['Detection Rule'].append("Zerologon Exploitation Using Well-known Tools ")
                            System_events[0]['Detection Domain'].append("Threat")
                            System_events[0]['Severity'].append("High")
                            System_events[0]['Event Description'].append(Event_desc)
                            System_events[0]['Event ID'].append(EventID[0])
                            System_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                            break
            else:
                print(record['data'])


def detect_events_powershell_operational_log(files,input_timzone):

    for file in files:
        parser = PyEvtxParser(file)
        for record in parser.records():
            EventID = EventID_rex.findall(record['data'])
            Computer = Computer_rex.findall(record['data'])
            Channel = Channel_rex.findall(record['data'])

            if len(EventID) > 0:
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
                #Powershell Module logging will record portions of scripts, some de-obfuscated code
                if EventID[0]=="4103" :
                    if len(Host_Application) == 0:
                        host_app = ""
                    else:
                        host_app = Host_Application[0].strip()
                    for i in Suspicious_powershell_commands:
                        if i in record['data']:
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
                        Powershell_Operational_events[0]['Severity'].append("Critical")
                        Powershell_Operational_events[0]['Event Description'].append(Event_desc)
                        Powershell_Operational_events[0]['Event ID'].append(EventID[0])
                        Powershell_Operational_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))

                Suspicious = []
                #captures powershell script block Execute a Remote Command
                if EventID[0]=="4104"  or EventID[0]=="24577" :
                    for i in Suspicious_powershell_commands:
                        if i in record['data']:
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
                        Powershell_Operational_events[0]['Severity'].append("Critical")
                        Powershell_Operational_events[0]['Event Description'].append(Event_desc)
                        Powershell_Operational_events[0]['Event ID'].append(EventID[0])
                        Powershell_Operational_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                Suspicious = []

                #capture PowerShell ISE Operation
                if EventID[0]=="24577" :
                    for i in Suspicious_powershell_commands:
                        if i in record['data']:
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
                        Powershell_Operational_events[0]['Severity'].append("Critical")
                        Powershell_Operational_events[0]['Event Description'].append(Event_desc)
                        Powershell_Operational_events[0]['Event ID'].append(EventID[0])
                        Powershell_Operational_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))

                Suspicious = []

                #Executing Pipeline
                if EventID[0]=="4100":
                    if len(Host_Application) == 0:
                        host_app = ""
                    else:
                        host_app = Host_Application[0].strip()
                    for i in Suspicious_powershell_commands:
                        if record['data'].find(i)>-1:
                            Suspicious.append(i)
                    if len(Suspicious)>0:
                        #print("##### " + record["timestamp"] + " #### EventID=4100 #### Executing Pipeline ####", end='')
                        #print("Found User ("+User[0].strip()+") run Suspicious PowerShell commands that include ("+",".join(Suspicious)+") in event with Command Name ("+Command_Name[0].strip()+") and full command ("+Host_Application[0].strip()+") ", end='')#, check event details "+record['data'])
                        Event_desc = "Found User (" + User[
                            0].strip() + ") run Suspicious PowerShell commands that include (" + ",".join(
                            Suspicious) + ") in event with Command Name (" + Command_Name[
                                         0].strip() + ") and full command (" + host_app + ") "

                        if len(Error_Message)>0:
                            #print(Error_Message[0].strip())
                            Event_desc = Event_desc + "Error Message (" + Error_Message[0].strip() + ")"
                        #else:
                            #print("")
                        Powershell_Operational_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Powershell_Operational_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Powershell_Operational_events[0]['Computer Name'].append(Computer[0])
                        Powershell_Operational_events[0]['Channel'].append(Channel[0])
                        Powershell_Operational_events[0]['Detection Rule'].append("Powershell Executing Pipeline - Suspicious Powershell Commands detected")
                        Powershell_Operational_events[0]['Detection Domain'].append("Threat")
                        Powershell_Operational_events[0]['Severity'].append("Critical")
                        Powershell_Operational_events[0]['Event Description'].append(Event_desc)
                        Powershell_Operational_events[0]['Event ID'].append(EventID[0])
                        Powershell_Operational_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))

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
                        Powershell_Operational_events[0]['Severity'].append("High")
                        Powershell_Operational_events[0]['Event Description'].append(Event_desc)
                        Powershell_Operational_events[0]['Event ID'].append(EventID[0])
                        Powershell_Operational_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                Suspicious = []
            else:
                print(record['data'])

def detect_events_powershell_log(file_name,input_timzone):

    for file in file_name:
        parser = PyEvtxParser(file)
        for record in parser.records():
            EventID = EventID_rex.findall(record['data'])
            Computer = Computer_rex.findall(record['data'])
            Channel = Channel_rex.findall(record['data'])

            if len(EventID) > 0:
                Host_Application = HostApplication_rex.findall(record['data'])
                User =UserId_rex.findall(record['data'])
                Engine_Version = EngineVersion_rex.findall(record['data'])
                ScriptName = ScriptName_rex.findall(record['data'])
                CommandLine= CommandLine_rex.findall(record['data'])
                Error_Message = ErrorMessage_rex.findall(record['data'])
                Suspicious=[]
                #Powershell Pipeline Execution details
                host_app=""

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


                #Detect any log that contain suspicious process name or argument
                for i in Suspicious_executables:

                    if record['data'].lower().find(i.lower())>-1:

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
                        Powershell_events[0]['Severity'].append("Critical")
                        Powershell_events[0]['Event Description'].append(Event_desc)
                        Powershell_events[0]['Event ID'].append(EventID[0])
                        Powershell_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                        break

                if EventID[0]=="800" :
                    if len(Host_Application) == 0:
                        host_app = ""
                    else:
                        host_app = Host_Application[0].strip()
                    for i in Suspicious_powershell_commands:
                        if i in record['data']:
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
                        Powershell_events[0]['Severity'].append("Critical")
                        Powershell_events[0]['Event Description'].append(Event_desc)
                        Powershell_events[0]['Event ID'].append(EventID[0])
                        Powershell_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))

                Suspicious = []

                if EventID[0]=="600" or EventID[0]=="400" or EventID[0]=="403" :
                    if len(Host_Application) == 0:
                        host_app = ""
                    else:
                        host_app = Host_Application[0].strip()
                    for i in Suspicious_powershell_commands:
                        if i in record['data']:
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
                        Powershell_events[0]['Severity'].append("Critical")
                        Powershell_events[0]['Event Description'].append(Event_desc)
                        Powershell_events[0]['Event ID'].append(EventID[0])
                        Powershell_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))


                Suspicious = []
                if EventID[0]!="600" and EventID[0]!="400" or EventID[0]!="403" or EventID[0]!="800":
                    for i in Suspicious_powershell_commands:
                        if i in record['data']:
                            Suspicious.append(i)

                    if len(Suspicious)>0:
                        Event_desc ="Found  Suspicious PowerShell commands that include (" + ",".join(Suspicious) + ") in event "
                        Powershell_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Powershell_events[0]['Computer Name'].append(Computer[0])
                        Powershell_events[0]['Channel'].append(Channel[0])
                        Powershell_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Powershell_events[0]['Detection Rule'].append("Suspicious PowerShell commands Detected")
                        Powershell_events[0]['Detection Domain'].append("Threat")
                        Powershell_events[0]['Severity'].append("Critical")
                        Powershell_events[0]['Event Description'].append(Event_desc)
                        Powershell_events[0]['Event ID'].append(EventID[0])
                        Powershell_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))
                Suspicious = []
            else:
                print(record['data'])

def detect_events_TerminalServices_LocalSessionManager_log(file_name,input_timzone):

    for file in file_name:
        parser = PyEvtxParser(file)
        for record in parser.records():
            EventID = EventID_rex.findall(record['data'])
            Computer = Computer_rex.findall(record['data'])
            Channel = Channel_rex.findall(record['data'])

            if len(EventID) > 0:

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

                        if Source_Network_Address[0][0].strip()!="127.0.0.1" and not IPAddress(Source_Network_Address[0][0].strip()).is_private():
                            #print("##### " + record["timestamp"] + " #### EventID=" + EventID[0].strip() + " ### Remote Desktop Services: Session logon succeeded: #### ", end='')
                            #print("Found User ("+User[0].strip()+") connecting from public IP (" +Source_Network_Address[0][0].strip()+") ")

                            Event_desc ="Found User ("+User[0].strip()+") connecting from public IP (" +Source_Network_Address[0][0].strip()+") "
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

                        else:
                            Event_desc = "Found User (" + User[
                                0].strip() + ") connecting from IP (" +Source_Network_Address[0][0]+ ") "
                            TerminalServices_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                            TerminalServices_events[0]['Computer Name'].append(Computer[0])
                            TerminalServices_events[0]['Channel'].append(Channel[0])
                            TerminalServices_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                            TerminalServices_events[0]['Detection Rule'].append(
                                "User connected RDP to this machine")
                            TerminalServices_events[0]['Detection Domain'].append("Threat")
                            TerminalServices_events[0]['User'].append(User[0].strip())
                            TerminalServices_events[0]['Source IP'].append(Source_Network_Address[0][0].strip())
                            TerminalServices_events[0]['Severity'].append("Medium")
                            TerminalServices_events[0]['Event Description'].append(Event_desc)
                            TerminalServices_events[0]['Event ID'].append(EventID[0])
                            TerminalServices_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))

                # Remote Desktop Services: Session logon succeeded
                if EventID[0]=="21" or EventID[0]=="25" :
                    #print(Source_Network_Address[0][0])
                    #print(len(Source_Network_Address))
                    if len(Source_Network_Address)<1:
                        #print(IPAddress(Source_Network_Address[0][0].strip()).is_private())
                        Event_desc ="Found User ("+User[0].strip()+") connecting from ( "+Source_Network_Address_Terminal_NotIP[0]+" ) "
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
            else:
                print(record['data'])
def detect_events_Microsoft_Windows_WinRM(file_name,input_timzone):
    for file in file_name:
        parser = PyEvtxParser(file)
        for record in parser.records():
            EventID = EventID_rex.findall(record['data'])
            Computer = Computer_rex.findall(record['data'])
            Channel = Channel_rex.findall(record['data'])

            if len(EventID) > 0:

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
                    WinRM_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    WinRM_events[0]['Computer Name'].append(Computer[0])
                    WinRM_events[0]['Channel'].append(Channel[0])
                    WinRM_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    WinRM_events[0]['Detection Rule'].append("connection is initiated using WinRM from this machine - Powershell remoting")
                    WinRM_events[0]['Detection Domain'].append("Audit")
                    WinRM_events[0]['Severity'].append("High")
                    WinRM_events[0]['Event Description'].append(Event_desc)
                    WinRM_events[0]['Event ID'].append(EventID[0])
                    WinRM_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))



                if EventID[0]=="91":

                    #print("##### " + record["timestamp"] + " #### EventID=" + EventID[0].strip() + " ### connection is initiated using WinRM to this machine - Powershell remoting  #### ", end='')
                    #print("User Connected to this machine using WinRM - powershell remote - check the system logs for more information")
                    try:
                        Event_desc="User ("+User_ID[0].strip()+") Connected to this machine using WinRM - powershell remote - check eventlog viewer"
                    except:
                        Event_desc="User Connected to this machine using WinRM - powershell remote - check eventlog viewer"
                    WinRM_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    WinRM_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    WinRM_events[0]['Computer Name'].append(Computer[0])
                    WinRM_events[0]['Channel'].append(Channel[0])
                    WinRM_events[0]['Detection Rule'].append("connection is initiated using WinRM to this machine - Powershell remoting")
                    WinRM_events[0]['Detection Domain'].append("Audit")
                    WinRM_events[0]['Severity'].append("High")
                    WinRM_events[0]['Event Description'].append(Event_desc)
                    WinRM_events[0]['Event ID'].append(EventID[0])
                    WinRM_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

            else:
                print(record['data'])


def detect_events_Sysmon_log(file_name,input_timzone):
    for file in file_name:
        parser = PyEvtxParser(file)
        for record in parser.records():
            EventID = EventID_rex.findall(record['data'])
            Computer = Computer_rex.findall(record['data'])
            Channel = Channel_rex.findall(record['data'])

            if len(EventID) > 0:


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

                #[  T1543 ] Sc.exe manipulating windows services
                if EventID[0]=="1" and Image[0].strip().find("\\sc.exe")>-1 and ( CommandLine[0].find("create")>-1 or CommandLine[0].find("start")>-1 or CommandLine[0].find("config")>-1 ):

                    """print("##### " + row[
                        'Date and Time'] + " #### EventID=1 ### [  T1543 ] Sc.exe manipulating windows services #### ", end='')
                    print(
                        "Found User (" + User[0].strip() + ") Trying to manipulate windows services usign Sc.exe with Command Line (" + CommandLine[
                            0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )")"""

                    Event_desc="Found User (" + User[0].strip() + ") Trying to manipulate windows services usign Sc.exe with Command Line (" + CommandLine[
                            0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )"
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[  T1543 ] Sc.exe manipulating windows services')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                # [ T1059 ] wscript or cscript runing script
                if EventID[0]=="1" and ( Image[0].strip().find("\\wscript.exe")>-1 or Image[0].strip().find("\\cscript.exe")>-1 ):

                    """print("##### " + record["timestamp"] + " #### EventID=1 ### [  T1059 ] wscript or cscript runing script #### ", end='')
                    print(
                        "Found User (" + User[0].strip() + ") Trying to run wscript or cscript with Command Line (" + CommandLine[
                            0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )")"""

                    Event_desc="Found User (" + User[0].strip() + ") Trying to run wscript or cscript with Command Line (" + CommandLine[
                            0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )"
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


                #  [T1170] Detecting  Mshta
                if EventID[0]=="1" and ( Image[0].strip().find("\\mshta.exe")>-1  ):

                    """print("##### " + record["timestamp"] + " #### EventID=1 ### [ T1218.005 ] Detecting  Mshta #### ", end='')
                    print(
                        "Found User (" + User[0].strip() + ") Trying to run mshta with Command Line (" + CommandLine[
                            0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )")"""

                    Event_desc="Found User (" + User[0].strip() + ") Trying to run mshta with Command Line (" + CommandLine[
                            0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )"
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

                #Detect Psexec with accepteula flag
                if  EventID[0] == "13" and (
                        TargetObject[0].strip().find("psexec") > -1 ) :
                    """print("##### " + row[
                        'Date and Time'] + " #### EventID=13 ### Psexec Detected in the system #### ", end='')
                    print(
                        "Found User (" + User[0].strip() + ") Trying to run psexec with process Image :" + Image[0].strip() )"""

                    Event_desc="Found User (" + User[0].strip() + ") Trying to run psexec with process Image :" + Image[0].strip()
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


                #Prohibited Process connecting to internet
                if EventID[0]=="3" and ( Image[0].strip().find("powershell.exe")>-1 or Image[0].strip().find("mshta.exe")>-1 or Image[0].strip().find("cscript.exe")>-1 or Image[0].strip().find("regsvr32.exe")>-1  or Image[0].strip().find("certutil.exe")>-1 ):
                    #temp.append()
                    #print("##### " + row[
                    #    'Date and Time'] + " #### EventID=3 ### Prohibited Process connecting to internet #### ", end='')
                    #print(
                    #    "Found User (" + User[0].strip() + ") run process "+Image[0].strip()+" and initiated network connection from hostname ( "+ SourceHostname[0].strip()+" and IP ( "+SourceIp[0].strip() +" ) to hostname ( "+ DestinationHostname[0].strip()+" ) , IP ( " +DestinationIp[0].strip()+" ) and port ( "+DestinationPort[0].strip()+" )")

                    Event_desc="User (" + User[0].strip() + ") run process "+Image[0].strip()+" and initiated network connection from hostname ( "+ SourceHostname[0].strip()+" and IP ( "+SourceIp[0].strip() +" ) to hostname ( "+ DestinationHostname[0].strip()+" ) , IP ( " +DestinationIp[0].strip()+" ) and port ( "+DestinationPort[0].strip()+" )"
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

                #Detecting WMI attacks
                if EventID[0]=="1" and ( ParentCommandLine[0].strip().find("WmiPrvSE.exe")>-1 or Image[0].strip().find("WmiPrvSE.exe")>-1 ):

                    Event_desc="User (" + User[0].strip() + ") run command through WMI with process ("+Image[0].strip()+ ") and commandline ( "+CommandLine[
                            0].strip() +" )"
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

                #Detecting IIS/Exchange Exploitation
                if EventID[0]=="1" and ( ParentCommandLine[0].strip().find("w3wp.exe")>-1  ):

                    Event_desc="IIS run command with user (" + User[0].strip() + ") and process name ("+Image[0].strip()+ ") and commandline ( "+CommandLine[
                            0].strip() +" )"
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

                # [T1082] System Information Discovery
                if EventID[0]=="1" and ( CommandLine[0].strip().find("sysinfo.exe")>-1 or Image[0].strip().find("sysinfo.exe")>-1 or CommandLine[0].strip().find("whoami.exe")>-1 or Image[0].strip().find("whoami.exe")>-1 ):

                    Event_desc="System Information Discovery Process ( %s) ith commandline ( %s) "%(Image[0],CommandLine[0])
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

                #  [T1117] Bypassing Application Whitelisting with Regsvr32
                if EventID[0]=="1" and ( Image[0].strip().find("regsvr32.exe")>-1 or Image[0].strip().find("rundll32.exe")>-1 or Image[0].strip().find("certutil.exe")>-1 ):

                    Event_desc="[T1117] Bypassing Application Whitelisting with Regsvr32 , Process ( %s) with commandline ( %s)"%(Image[0],CommandLine[0])
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('[T1117] Bypassing Application Whitelisting with Regsvr32')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("High")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                # [T1055] Process Injection
                if EventID[0]=="8" and ( StartFunction[0].strip().lower().find("loadlibrary")>-1  ):

                    Event_desc="Process ( %s) attempted process injection on process ( %s)"%(SourceImage,TargetImage)
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

                # [T0000] Console History
                if EventID[0]=="1" and ( CommandLine[0].strip().find("get-history")>-1 or
                                        CommandLine[0].strip().find("appdata\\roaming\\microsoft\\windows\\powershell\\psreadline\\consolehost_history.txt")>-1 or
                                        CommandLine[0].strip().find("(get-psreadlineoption).historysavepath")>-1 ):

                    Event_desc="Found User (" + User[0].strip() + ") through process name ("+Image[0].strip()+ ") tried accessing powershell history through commandline ( "+CommandLine[0].strip() +" )"
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


                # [ T0000 ] Remotely Query Login Sessions - Network
                if EventID[0]=="3" and Image[0].strip().find("qwinsta.exe")>-1:

                    Event_desc="Found User (" + User[0].strip() + ") Trying to run query login session through network using Command Line (" + CommandLine[0].strip() + ")"
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

                # [ T0000 ] Remotely Query Login Sessions - Process
                if EventID[0]=="3" and Image[0].strip().find("qwinsta.exe")>-1:

                    Event_desc="Found User (" + User[0].strip() + ") Trying to run query login session Command Line (" + CommandLine[0].strip() + ")"
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

                # [ T0000 ] Suspicious process name detected
                if EventID[0]=="1":

                    #detect suspicious process
                    for sProcessName in Suspicious_executables:

                        if CommandLine[0].lower().find(sProcessName.lower())>-1:

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

                #[  T1002 ] Data Compressed
                if EventID[0]=="1" and ((Image[0].strip().find("powershell.exe")>-1 and CommandLine[0].find("-recurse | compress-archive")>-1) or (Image[0].strip().find("rar.exe")>-1 and CommandLine[0].find("rar*a*")>-1)):

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
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['Detection Rule'].append("#[  T1003 ] Credential Dumping ImageLoad")
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("Medium")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))

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

                # [T1003] Credential Dumping - Registry Save
                if (EventID[0]=="1") and Image[0].strip().find("reg.exe")==-1 and (
                    CommandLine[0].strip().find("*save*HKLM\\sam*")>-1 or
                    CommandLine[0].strip().find("*save*HKLM\\system*")>-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") Tried to dump registry "+CommandLine[0]+ SourceImage[0].strip() +" )"
                    except:
                        Event_desc="[T1003] Credential Dumping - Registry Save"
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

                # [T1004] Winlogon Helper DLL
                if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") and (
                    TargetObject[0].strip().find("\\software\\microsoft\\windows nt\\currentversion\\winlogon\\user_nameinit\\")>-1 or
                    TargetObject[0].strip().find("\\software\\microsoft\\windows nt\\currentversion\\winlogon\\shell\\")>-1 or
                    TargetObject[0].strip().find("\\software\\microsoft\\windows nt\\currentversion\\winlogon\\notify\\")>-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") accessed target image ("+TargetImage[0].strip()+ ") through source image ( "+ SourceImage[0].strip() +" )"
                    except:
                        Event_desc="[T1004] Winlogon Helper DLL"
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

                # [T1004] Winlogon Helper DLL
                if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") and (
                    TargetObject[0].strip().find("\\software\\microsoft\\windows nt\\currentversion\\winlogon\\user_nameinit\\")>-1 or
                    TargetObject[0].strip().find("\\software\\microsoft\\windows nt\\currentversion\\winlogon\\shell\\")>-1 or
                    TargetObject[0].strip().find("\\software\\microsoft\\windows nt\\currentversion\\winlogon\\notify\\")>-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") accessed target image ("+TargetImage[0].strip()+ ") through source image ( "+ SourceImage[0].strip() +" )"
                    except:
                        Event_desc="[T1004] Winlogon Helper DLL"
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
                if (EventID[0]=="1") and Image[0].strip().find("hh.exe")==-1:

                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( "+ Image[0].strip() +" )"
                    except:
                        Event_desc="[T1223] Compiled HTML File"
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


                # [T1218] Signed Binary Proxy Execution - Network
                if (EventID[0]=="3") and (Image[0].strip().find("certutil.exe")>-1 or
                                        CommandLine[0].strip().find("*certutil*script\\:http\\[\\:\\]\\/\\/*")>-1 or
                                        Image[0].strip().find("*\\replace.exe")>-1):

                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                    except:
                        Event_desc="[T1218] Signed Binary Proxy Execution - Network"
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

                # [T1216] Signed Script Proxy Execution
                #if (EventID[0]=="1") and (CommandLine[0].strip().find("*firefox*places.sqlite*")>-1):

                #    Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) trying to discover browser bookmark"
                #    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                #    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
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

                # [T1209] Boot or Logon Autostart Execution: Time Providers
                if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") and (
                    TargetObject[0].strip().find("\\system\\currentcontrolset\\services\\w32time\\timeproviders\\")>-1):
                    try:
                        Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) to hijack time provider"
                    except:
                        Event_desc="[T1209] Boot or Logon Autostart Execution: Time Providers"
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

                # [T1202] Indirect Command Execution
                if EventID[0]=="1":
                    if ParentImage[0].strip().find("pcalua.exe")>-1:
                        Event_desc="Found User (" + User[0].strip() + ") through process name ("+ParentImage[0].strip()+ ") tried indirect command execution through commandline ( "+CommandLine[0].strip() +" )"

                    if (Image[0].strip().find("pcalua.exe")>-1 or
                        Image[0].strip().find("bash.exe")>-1 or
                        Image[0].strip().find("forfiles.exe")>-1):
                        Event_desc="Found User (" + User[0].strip() + ") through process name ("+Image[0].strip()+ ") tried accessing powershell history through commandline ( "+CommandLine[0].strip() +" )"

                    Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                    Sysmon_events[0]['Detection Rule'].append('# [T1202] Indirect Command Execution')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("Medium")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(EventID[0])
                    Sysmon_events[0]['Original Event Log'].append(str(record['data']).replace("\r"," "))

                # [T1201] Password Policy Discovery
                if (EventID[0]=="1") :
                    if (CommandLine[0].strip().find("net accounts")>-1 or CommandLine[0].strip().find("net accounts \\/domain")>-1):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) tried discovering password policy through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1201] Password Policy Discovery"
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

                # [T1197] BITS Jobs - Process
                if (EventID[0]=="1") :
                    if (Image[0].strip().find("bitsamin.exe")>-1 or CommandLine[0].strip().find("Start-BitsTransfer")>-1):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1197] BITS Jobs - Process"
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

                # [T1197] BITS Jobs - Network
                if (EventID[0]=="3") :
                    if (Image[0].strip().find("bitsadmin.exe")>-1):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1197] BITS Jobs - Network"
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

                # [T1196] Control Panel Items - Process
                if (EventID[0]=="1") :
                    if (CommandLine[0].strip().find("control \\/name")>-1 or
                                        CommandLine[0].strip().find("rundll32 shell32.dll,Control_RunDLL")):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " to acess control panel)"
                        except:
                            Event_desc="[T1196] Control Panel Items - Process"
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

                # [T1191] Signed Binary Proxy Execution: CMSTP
                if (EventID[0]=="1") :
                    if (Image[0].strip().find("CMSTP.exe")>-1):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " )"
                        except:
                            Event_desc="[T1191] Signed Binary Proxy Execution: CMSTP"
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

                # [T1183] Image File Execution Options Injection
                if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") :
                    if (
                    TargetObject[0].strip().find("\\software\\microsoft\\windows nt\\currentversion\\image file execution options\\")>-1 or
                    TargetObject[0].strip().find("\\wow6432node\\microsoft\\windows nt\\currentversion\\image file execution options\\")>-1):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") accessed target image ("+TargetImage[0].strip()+ ") through source image ( "+ SourceImage[0].strip() +" )"
                        except:
                            Event_desc="[T1183] Image File Execution Options Injection"
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

                # [T1182] AppCert DLLs Registry Modification
                if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") :
                    if (
                    TargetObject[0].strip().find("\\system\\currentcontrolset\\control\\session manager\\appcertdlls\\")>-1):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") accessed target image ("+TargetImage[0].strip()+ ") through source image ( "+ SourceImage[0].strip() +" )"
                        except:
                            Event_desc="[T1182] AppCert DLLs Registry Modification"
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

                # [T1179] Hooking detected
                if (EventID[0]=="1") :
                    if (Image[0].strip().find("mavinject.exe")>-1 or CommandLine[0].strip().find("/INJECTRUNNING")>-1):
                        try:

                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1179] Hooking detected"
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

                #  [T1170] Detecting  Mshta - Process
                if EventID[0]=="1" :
                    if ( Image[0].strip().find("\\mshta.exe")>-1 or CommandLine[0].strip().find("\\mshta.exe")>-1 ):

                        try:

                            Event_desc="Found User (" + User[0].strip() + ") Trying to run mshta with Command Line (" + CommandLine[0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )"
                        except:
                            Event_desc="[T1170] Detecting Mshta Exection "
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

                #  [T1170] Detecting  Mshta - Network
                if EventID[0]=="3" :
                    if ( ParentCommandLine[0].strip().find("\\mshta.exe")>-1 or CommandLine[0].strip().find("\\mshta.exe")>-1 ):

                        try:

                            Event_desc="Found User (" + User[0].strip() + ") Trying to run mshta with Command Line (" + CommandLine[0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )"
                        except:
                            Event_desc="[T1170] Detecting  Mshta"
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

                #  [T1158] Hidden Files and Directories - VSS
                if EventID[0]=="1" and ( Image[0].strip().find("*\\volumeshadowcopy*\\*")>-1 or CommandLine[0].strip().find("*\\volumeshadowcopy*\\*")>-1 ):

                    Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) accessing volume shadow copy hidden files and directories"
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

                #  [T1158] Hidden Files and Directories
                if EventID[0]=="1" and ( Image[0].strip().find("attrib.exe")>-1 and (CommandLine[0].strip().find("+h")>-1 or CommandLine[0].strip().find("+s")>-1) ):

                    Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) accessing hidden files and directories"
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

                # [T1146] Clear Command History
                if EventID[0]=="1" and ( CommandLine[0].strip().find("*rm (Get-PSReadlineOption).HistorySavePath*")>-1 or
                                        CommandLine[0].strip().find("*del (Get-PSReadlineOption).HistorySavePath*")>-1 or
                                        CommandLine[0].strip().find("*Set-PSReadlineOption –HistorySaveStyle SaveNothing*")>-1 or
                                        CommandLine[0].strip().find("*Remove-Item (Get-PSReadlineOption).HistorySavePath*")>-1 ):

                    Event_desc="Found User (" + User[0].strip() + ") through process name ("+Image[0].strip()+ ") tried clearing powershell history through commandline ( "+CommandLine[0].strip() +" )"
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

                #  [T1140] Deobfuscate/Decode Files or Information
                if EventID[0]=="1" and ( Image[0].strip().find("certutil.exe")>-1 and (CommandLine[0].strip().find("decode")>-1) ):

                    Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) tried decoding file or information"
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

                # [T1138] Application Shimming - Registry
                if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") and (
                    TargetObject[0].strip().find("\\software\\microsoft\\windows nt\\currentversion\\appcompatflags\\installedsdb\\")>-1):

                    Event_desc="Found User (" + User[0].strip() + ") accessed target image ("+TargetImage[0].strip()+ ") through source image ( "+ SourceImage[0].strip() +" ) shimming application through registry"
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

                # [T1138] Application Shimming - process
                if (EventID[0]=="1") and (Image[0].strip().find("sdbinst.exe")>-1):

                    Event_desc="Found User (" + User[0].strip() + ") accessed target image ("+TargetImage[0].strip()+ ") through source image ( "+ SourceImage[0].strip() +" ) shimming application through process"
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

                # [T1136] Create Account
                if EventID[0]=="1" and ( CommandLine[0].strip().find("New-LocalUser")>-1 or
                                        CommandLine[0].strip().find("net user add")>-1 ):

                    Event_desc="Found User (" + User[0].strip() + ") through process name ("+Image[0].strip()+ ") tried creating user through commandline ( "+CommandLine[0].strip() +" )"
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

                #  [T1135] Network Share Discovery - Process
                if EventID[0]=="1" and ( Image[0].strip().find("net.exe")>-1 and
                                       ( CommandLine[0].strip().find("net view")>-1 or
                                         CommandLine[0].strip().find("net share")>-1 or
                                         CommandLine[0].strip().find("get-smbshare -Name")>-1)):

                    Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) tried discovering network share through process"
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

                # [T1131] Authentication Package
                if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") and (
                    TargetObject[0].strip().find("*\\system\\currentcontrolset\\control\\lsa\\*")>-1 and (
                    Image[0].strip().find("c:\\windows\\system32\\lsass.exe")==-1 or
                    Image[0].strip().find("c:\\windows\\system32\\svchost.exe")==-1 or
                    Image[0].strip().find("c:\\windows\\system32\\services.exe")==-1)):

                    Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) to access authentication services by modifying registry"
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

                # [T1130]  Install Root Certificate
                if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") and (
                    Image[0].strip().find("c:\\windows\\system32\\lsass.exe")==-1 and (
                    TargetObject[0].strip().find("*\\software\\microsoft\\enterprisecertificates\\root\\certificates\\*")>-1 or
                    TargetObject[0].strip().find("*\\microsoft\\systemcertificates\\root\\certificates\\*")>-1)):

                    Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) tried to install root certificates"
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

                #  [T1128] Netsh Helper DLL - Process
                if EventID[0]=="1" and ( Image[0].strip().find("netsh.exe")>-1 and (CommandLine[0].strip().find("*helper*")>-1) ):

                    Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + ") "
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

                #  [T1128] Netsh Helper DLL - Registry
                if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") and (
                    TargetObject[0].strip().find("*\\software\\microsoft\\netsh\\*")>-1):

                    Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + ") "
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

                #  [T1127] Trusted Developer Utilities
                if EventID[0]=="1" and ( Image[0].strip().find("msbuild.exe")>-1 or Image[0].strip().find("msxsl.exe")>-1 ):

                    Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + ") "
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

                #  [T1124] System Time Discovery
                try:
                    if EventID[0]=="1":
                        if  ( Image[0].strip().find("*\\net.exe")>-1 and CommandLine[0].strip().find("*net* time*")>-1 ) or (
                                                 Image[0].strip().find("w32tm.exe")>-1 and CommandLine[0].strip().find("*get-date*")>-1 ):
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) to alter system time"
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
                except:
                    print("issue with event : \n"+str(record['data']))
                #  [T1115] Audio Capture
                if EventID[0]=="1" :

                    if ( Image[0].strip().find("soundrecorder.exe")>-1 and ( CommandLine[0].strip().find("*get-audiodevice*")>-1 or CommandLine[0].strip().find("*windowsaudiodevice-powershell-cmdlet*")>-1 ) ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " ) to capture audio"
                        except:
                            Event_desc="Found User trying to capture audio"
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

                #  [T1122] Component Object Model Hijacking
                if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") :
                    if TargetObject[0].strip().find("\\Software\\Classes\\CLSID\\")>-1:
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + ") to hijack COM"
                        except:
                            Event_desc="Found User trying to hijack COM"
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

                #  [T1121] Regsvcs/Regasm
                if EventID[0]=="1":
                    if ( Image[0].strip().find("regsvcs.exe")>-1 or Image[0].strip().find("regasm.exe")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1121] Regsvcs/Regasm execution"
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

                #  [T1118] InstallUtil
                if EventID[0]=="1" :
                    if ( Image[0].strip().find("installutil.exe")>-1 and ( CommandLine[0].strip().find("\\/logfile= \\/LogToConsole=false \\/U")>-1 ) ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1118] InstallUtil Execution"
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

                #  [T1117] Regsvr32
                if EventID[0]=="1" :
                    if ( ParentImage[0].strip().find("\\regsvr32.exe")>-1 or Image[0].strip().find("\\regsvr32.exe")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1117] Regsvr32 Execution"
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

                #  [T1117] Bypassing Application Whitelisting
                if EventID[0]=="1" :
                    if ( Image[0].strip().find("regsvr32.exe")>-1 or Image[0].strip().find("rundll32.exe")>-1 or Image[0].strip().find("certutil.exe")>-1 ) or ( CommandLine[0].strip().find("scrobj.dll")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1117] Bypassing Application Whitelisting "
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

                #  [T1115] Clipboard Data
                if EventID[0]=="1" :
                    if ( Image[0].strip().find("clip.exe")>-1 or CommandLine[0].strip().find("*Get-Clipboard*")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1115] Clipboard Data Collection "
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

                # [T1103]  AppInit DLLs Usage
                if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") :
                    if (
                    TargetObject[0].strip().find("\\software\\microsoft\\windows nt\\currentversion\\windows\\appinit_dlls\\")>-1 or
                    TargetObject[0].strip().find("\\software\\wow6432node\\microsoft\\windows nt\\currentversion\\windows\\appinit_dlls\\")>-1):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1103]  AppInit DLLs Usage"
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

    ##############################################reached
                #  [T1096] Hide Artifacts: NTFS File Attributes
                if EventID[0]=="1" :
                    if ( Image[0].strip().find("fsutil.exe")>-1 or
                                         CommandLine[0].strip().find("*usn*deletejournal*")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1096] Hide Artifacts: NTFS File Attributes"
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

                # [T1088] Bypass User Account Control - Registry
                if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") :
                    if (
                    TargetObject[0].strip().find("*\\mscfile\\shell\\open\\command\\*")>-1 or
                    TargetObject[0].strip().find("*\\ms-settings\\shell\\open\\command\\*")>-1):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1088] Bypass User Account Control - Registry"
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

                #  [T1088] Bypass User Account Control - Process
                if EventID[0]=="1" :
                    if ( Image[0].strip().find("ShellRunas.exe")>-1 or
                                         ParentCommandLine[0].strip().find("eventvwr.exe")>-1 or
                                         ParentCommandLine[0].strip().find("fodhelper.exe")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1088] Bypass User Account Control - Process"
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

                #  [T1086] PowerShell Downloads - Process
                if EventID[0]=="1" :
                    if ( ParentCommandLine[0].strip().find("*.Download*")>-1 or
                                         ParentCommandLine[0].strip().find("*Net.WebClient*")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1086] PowerShell Downloads - Process"
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

                #  [T1086] PowerShell Process found
                if EventID[0]=="1" :
                    if ( Image[0].strip().find("powershell.exe")>-1 or
                                         Image[0].strip().find("powershell_ise.exe")>-1  ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1086] PowerShell Process found "
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

                #  [T1085] Rundll32 Execution detected
                if EventID[0]=="1" :
                    if ( Image[0].strip().find("\\rundll32.exe")>-1 or
                                         Image[0].strip().find("rundll32.exe")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1085] Rundll32 Execution detected"
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

                #  [T1082] System Information Discovery
                if EventID[0]=="1" :
                    if ( Image[0].strip().find("sysinfo.exe")>-1 or
                                         Image[0].strip().find("reg.exe")>-1 ) and CommandLine[0].strip().find("reg*query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum")>-1:
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc='[T1082] System Information Discovery'
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

                #  [T1081] Credentials in Files
                if EventID[0]=="1" :
                    if ( CommandLine[0].strip().find("*findstr* /si pass*")>-1 or
                                         CommandLine[0].strip().find("*select-string -Pattern pass*")>-1 or
                                         CommandLine[0].strip().find("*list vdir*/text:password*")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1081] Credentials in Files"
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

                #  [T1077] Windows Admin Shares - Process - Created
                if EventID[0]=="1" :
                    if ( Image[0].strip().find("net.exe")>-1 or
                                         CommandLine[0].strip().find("net share")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1077] Windows Admin Shares - Process - Created"
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

                # [T1076] Remote Desktop Protocol - Process
                if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") :
                    if ( Image[0].strip().find("logonui.exe")>-1 or TargetObject[0].strip().find("\\software\\policies\\microsoft\\windows nt\\terminal services\\")>-1):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1076] Remote Desktop Protocol - Process"
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

                # [T1076] Remote Desktop Protocol - Registry
                if EventID[0]=="1" :
                    if ( Image[0].strip().find("tscon.exe")>-1 or
                                         Image[0].strip().find("mstsc.exe")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1076] Remote Desktop Protocol - Registry"
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

                #  [T1070] Indicator removal on host
                if EventID[0]=="1" :
                    if ( Image[0].strip().find("wevtutil")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1070] Indicator removal on host"
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

                # [T1060] Registry Run Keys or Start Folder
                if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") :
                    if (
                    TargetObject[0].strip().find("*\\software\\microsoft\\windows\\currentversion\\run*")>-1 or
                    TargetObject[0].strip().find("*\\software\\microsoft\\windows\\currentversion\\explorer\\*shell folders")>-1):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1060] Registry Run Keys or Start Folder"
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

                #  [T1059] Command-Line Interface
                if EventID[0]=="1" :
                    if ( Image[0].strip().find("cmd.exe")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1059] Command-Line Interface"
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

                #  [1057] Running Process Discovery
                if EventID[0]=="1" :
                    if ( CommandLine[0].strip().find("tasklist")>-1 or CommandLine[0].strip().find("get-process")>-1  ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[1057] Process Discovery"
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

                #  [T1054] Indicator Blocking - Driver unloaded
                if EventID[0]=="1" :
                    if ( Image[0].strip().find("fltmc.exe")>-1 or CommandLine[0].strip().find("*fltmc*unload*")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1054] Indicator Blocking - Driver unloaded"
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

                #  [T1053] Scheduled Task - Process
                if EventID[0]=="1" :
                    if ( Image[0].strip().find("taskeng.exe")>-1 or
                                         Image[0].strip().find("schtasks.exe")>-1 or (
                                         Image[0].strip().find("svchost.exe")>-1 and
                                         ParentCommandLine[0].strip().find("C:\\Windows\\System32\\services.exe")==-1 ) ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1053] Scheduled Task - Process"
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

                #  [T1047] Windows Management Instrumentation - Process
                if EventID[0]=="1" :
                    if ( ParentCommandLine[0].strip().find("wmiprvse.exe")>-1 or
                                         Image[0].strip().find("wmic.exe")>-1 or
                                         CommandLine[0].strip().find("wmic")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1047] Windows Management Instrumentation - Process"
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

                #  [T1047] Windows Management Instrumentation - Network
                if EventID[0]=="3" :
                    if ( Image[0].strip().find("wmic.exe")>-1 or
                                         CommandLine[0].strip().find("wmic")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1047] Windows Management Instrumentation - Network"
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

                #  [T1047] Windows Management Instrumentation - Instances of an Active Script Event Consumer - Process
                if EventID[0]=="1" :
                    if ( ParentCommandLine[0].strip().find("wmiprvse.exe")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1047] Windows Management Instrumentation - Instances of an Active Script Event Consumer - Process"
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

                #  [T1047] Windows Management Instrumentation - Instances of an Active Script Event Consumer - FileAccess
                if EventID[0]=="1" :
                    if ( CommandLine[0].strip().find("c:\\windows\\system32\\wbem\\scrcons.exe")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1047] Windows Management Instrumentation - Instances of an Active Script Event Consumer - FileAccess"
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

                #  [T1037] Boot or Logon Initialization Scripts
                if EventID[0]=="1" :
                    if ( CommandLine[0].strip().find("*reg*add*hkcu\\environment*userinitmprlogonscript*")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1037] Boot or Logon Initialization Scripts"
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

                #  [T1027] Obfuscated Files or Information
                if EventID[0]=="1" :
                    if ( Image[0].strip().find("certutil.exe")>-1 and
                                         CommandLine[0].strip().find("encode")>-1 ) or (
                                         CommandLine[0].strip().find("tobase64string")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1027] Obfuscated Files or Information"
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

                #  [T1018] Remote System Discovery - Process
                if EventID[0]=="1" and ( Image[0].strip().find("net.exe")>-1 or
                                         Image[0].strip().find("ping.exe")>-1 ) and (
                                         CommandLine[0].strip().find("view")>-1 or
                                         CommandLine[0].strip().find("png")>-1 ):
                        try:

                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1018] Remote System Discovery - Process"
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

                # [T1015] Accessibility Features - Registry
                if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") :
                    if (
                    TargetObject[0].strip().find("hklm\\software\\microsoft\\windows nt\\currentversion\\image file execution options\\*")>-1):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") accessed target image ("+TargetImage[0].strip()+ ") through source image ( "+ SourceImage[0].strip() +" )"
                        except:
                            Event_desc="[T1015] Accessibility Features - Registry"
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

                #  [T1015] Accessibility features
                if EventID[0]=="3" :
                    if ParentImage[0].strip().find("winlogon.exe")>-1 and (
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

                # [T1013] Local Port Monitor
                if (EventID[0]=="12" or EventID[0]=="13" or EventID[0]=="14") :
                    if (
                    TargetObject[0].strip().find("\system\\currentcontrolset\\control\\print\\monitors\\")>-1):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") accessed target image ("+TargetImage[0].strip()+ ") through source image ( "+ SourceImage[0].strip() +" )"
                        except:
                            Event_desc="[T1013] Local Port Monitor"
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

                #  [T1012] Query Registry - Process
                if EventID[0]=="1" :
                    if ( Image[0].strip().find("reg.exe")>-1 and
                                         CommandLine[0].strip().find("reg query")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1012] Query Registry - Process"
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

                #  [T1012] Query Registry - Network
                if EventID[0]=="3" :
                    if ( Image[0].strip().find("reg.exe")>-1 and
                                         CommandLine[0].strip().find("reg query")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc="[T1012] Query Registry - Network"
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

                #  [T1012] Processes opening handles and accessing Lsass with potential dlls in memory (i.e UNKNOWN in CallTrace)
                if EventID[0]=="10" :
                    if ( TargetImage[0].strip().find("lsass.exe")>-1 and
                                          CallTrace[0].strip().find("unknown")>-1 ):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                        except:
                            Event_desc='[T1012] Processes opening handles and accessing Lsass with potential dlls in memory'
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

                #  [T1059] processes loading PowerShell DLL *system.management.automation*
                if EventID[0]=="7" :
                    if (Description[0].strip().find("system.management.automation")>-1 or ImageLoaded[0].strip().find("system.management.automation")>-1):
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) loaded ( " + ImageLoaded[0].strip() + " )."
                        except:
                            Event_desc="[T1059] processes loading PowerShell DLL *system.management.automation*"
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

                #  [T1059] PSHost* pipes found in PowerShell execution
                if EventID[0]=="17" :
                    if PipeName[0].strip().find("\\pshost")>-1:
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) started command ( " + PipeName[0].strip() + " )."
                        except:
                            Event_desc="[T1059] PSHost* pipes found in PowerShell execution"
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


                #  [T1112] process updating UseLogonCredential registry key value
                if EventID[0]=="13" :
                    if TargetObject[0].strip().find("UseLogonCredential")>-1:
                        try:
                            Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) updating ( " + TargetObject[0].strip() + " )."
                        except:
                            Event_desc="[T1112] process updating UseLogonCredential registry key value"
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

            else:
                print(record['data'])


"""            #  [T1055] Process Injection - Process
            if EventID[0]=="1" :
                if ( CommandLine[0].strip().find("*invoke-dllinjection*")>-1 or CommandLine.strip().find("C:\\windows\\sysnative\\")>-1 ):
                    try:

                Event_desc="Found User (" + User[0].strip() + ") running image ( " + Image[0].strip() + " ) through command line ( " + CommandLine[0].strip() + " )"
                Sysmon_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    Sysmon_events[0]['Computer Name'].append(Computer[0])
                    Sysmon_events[0]['Channel'].append(Channel[0])
                Sysmon_events[0]['Detection Rule'].append('[T1055] Process Injection - Process')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(EventID[0])
"""
"""                #Detect any log that contain suspicious process name or argument
                for i in all_suspicious:

                    if record['data'].lower().find(i.lower())>-1:

                        #print("##### " + record["timestamp"] + " ####  ", end='')
                        #print("## Found Suspicios Process ", end='')
                        #print("User Name : ( %s ) " % Account_Name[0][0].strip(), end='')
                        #print("with Command Line : ( " + Process_Command_Line[0][0].strip() + " )")
                        # print("###########")

                        Event_desc ="Found a log contain suspicious powershell command ( %s)"%i
                        System_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                    System_events[0]['Computer Name'].append(Computer[0])
                    System_events[0]['Channel'].append(Channel[0])
                        System_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        System_events[0]['Detection Rule'].append("Suspicious Command or process found in the log")
                        System_events[0]['Detection Domain'].append("Threat")
                        System_events[0]['Severity'].append("Critical")
                        System_events[0]['Service Name'].append("None")
                        System_events[0]['Event Description'].append(Event_desc)
                        System_events[0]['Event ID'].append(EventID[0])
                        System_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " "))
                        break
"""
