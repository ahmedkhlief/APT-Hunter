import csv
import re
from netaddr import *
import xml.etree.ElementTree as ET
import pandas as pd
from datetime import datetime
minlength=1000

account_op={}
PasswordSpray={}
Suspicious_executables=['pl.exe','nc.exe','nmap.exe','psexec.exe','plink.exe','mimikatz','procdump.exe',' dcom.exe',' Inveigh.exe',' LockLess.exe',' Logger.exe',' PBind.exe',' PS.exe',' Rubeus.exe',' RunasCs.exe',' RunAs.exe',' SafetyDump.exe',' SafetyKatz.exe',' Seatbelt.exe',' SExec.exe',' SharpApplocker.exe',' SharpChrome.exe',' SharpCOM.exe',' SharpDPAPI.exe',' SharpDump.exe',' SharpEdge.exe',' SharpEDRChecker.exe',' SharPersist.exe',' SharpHound.exe',' SharpLogger.exe',' SharpPrinter.exe',' SharpRoast.exe',' SharpSC.exe',' SharpSniper.exe',' SharpSocks.exe',' SharpSSDP.exe',' SharpTask.exe',' SharpUp.exe',' SharpView.exe',' SharpWeb.exe',' SharpWMI.exe',' Shhmon.exe',' SweetPotato.exe',' Watson.exe',' WExec.exe','7zip.exe']

Suspicious_powershell_commands=['Get-WMIObject','Get-GPPPassword','Get-Keystrokes','Get-TimedScreenshot','Get-VaultCredential','Get-ServiceUnquoted','Get-ServiceEXEPerms','Get-ServicePerms','Get-RegAlwaysInstallElevated','Get-RegAutoLogon','Get-UnattendedInstallFiles','Get-Webconfig','Get-ApplicationHost','Get-PassHashes','Get-LsaSecret','Get-Information','Get-PSADForestInfo','Get-KerberosPolicy','Get-PSADForestKRBTGTInfo','Get-PSADForestInfo','Get-KerberosPolicy','Invoke-Command','Invoke-Expression','iex','Invoke-Shellcode','Invoke--Shellcode','Invoke-ShellcodeMSIL','Invoke-MimikatzWDigestDowngrade','Invoke-NinjaCopy','Invoke-CredentialInjection','Invoke-TokenManipulation','Invoke-CallbackIEX','Invoke-PSInject','Invoke-DllEncode','Invoke-ServiceUserAdd','Invoke-ServiceCMD','Invoke-ServiceStart','Invoke-ServiceStop','Invoke-ServiceEnable','Invoke-ServiceDisable','Invoke-FindDLLHijack','Invoke-FindPathHijack','Invoke-AllChecks','Invoke-MassCommand','Invoke-MassMimikatz','Invoke-MassSearch','Invoke-MassTemplate','Invoke-MassTokens','Invoke-ADSBackdoor','Invoke-CredentialsPhish','Invoke-BruteForce','Invoke-PowerShellIcmp','Invoke-PowerShellUdp','Invoke-PsGcatAgent','Invoke-PoshRatHttps','Invoke-PowerShellTcp','Invoke-PoshRatHttp','Invoke-PowerShellWmi','Invoke-PSGcat','Invoke-Encode','Invoke-Decode','Invoke-CreateCertificate','Invoke-NetworkRelay','EncodedCommand','New-ElevatedPersistenceOption','wsman','Enter-PSSession','DownloadString','DownloadFile','Out-Word','Out-Excel','Out-Java','Out-Shortcut','Out-CHM','Out-HTA','Out-Minidump','HTTP-Backdoor','Find-AVSignature','DllInjection','ReflectivePEInjection','Base64','System.Reflection','System.Management','Restore-ServiceEXE','Add-ScrnSaveBackdoor','Gupt-Backdoor','Execute-OnTime','DNS_TXT_Pwnage','Write-UserAddServiceBinary','Write-CMDServiceBinary','Write-UserAddMSI','Write-ServiceEXE','Write-ServiceEXECMD','Enable-DuplicateToken','Remove-Update','Execute-DNSTXT-Code','Download-Execute-PS','Execute-Command-MSSQL','Download_Execute','Copy-VSS','Check-VM','Create-MultipleSessions','Run-EXEonRemote','Port-Scan','Remove-PoshRat','TexttoEXE','Base64ToString','StringtoBase64','Do-Exfiltration','Parse_Keys','Add-Exfiltration','Add-Persistence','Remove-Persistence','Find-PSServiceAccounts','Discover-PSMSSQLServers','Discover-PSMSExchangeServers','Discover-PSInterestingServices','Discover-PSMSExchangeServers','Discover-PSInterestingServices','Mimikatz','powercat','powersploit','PowershellEmpire','Payload','GetProcAddress','ICM','.invoke',' -e ','hidden','-w hidden']

Suspicious_powershell_Arguments=["-EncodedCommand","-enc","-w hidden","[Convert]::FromBase64String","iex(","New-Object","Net.WebClient","-windowstyle hidden","DownloadFile","DownloadString","Invoke-Expression","Net.WebClient","-Exec bypass" ,"-ExecutionPolicy bypass"]

TerminalServices_Summary=[{'User':[],'Number of Logins':[]}]
Security_Authentication_Summary=[{'User':[],'Number of Failed Logins':[],'Number of Successful Logins':[]}]
Executed_Process_Summary=[{'Process Name':[],'Number of Execution':[]}]

critical_services=["Software Protection","Network List Service","Network Location Awareness","Windows Event Log"]

Sysmon_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[]}]
WinRM_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[]}]
Security_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[]}]
System_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Service Name':[],'Event Description':[],'Event ID':[],'Original Event Log':[]}]
ScheduledTask_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Schedule Task Name':[],'Event Description':[],'Event ID':[],'Original Event Log':[]}]
Powershell_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[]}]
Powershell_Operational_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[]}]
TerminalServices_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[]}]
Windows_Defender_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[]}]
Timesketch_events=[{'message':[],'timestamp':[],'datetime':[],'timestamp_desc':[],'Event Description':[],'Severity':[],'Detection Domain':[],'Event ID':[],'Original Event Log':[]}]

#=======================
#Regex for security logs
Logon_Type_rex = re.compile('Logon Type:\t{1,15}(\d{1,4})', re.IGNORECASE)

#Account_Name_rex = re.compile('Account Name:\t{1,15}(.*)', re.IGNORECASE)
Account_Name_rex = re.compile('Account Name:(.*)', re.IGNORECASE)

Security_ID_rex = re.compile('Security ID:\t{1,15}(.*)', re.IGNORECASE)

Account_Domain_rex = re.compile('Account Domain:\t{1,15}(.*)', re.IGNORECASE)

Workstation_Name_rex = re.compile('Workstation Name:\t{1,15}(.*)', re.IGNORECASE)

Source_Network_Address_rex = re.compile('Source Network Address:\t{1,15}(.*)', re.IGNORECASE)

Logon_Process_rex = re.compile('Logon Process:\t{1,15}(.*)', re.IGNORECASE)

Key_Length_rex = re.compile('Key Length:\t{1,15}(\d{1,4})', re.IGNORECASE)

Process_Command_Line_rex=re.compile('Process Command Line:\t{1,15}(.*)', re.IGNORECASE)

Group_Name_rex=re.compile('Group Name:\t{1,15}(.*)', re.IGNORECASE)

Task_Name_rex=re.compile('Task Name: \t{1,10}(.*)', re.IGNORECASE)

Task_Command_rex=re.compile('<Command>(.*)</Command>', re.IGNORECASE)

Task_args_rex=re.compile('<Arguments>(.*)</Arguments>', re.IGNORECASE)

Process_Name_sec_rex = re.compile('Process Name:\t{1,15}(.*)', re.IGNORECASE)

Category_sec_rex= re.compile('Category:\t{1,15}(.*)', re.IGNORECASE)

Subcategory_rex= re.compile('Subcategory:\t{1,15}(.*)', re.IGNORECASE)

Changes_rex= re.compile('Changes:\t{1,15}(.*)', re.IGNORECASE)


#=======================
#Regex for windows defender logs

Name_rex = re.compile('\t{1,15}Name: (.*)', re.IGNORECASE)

Severity_rex = re.compile('\t{1,15}Severity: (.*)', re.IGNORECASE)

Category_rex = re.compile('\t{1,15}Category: (.*)', re.IGNORECASE)

Path_rex = re.compile('\t{1,15}Path: (.*)', re.IGNORECASE)

Defender_User_rex = re.compile('\t{1,15}User: (.*)', re.IGNORECASE)

Process_Name_rex = re.compile('\t{1,15}Process Name: (.*)', re.IGNORECASE)

Action_rex = re.compile('\t{1,15}Action: (.*)', re.IGNORECASE)

#=======================
#Regex for system logs

Service_Name_rex = re.compile('Service Name: (.*)', re.IGNORECASE)
Service_File_Name_rex = re.compile('Service File Name: (.*)', re.IGNORECASE)
Service_Type_rex = re.compile('Service Type: (.*)', re.IGNORECASE)
Service_Account_rex = re.compile('Service Account: (.*)', re.IGNORECASE)
Service_and_state_rex = re.compile('The (.*) service entered the (.*) state\.', re.IGNORECASE)
StartType_rex = re.compile('The start type of the (.*) service was changed', re.IGNORECASE)
Service_Start_Type_rex = re.compile('Service Start Type: (.*)', re.IGNORECASE)


#=======================
#Regex for task scheduler logs
task_register_rex = re.compile('User \"(.*)\"  registered Task Scheduler task \"(.*)\"', re.IGNORECASE)
task_update_rex = re.compile('User \"(.*)\"  updated Task Scheduler task \"(.*)\"', re.IGNORECASE)
task_delete_rex = re.compile('User \"(.*)\"  deleted Task Scheduler task \"(.*)\"', re.IGNORECASE)


#======================
#Regex for powershell operational logs
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
Source_Network_Address_Terminal_rex= re.compile('Source Network Address: ((\d{1,3}\.){3}\d{1,3})')
User_Terminal_rex=re.compile('User: (.*)')
Session_ID_rex=re.compile('Session ID: (.*)')
#======================
#Microsoft-Windows-WinRM logs
Connection_rex=re.compile("""The connection string is: (.*)""")
#User_ID_rex=re.compile("""<Security UserID=\'(?<UserID>.*)\'\/><\/System>""")
#src_device_rex=re.compile("""<Computer>(?<src>.*)<\/Computer>""")
#======================
#Sysmon Logs
Sysmon_CommandLine_rex=re.compile("CommandLine: (.*)")
Sysmon_ProcessGuid_rex=re.compile("ProcessGuid: (.*)")
Sysmon_ProcessId_rex=re.compile("ProcessId: (.*)")
Sysmon_Image_rex=re.compile("Image: (.*)")
Sysmon_FileVersion_rex=re.compile("FileVersion: (.*)")
Sysmon_Company_rex=re.compile("Company: (.*)")
Sysmon_Product_rex=re.compile("Product: (.*)")
Sysmon_Description_rex=re.compile("Description: (.*)")
Sysmon_User_rex=re.compile("User: (.*)")
Sysmon_LogonGuid_rex=re.compile("LogonGuid: (.*)")
Sysmon_TerminalSessionId_rex=re.compile("TerminalSessionId: (.*)")
Sysmon_Hashes_MD5_rex=re.compile("MD5=(.*),")
Sysmon_Hashes_SHA256_rex=re.compile("SHA256=(.*)")
Sysmon_ParentProcessGuid_rex=re.compile("ParentProcessGuid: (.*)")
Sysmon_ParentProcessId_rex=re.compile("ParentProcessId: (.*)")
Sysmon_ParentImage_rex=re.compile("ParentImage: (.*)")
Sysmon_ParentCommandLine_rex=re.compile("ParentCommandLine: (.*)")
Sysmon_CurrentDirectory_rex=re.compile("CurrentDirectory: (.*)")
Sysmon_OriginalFileName_rex=re.compile("OriginalFileName: (.*)")
Sysmon_TargetObject_rex=re.compile("TargetObject: (.*)")
#########
#Sysmon  event ID 3
Sysmon_Protocol_rex=re.compile("Protocol: (.*)")
Sysmon_SourceIp_rex=re.compile("SourceIp: (.*)")
Sysmon_SourceHostname_rex=re.compile("SourceHostname: (.*)")
Sysmon_SourcePort_rex=re.compile("SourcePort: (.*)")
Sysmon_DestinationIp_rex=re.compile("DestinationIp: (.*)")
Sysmon_DestinationHostname_rex=re.compile("DestinationHostname: (.*)")
Sysmon_DestinationPort_rex=re.compile("DestinationPort: (.*)")
#########
#Sysmon  event ID 8
Sysmon_StartFunction_rex=re.compile("StartFunction: (.*)")
Sysmon_StartModule_rex=re.compile("StartModule: (.*)")
Sysmon_TargetImage_rex=re.compile("TargetImage: (.*)")
Sysmon_SourceImage_rex=re.compile("SourceImage: (.*)")
Sysmon_SourceProcessId_rex=re.compile("SourceProcessId: (.*)")
Sysmon_SourceProcessGuid_rex=re.compile("SourceProcessGuid: (.*)")
Sysmon_TargetProcessGuid_rex=re.compile("TargetProcessGuid: (.*)")
Sysmon_TargetProcessId_rex=re.compile("TargetProcessId: (.*)")


def detect_events_security_log(file_name='deep-blue-secuity.csv',winevent=False):
    #global Logon_Type_rex,Account_Name_rex,Account_Domain_rex,Workstation_Name_rex,Source_Network_Address_rex
    with open(file_name, newline='') as csvfile:

        # list = csv.reader(csvfile,delimiter=',',quotechar='"')
        """if winevent==True:
            list2 = csv.DictReader(csvfile, fieldnames=('Level', 'Date and Time', 'Source', 'Event ID', 'Task Category', 'Details',))
        else:
            list2 = csv.DictReader(csvfile,
                               fieldnames=('Event ID',"MachineName","Data","Index","Category","CategoryNumber","EntryType","Details","Source","ReplacementStrings","InstanceId", 'Date and Time',"TimeWritten","UserName","Site","Container"))

        """
        if open(file_name,"r").read(1000).find("\"InstanceId\",\"TimeGenerated\"")>0:
            list2 = csv.DictReader(csvfile,
                                   fieldnames=('Event ID', "MachineName", "Data", "Index", "Category", "CategoryNumber",
                                               "EntryType", "Details", "Source", "ReplacementStrings", "InstanceId",
                                               'Date and Time', "TimeWritten", "UserName", "Site", "Container"))
        else:
            list2 = csv.DictReader(csvfile, fieldnames=(
            'Level', 'Date and Time', 'Source', 'Event ID', 'Task Category', 'Details',))
        for row in list2:
            if row['Details']==None:
                continue

            Logon_Type = Logon_Type_rex.findall(row['Details'])

            Account_Name = Account_Name_rex.findall(row['Details'])

            Account_Domain = Account_Domain_rex.findall(row['Details'])

            Workstation_Name = Workstation_Name_rex.findall(row['Details'])

            Source_IP = Source_Network_Address_rex.findall(row['Details'])

            Logon_Process = Logon_Process_rex.findall(row['Details'])

            Key_Length = Key_Length_rex.findall(row['Details'])

            Security_ID = Security_ID_rex.findall(row['Details'])

            Group_Name = Group_Name_rex.findall(row['Details'])

            Task_Name=Task_Name_rex.findall(row['Details'])

            Task_Command = Task_Command_rex.findall(row['Details'])

            Task_args= Task_args_rex.findall(row['Details'])

            Process_Name=Process_Name_sec_rex.findall(row['Details'])

            Category=Category_sec_rex.findall(row['Details'])

            Subcategory=Subcategory_rex.findall(row['Details'])

            Changes=Changes_rex.findall(row['Details'])

            Process_Command_Line = Process_Command_Line_rex.findall(row['Details'])
            #User Cretion using Net command
            if row['Event ID']=="4688":
                try:
                    if len(re.findall('.*user.*/add.*',row['Details']))>0:
                        #print("test")

                        #print("##### " + row['Date and Time'] + " ####  ", end='')
                        #print("## High ## User Added using Net Command ",end='')
                        #print("User Name : ( %s ) "%Account_Name[0].strip(),end='')
                        #print("with Command Line : ( " + Process_Command_Line[0].strip()+" )")

                        Event_desc ="User Name : ( %s ) "%Account_Name[0].strip()+"with Command Line : ( " + Process_Command_Line[0].strip()+" )"
                        Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                        Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                        Security_events[0]['Detection Rule'].append("User Added using Net Command")
                        Security_events[0]['Detection Domain'].append("Audit")
                        Security_events[0]['Severity'].append("Critical")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(row['Event ID'])
                        Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r", " "))

                    #Detecting privielge Escalation using Token Elevation
                    if len(re.findall(r"cmd.exe /c echo [a-z]{6} > \\\.\\pipe\\\w{1,10}",process_command_line))>0:

                            Event_desc ="User Name : ( %s ) " % user+"conducting NAMED PIPE privilege escalation with Command Line : ( " + process_command_line + " ) "
                            Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                            Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                            Security_events[0]['Detection Rule'].append("Suspected privielge Escalation attempt using NAMED PIPE")
                            Security_events[0]['Detection Domain'].append("Threat")
                            Security_events[0]['Severity'].append("Critical")
                            Security_events[0]['Event Description'].append(Event_desc)
                            Security_events[0]['Event ID'].append(row['Event ID'])
                            Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r", " "))

                    if Process_Command_Line[0].strip().lower().find("\\temp\\")>-1 or  Process_Command_Line[0].strip().lower().find("\\tmp\\")>-1 or  Process_Command_Line[0].strip().lower().find("\\program data\\")>-1:
                        # print("test")

                        #print("##### " + row['Date and Time'] + " ####  ", end='')
                        #print("## Process running in temp ", end='')
                        #print("User Name : ( %s ) " % Account_Name[0].strip(), end='')
                        #print("with Command Line : ( " + Process_Command_Line[0].strip() + " )")
                        # print("###########")
                        Event_desc ="User Name : ( %s ) " % Account_Name[0].strip()+" with Command Line : ( " + Process_Command_Line[0].strip() + " )"
                        Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                        Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                        Security_events[0]['Detection Rule'].append("Process running in suspicious location")
                        Security_events[0]['Detection Domain'].append("Threat")
                        Security_events[0]['Severity'].append("Critical")
                        Security_events[0]['Event Description'].append(Event_desc)
                        Security_events[0]['Event ID'].append(row['Event ID'])
                        Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r", " "))

                    for i in Suspicious_executables:

                        if Process_Command_Line[0].strip().lower().find(i.lower())>-1:

                            #print("##### " + row['Date and Time'] + " ####  ", end='')
                            #print("## Found Suspicios Process ", end='')
                            #print("User Name : ( %s ) " % Account_Name[0].strip(), end='')
                            #print("with Command Line : ( " + Process_Command_Line[0].strip() + " )")
                            # print("###########")
                            Event_desc ="User Name : ( %s ) " % Account_Name[0].strip()+"with Command Line : ( " + Process_Command_Line[0].strip() + " ) contain suspicious command ( %s)"%i
                            Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                            Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                            Security_events[0]['Detection Rule'].append("Suspicious Process Found")
                            Security_events[0]['Detection Domain'].append("Threat")
                            Security_events[0]['Severity'].append("Critical")
                            Security_events[0]['Event Description'].append(Event_desc)
                            Security_events[0]['Event ID'].append(row['Event ID'])
                            Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r", " "))

                    for i in Suspicious_powershell_commands:

                        if Process_Command_Line[0].strip().lower().find(i.lower())>-1:

                            #print("##### " + row['Date and Time'] + " ####  ", end='')
                            #print("## Found Suspicios Process ", end='')
                            #print("User Name : ( %s ) " % Account_Name[0].strip(), end='')
                            #print("with Command Line : ( " + Process_Command_Line[0].strip() + " )")
                            # print("###########")
                            Event_desc ="User Name : ( %s ) " % Account_Name[0].strip()+"with Command Line : ( " + Process_Command_Line[0].strip() + " ) contain suspicious command ( %s)"%i
                            Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                            Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                            Security_events[0]['Detection Rule'].append("Suspicious Process Found")
                            Security_events[0]['Detection Domain'].append("Threat")
                            Security_events[0]['Severity'].append("Critical")
                            Security_events[0]['Event Description'].append(Event_desc)
                            Security_events[0]['Event ID'].append(row['Event ID'])
                            Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r", " "))


                except:
                    print("Error parsing below Event \n"+row['Details'])

                    continue

            # User Created through management interface
            if row['Event ID']=="4720":
                #print("##### " + row['Date and Time'] + " ####  ", end='')
                #print("User Name ( " + Account_Name[0].strip() + " )", end='')
                #print(" Created User Name ( " + Account_Name[1].strip()+ " )")
                try:
                    Event_desc="User Name ( " + Account_Name[0].strip() + " )" + " Created User Name ( " + Account_Name[1].strip()+ " )"

                except:
                    Event_desc="User Created a new user "
                Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Security_events[0]['Detection Rule'].append("User Created through management interface")
                Security_events[0]['Detection Domain'].append("Audit")
                Security_events[0]['Severity'].append("Medium")
                Security_events[0]['Event Description'].append(Event_desc)
                Security_events[0]['Event ID'].append(row['Event ID'])
                Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            # Windows is shutting down
            if row['Event ID']=="4609" or row['Event ID']=="1100":
                #print("##### " + row['Date and Time'] + " ####  ", end='')
                #print("User Name ( " + Account_Name[0].strip() + " )", end='')
                #print(" Created User Name ( " + Account_Name[1].strip()+ " )")

                Event_desc="Windows is shutting down "
                Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Security_events[0]['Detection Rule'].append("Windows is shutting down")
                Security_events[0]['Detection Domain'].append("Audit")
                Security_events[0]['Severity'].append("Medium")
                Security_events[0]['Event Description'].append(Event_desc)
                Security_events[0]['Event ID'].append(row['Event ID'])
                Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))




            # User added to local group
            if row['Event ID']=="4732":

                #print("##### " + row['Date and Time'] + " ####  ", end='')
                #print("User ( " + Account_Name[0].strip() + " ) added User ( "+Security_ID[1].strip(), end='')
                #print(" to local group ( " + Group_Name[0].strip() + " )")


                try :
                    Event_desc="User ( " + Account_Name[0].strip() + " ) added User ( "+Account_Name[1].strip()+" to local group ( " + Group_Name[0].strip() + " )"
                except:
                    Event_desc = "User ( " + Account_Name[0].strip() + " ) added User ( " + Security_ID[
                        1].strip() + " to Global group ( " + Group_Name[0].strip() + " )"


                Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Security_events[0]['Detection Rule'].append("User added to local group")
                Security_events[0]['Detection Domain'].append("Audit")
                Security_events[0]['Severity'].append("High")
                Security_events[0]['Event Description'].append(Event_desc)
                Security_events[0]['Event ID'].append(row['Event ID'])
                Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            #add user to global group
            if row['Event ID'] == "4728":

                #print("##### " + row['Date and Time'] + " ####  ", end='')
                #print("User ( " + Account_Name[0].strip() + " ) added User ( "+Security_ID[1].strip(), end='')
                #print(" to Global group ( " + Group_Name[0].strip() + " )")
                try :
                    Event_desc="User ( " + Account_Name[0].strip() + " ) added User ( "+Account_Name[1].strip()+" to Global group ( " + Group_Name[0].strip() + " )"
                except:
                    Event_desc = "User ( " + Account_Name[0].strip() + " ) added User ( " + Security_ID[
                        1].strip() + " to Global group ( " + Group_Name[0].strip() + " )"
                Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Security_events[0]['Detection Rule'].append("User added to global group")
                Security_events[0]['Detection Domain'].append("Audit")
                Security_events[0]['Severity'].append("High")
                Security_events[0]['Event Description'].append(Event_desc)
                Security_events[0]['Event ID'].append(row['Event ID'])
                Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            #add user to universal group
            if row['Event ID'] == "4756":

                #print("##### " + row['Date and Time'] + " ####  ", end='')
                #print("User ( " + Account_Name[0].strip() + " ) added User ( "+Security_ID[1].strip(), end='')
                Event_desc ="User ( " + Account_Name[0].strip() + " ) added User ( "+Security_ID[1].strip()
                if len(Group_Name)>0:
                    #print(" to Universal group ( " + Group_Name[0].strip() + " )")
                    Event_desc=Event_desc+" to Universal group ( " + Group_Name[0].strip() + " )"
                else:
                    Event_desc = Event_desc +" to Universal group ( " + Account_Name[1].strip() + " )"
                    #print(" to Universal group ( " + Account_Name[1].strip() + " )")


                Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Security_events[0]['Detection Rule'].append("User added to Universal group")
                Security_events[0]['Detection Domain'].append("Audit")
                Security_events[0]['Severity'].append("High")
                Security_events[0]['Event Description'].append(Event_desc)
                Security_events[0]['Event ID'].append(row['Event ID'])
                Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            #remove user from global group
            if row['Event ID'] == "4729":

                #print("##### " + row['Date and Time'] + " ####  ", end='')
                #print("User ( " + Account_Name[0].strip() + " ) removed User ( "+Security_ID[1].strip(), end='')
                Event_desc ="User ( " + Account_Name[0].strip() + " ) removed User ( "+Security_ID[1].strip()
                if len(Group_Name)>0:
                    #print(") from Global group ( " + Group_Name[0].strip() + " )")
                    Event_desc = Event_desc +") from Global group ( " + Group_Name[0].strip() + " )"
                else:
                    Event_desc = Event_desc +") from Global group ( " + Account_Name[1].strip() + " )"
                    #print(") from Global group ( " + Account_Name[1].strip() + " )")


                Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Security_events[0]['Detection Rule'].append("User Removed from Global Group")
                Security_events[0]['Detection Domain'].append("Audit")
                Security_events[0]['Severity'].append("High")
                Security_events[0]['Event Description'].append(Event_desc)
                Security_events[0]['Event ID'].append(row['Event ID'])
                Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            #remove user from universal group
            if row['Event ID'] == "4757":
                #print("##### " + row['Date and Time'] + " ####  ", end='')
                #print("User ( " + Account_Name[0].strip() + " ) removed User ( "+Security_ID[1].strip(), end='')
                Event_desc ="User ( " + Account_Name[0].strip() + " ) removed User ( "+Security_ID[1].strip()
                if len(Group_Name)>0:
                    #print(") from Universal group ( " + Group_Name[0].strip() + " )")
                    Event_desc = Event_desc+") from Universal group ( " + Group_Name[0].strip() + " )"
                else:
                    #print(") from Universal group ( " + Account_Name[1].strip() + " )")
                    Event_desc = Event_desc +") from Universal group ( " + Account_Name[1].strip() + " )"

                Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Security_events[0]['Detection Rule'].append("User Removed from Universal Group")
                Security_events[0]['Detection Domain'].append("Audit")
                Security_events[0]['Severity'].append("High")
                Security_events[0]['Event Description'].append(Event_desc)
                Security_events[0]['Event ID'].append(row['Event ID'])
                Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            #remove user from local group
            if row['Event ID'] == "4733":
                #print("##### " + row['Date and Time'] + " ####  ", end='')
                #print("User ( " + Account_Name[0].strip() + " ) removed User ( "+Security_ID[1].strip(), end='')
                Event_desc ="User ( " + Account_Name[0].strip() + " ) removed User ( "+Security_ID[1].strip()
                if len(Group_Name)>0:
                    #print(") from Local group ( " + Group_Name[0].strip() + " )")
                    Event_desc = Event_desc +") from Local group ( " + Group_Name[0].strip() + " )"
                else:
                    #print(") from Local group ( " + Account_Name[1].strip() + " )")
                    Event_desc = Event_desc +") from Local group ( " + Account_Name[1].strip() + " )"



                Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Security_events[0]['Detection Rule'].append("User Removed from Local Group")
                Security_events[0]['Detection Domain'].append("Audit")
                Security_events[0]['Severity'].append("High")
                Security_events[0]['Event Description'].append(Event_desc)
                Security_events[0]['Event ID'].append(row['Event ID'])
                Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))


            #user removed group
            if row['Event ID'] == "4730":
                print("##### " + row['Date and Time'] + " ####  ", end='')
                print("User ( " + Account_Name[0].strip() + " ) removed Group ( ", end='')
                Event_desc ="User ( " + Account_Name[0].strip() + " ) removed Group ( "
                if len(Group_Name)>0:
                    Event_desc = Event_desc +") from Local group ( " + Group_Name[0].strip() + " )"
                    #print(") from Local group ( " + Group_Name[0].strip() + " )")
                else:
                    Event_desc = Event_desc +") from Local group ( " + Account_Name[0].strip() + " )"
                    #print(") from Local group ( " + Account_Name[0].strip() + " )")


                Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Security_events[0]['Detection Rule'].append("User Removed Group")
                Security_events[0]['Detection Domain'].append("Audit")
                Security_events[0]['Severity'].append("High")
                Security_events[0]['Event Description'].append(Event_desc)
                Security_events[0]['Event ID'].append(row['Event ID'])
                Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            #user account removed
            if row['Event ID'] == "4726":
                #print("##### " + row['Date and Time'] + " ####  ", end='')
                #print("User ( " + Account_Name[0].strip() + " ) removed user ", end='')
                #print("( " + Account_Name[1].strip() + " )")

                Event_desc ="User ( " + Account_Name[0].strip() + " ) removed user "+"( " + Account_Name[1].strip() + " )"
                Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Security_events[0]['Detection Rule'].append("User Account Removed")
                Security_events[0]['Detection Domain'].append("Audit")
                Security_events[0]['Severity'].append("High")
                Security_events[0]['Event Description'].append(Event_desc)
                Security_events[0]['Event ID'].append(row['Event ID'])
                Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            #Summary of process Execution
            if row['Event ID']=="4688":
                try:

                    if Process_Command_Line[0] not in Executed_Process_Summary[0]['Process Name']:
                        Executed_Process_Summary[0]['Process Name'].append(Process_Command_Line[0].strip())
                        Executed_Process_Summary[0]['Number of Execution'].append(1)
                    else :
                        Executed_Process_Summary[0]['Number of Execution'][Executed_Process_Summary[0]['Process Name'].index(Process_Command_Line[0].strip())]=Executed_Process_Summary[0]['Number of Execution'][Executed_Process_Summary[0]['Process Name'].index(Process_Command_Line[0].strip())]+1
                except:
                    continue
            if row['Event ID'] == "4625" :
                try:
                    if Account_Name[1].strip() not in Security_Authentication_Summary[0]['User']:
                        Security_Authentication_Summary[0]['User'].append(Account_Name[1].strip())
                        Security_Authentication_Summary[0]['Number of Failed Logins'].append(1)
                        Security_Authentication_Summary[0]['Number of Successful Logins'].append(0)
                    else :
                        try:
                            Security_Authentication_Summary[0]['Number of Failed Logins'][
                                Security_Authentication_Summary[0]['User'].index(Account_Name[1].strip())] = \
                            Security_Authentication_Summary[0]['Number of Failed Logins'][
                                Security_Authentication_Summary[0]['User'].index(Account_Name[1].strip())] + 1
                        except:
                            print("User : "+Account_Name[1].strip() +  " array : ")
                            print(Security_Authentication_Summary[0])
                except:
                    continue
            #password spray detection
            if row['Event ID'] == "4648" :
                try:

                    if Account_Name[0].strip() not in PasswordSpray:
                        PasswordSpray[Account_Name[0].strip()]=[]
                        PasswordSpray[Account_Name[0].strip()].append(Account_Name[1].strip())
                    #else:
                    #    PasswordSpray[Account_Name[0].strip()].append(Account_Name[1].strip())
                    if Account_Name[1].strip() not in PasswordSpray[Account_Name[0].strip()] :
                        PasswordSpray[Account_Name[0].strip()].append(Account_Name[1].strip())
                except:
                    continue
#and (Logon_Type[0].strip()=="3" or Logon_Type[0].strip()=="10" or Logon_Type[0].strip()=="2" or Logon_Type[0].strip()=="8")
            if row['Event ID'] == "4624" :
                try:
                    #print(Account_Name[0])
                    if Account_Name[1].strip() not in Security_Authentication_Summary[0]['User']:
                        Security_Authentication_Summary[0]['User'].append(Account_Name[1].strip())
                        Security_Authentication_Summary[0]['Number of Successful Logins'].append(1)
                        Security_Authentication_Summary[0]['Number of Failed Logins'].append(0)
                    else :
                        Security_Authentication_Summary[0]['Number of Successful Logins'][
                            Security_Authentication_Summary[0]['User'].index(Account_Name[1].strip())] = \
                        Security_Authentication_Summary[0]['Number of Successful Logins'][
                            Security_Authentication_Summary[0]['User'].index(Account_Name[1].strip())] + 1
                except:
                    continue
            #detect pass the hash
            if row['Event ID'] == "4625" or row['Event ID'] == "4624":
                if Logon_Type[0].strip() == "3" and Account_Name[1].strip() != "ANONYMOUS LOGON" and Account_Name[1].strip().find("$")==-1 and Logon_Process[0].strip() == "NtLmSsp" and Key_Length[0].strip() == "0":
                    #print("##### " + row['Date and Time'] + " ####  ", end='')
                    #print(
                    #        "Pass the hash attempt Detected : user name ( %s ) domain name ( %s ) from  IP ( %s ) and machine name ( %s )" % (
                    #        Account_Name[1].strip(), Account_Domain[1].strip(), Source_IP[0].strip(), Workstation_Name[0].strip()))

                    Event_desc ="Pass the hash attempt Detected : user name ( %s ) domain name ( %s ) from  IP ( %s ) and machine name ( %s )" % (
                            Account_Name[1].strip(), Account_Domain[1].strip(), Source_IP[0].strip(), Workstation_Name[0].strip())
                    Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                    Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                    Security_events[0]['Detection Rule'].append("Pass the hash attempt Detected")
                    Security_events[0]['Detection Domain'].append("Threat")
                    Security_events[0]['Severity'].append("Critical")
                    Security_events[0]['Event Description'].append(Event_desc)
                    Security_events[0]['Event ID'].append(row['Event ID'])
                    Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            #Audit log cleared
            if row['Event ID'] == "517" or row['Event ID'] == "1102":
                    """print("##### " + row['Date and Time'] + " ####  ", end='')
                    print(
                            "Audit log cleared by user ( %s )" % (
                            Account_Name[0].strip()))
                    """
                    Event_desc = "Audit log cleared by user ( %s )" % (
                            Account_Name[0].strip())
                    Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                    Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                    Security_events[0]['Detection Rule'].append("Audit log cleared")
                    Security_events[0]['Detection Domain'].append("Audit")
                    Security_events[0]['Severity'].append("Critical")
                    Security_events[0]['Event Description'].append(Event_desc)
                    Security_events[0]['Event ID'].append(row['Event ID'])
                    Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            #Suspicious Attempt to enumerate users or groups
            if row['Event ID'] == "4798" or row['Event ID'] == "4799" and row['Details'].find("System32\\svchost.exe")==-1:
                    """print("##### " + row['Date and Time'] + " ####  ", end='')
                    print(
                            "Suspicious Attempt to enumerate groups by user ( %s ) using process ( %s )" % (
                            Account_Name[0].strip(),Process_Name[0].strip()))
                    """
                    Event_desc ="Suspicious Attempt to enumerate groups by user ( %s ) using process ( %s )" % (Account_Name[0].strip(),Process_Name[0].strip())
                    Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                    Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                    Security_events[0]['Detection Rule'].append("Suspicious Attempt to enumerate groups")
                    Security_events[0]['Detection Domain'].append("Audit")
                    Security_events[0]['Severity'].append("Medium")
                    Security_events[0]['Event Description'].append(Event_desc)
                    Security_events[0]['Event ID'].append(row['Event ID'])
                    Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            #System audit policy was changed

            if row['Event ID'] == "4719" and len(Security_ID)>0 and Security_ID[0].strip()!="S-1-5-18" and Security_ID[0].strip()!="SYSTEM"  :
                    """print("##### " + row['Date and Time'] + " ####  ", end='')
                    print(
                            "System audit policy was changed by user ( %s ) , Audit Poricly category ( %s ) , Subcategory ( %s ) with changes ( %s )" % (
                            Account_Name[0].strip(),Category[0].strip(),Subcategory[0].strip(),Changes[0].strip()))
                    """
                    try :
                        Event_desc ="System audit policy was changed by user ( %s ) , Audit Poricly category ( %s ) , Subcategory ( %s ) with changes ( %s )" % (Account_Name[0].strip(),Category[0].strip(),Subcategory[0].strip(),Changes[0].strip())
                    except :
                        Event_desc = "System audit policy was changed by user"
                    Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                    Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                    Security_events[0]['Detection Rule'].append("System audit policy was changed")
                    Security_events[0]['Detection Domain'].append("Audit")
                    Security_events[0]['Severity'].append("High")
                    Security_events[0]['Event Description'].append(Event_desc)
                    Security_events[0]['Event ID'].append(row['Event ID'])
                    Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r", " "))

            #scheduled task created
            if row['Event ID']=="4698" :
                #print("##### " + row['Date and Time'] + " ####  ", end='')

                #print("schedule task created by user ( %s ) with task name ( %s ) , Command ( %s ) and Argument ( %s )  " % ( Account_Name[0].strip(),Task_Name[0].strip(),Task_Command[0],Task_args[0]))
                try:
                    Event_desc ="schedule task created by user ( %s ) with task name ( %s ) , Command ( %s ) and Argument ( %s )  " % ( Account_Name[0].strip(),Task_Name[0].strip(),Task_Command[0],Task_args[0])
                except:
                    Event_desc = "schedule task created by user"
                Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Security_events[0]['Detection Rule'].append("schedule task created")
                Security_events[0]['Detection Domain'].append("Audit")
                Security_events[0]['Severity'].append("Critical")
                Security_events[0]['Event Description'].append(Event_desc)
                Security_events[0]['Event ID'].append(row['Event ID'])
                Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            #scheduled task deleted
            if row['Event ID']=="1699" :
                #print("##### " + row['Date and Time'] + " ####  ", end='')

                #print("schedule task deleted by user ( %s ) with task name ( %s ) , Command ( %s ) and Argument ( %s )  " % ( Account_Name[0].strip(),Task_Name[0].strip(),Task_Command[0],Task_args[0]))
                try :
                    Event_desc ="schedule task deleted by user ( %s ) with task name ( %s ) , Command ( %s ) and Argument ( %s )  " % ( Account_Name[0].strip(),Task_Name[0].strip(),Task_Command[0],Task_args[0])
                except:
                    Event_desc = "schedule task deleted by user"
                Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Security_events[0]['Detection Rule'].append("schedule task deleted")
                Security_events[0]['Detection Domain'].append("Audit")
                Security_events[0]['Severity'].append("High")
                Security_events[0]['Event Description'].append(Event_desc)
                Security_events[0]['Event ID'].append(row['Event ID'])
                Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            #schedule task updated
            if row['Event ID']=="4702" :
                #print("##### " + row['Date and Time'] + " ####  ", end='')

                #print("schedule task updated by user ( %s ) with task name ( %s ) , Command ( %s ) and Argument ( %s )  " % ( Account_Name[0].strip(),Task_Name[0].strip(),Task_Command[0],Task_args[0]))
                try:
                    Event_desc ="schedule task updated by user ( %s ) with task name ( %s ) , Command ( %s ) and Argument ( %s )  " % ( Account_Name[0].strip(),Task_Name[0].strip(),Task_Command[0],Task_args[0])
                except:
                    Event_desc = "schedule task updated by user"
                Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Security_events[0]['Detection Rule'].append("schedule task updated")
                Security_events[0]['Detection Domain'].append("Audit")
                Security_events[0]['Severity'].append("Medium")
                Security_events[0]['Event Description'].append(Event_desc)
                Security_events[0]['Event ID'].append(row['Event ID'])
                Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            #schedule task enabled
            if row['Event ID']=="4700" :
                #print("##### " + row['Date and Time'] + " ####  ", end='')

                #print("schedule task enabled by user ( %s ) with task name ( %s )  " % ( Account_Name[0].strip(),Task_Name[0].strip(),Task_Command[0],Task_args[0]))
                try :
                    Event_desc ="schedule task enabled by user ( %s ) with task name ( %s )  " % ( Account_Name[0].strip(),Task_Name[0].strip(),Task_Command[0],Task_args[0])
                except:
                    Event_desc = "schedule task enabled by user"
                Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Security_events[0]['Detection Rule'].append("schedule task enabled")
                Security_events[0]['Detection Domain'].append("Audit")
                Security_events[0]['Severity'].append("Medium")
                Security_events[0]['Event Description'].append(Event_desc)
                Security_events[0]['Event ID'].append(row['Event ID'])
                Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            #schedule task disabled
            if row['Event ID']=="4701" :
                print("##### " + row['Date and Time'] + " ####  ", end='')

                #print("schedule task disabled by user ( %s ) with task name ( %s ) " % ( Account_Name[0].strip(),Task_Name[0].strip(),Task_Command[0],Task_args[0]))
                try :
                    Event_desc ="schedule task disabled by user ( %s ) with task name ( %s ) " % ( Account_Name[0].strip(),Task_Name[0].strip(),Task_Command[0],Task_args[0])
                except:
                    Event_desc = "schedule task disabled by user"
                Security_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Security_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Security_events[0]['Detection Rule'].append("schedule task disabled")
                Security_events[0]['Detection Domain'].append("Audit")
                Security_events[0]['Severity'].append("High")
                Security_events[0]['Event Description'].append(Event_desc)
                Security_events[0]['Event ID'].append(row['Event ID'])
                Security_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

    for user in PasswordSpray:
        if len(PasswordSpray[user])>3:
            Event_desc = "Password Spray Detected by user ( "+user+" )"
            Security_events[0]['Date and Time'].append(datetime.timestamp(datetime.now()))
            Security_events[0]['timestamp'].append(datetime.timestamp(datetime.now()))
            Security_events[0]['Detection Rule'].append("Password Spray Detected")
            Security_events[0]['Detection Domain'].append("Threat")
            Security_events[0]['Severity'].append("High")
            Security_events[0]['Event Description'].append(Event_desc)
            Security_events[0]['Event ID'].append("4648")
            Security_events[0]['Original Event Log'].append("User ( "+user+" ) did password sparay attack using usernames ( "+",".join(PasswordSpray[user])+" )")


def detect_events_windows_defender_log(file_name='Defender-logs.csv',winevent=False):
    with open(file_name, newline='') as csvfile:
        """if winevent == True:
            list = csv.DictReader(csvfile, fieldnames=('Level', 'Date and Time', 'Source', 'Event ID', 'Task Category', 'Details',))
        else:
            list = csv.DictReader(csvfile,fieldnames=("Details","Event ID","Version","Qualifiers","Level","Task","Opcode","Keywords","RecordId","ProviderName","ProviderId","LogName","ProcessId","ThreadId","MachineName","UserId","Date and Time","ActivityId","RelatedActivityId","ContainerLog","MatchedQueryIds","Bookmark","LevelDisplayName","OpcodeDisplayName","TaskDisplayName","KeywordsDisplayNames","Properties"))
"""
        if open(file_name,"r").read(1000).find("\"Message\",\"Id\",\"Version\"")>0:
            list = csv.DictReader(csvfile, fieldnames=(
            "Details", "Event ID", "Version", "Qualifiers", "Level", "Task", "Opcode", "Keywords", "RecordId",
            "ProviderName", "ProviderId", "LogName", "ProcessId", "ThreadId", "MachineName", "UserId", "Date and Time",
            "ActivityId", "RelatedActivityId", "ContainerLog", "MatchedQueryIds", "Bookmark", "LevelDisplayName",
            "OpcodeDisplayName", "TaskDisplayName", "KeywordsDisplayNames", "Properties"))

        else:
            list = csv.DictReader(csvfile, fieldnames=(
            'Level', 'Date and Time', 'Source', 'Event ID', 'Task Category', 'Details',))

        for row in list:
            if row['Details']==None:
                continue
            Name = Name_rex.findall(row['Details'])
            Severity = Severity_rex.findall(row['Details'])
            Category = Category_rex.findall(row['Details'])
            Path = Path_rex.findall(row['Details'])
            User = Defender_User_rex.findall(row['Details'])
            Process_Name = Process_Name_rex.findall(row['Details'])
            Action = Action_rex.findall(row['Details'])

            #Windows Defender took action against Malware
            if row['Event ID']=="1117" or row['Event ID']=="1007" :
                #print("##### " + row['Date and Time'] + " ####  ", end='')
                #print(" Windows Defender took action against Malware - details : Severity ( %s ) , Name ( %s ) , Action ( %s ) , Catgeory ( %s ) , Path ( %s ) , Process Name ( %s ) , User ( %s ) "%(Severity[0].strip(),Name[0].strip(),Action[0].strip(),Category[0].strip(),Path[0].strip(),Process_Name[0].strip(),User[0]))
                Event_desc="Windows Defender took action against Malware - details : Severity ( %s ) , Name ( %s ) , Action ( %s ) , Catgeory ( %s ) , Path ( %s ) , Process Name ( %s ) , User ( %s ) "%(Severity[0].strip(),Name[0].strip(),Action[0].strip(),Category[0].strip(),Path[0].strip(),Process_Name[0].strip(),User[0].strip())
                Windows_Defender_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Windows_Defender_events[0]['Detection Rule'].append("Windows Defender took action against Malware")
                Windows_Defender_events[0]['Detection Domain'].append("Threat")
                Windows_Defender_events[0]['Severity'].append("High")
                Windows_Defender_events[0]['Event Description'].append(Event_desc)
                Windows_Defender_events[0]['Event ID'].append(row['Event ID'])
                Windows_Defender_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            #Windows Defender failed to take action against Malware
            if  row['Event ID']=="1118" or row['Event ID']=="1008" or row['Event ID']=="1119":
                #print("##### " + row['Date and Time'] + " ####  ", end='')
                #print("Windows Defender failed to take action against Malware - details : Severity ( %s ) , Name ( %s ) , Action ( %s ) , Catgeory ( %s ) , Path ( %s ) , Process Name ( %s ) , User ( %s ) "%(Severity[0].strip(),Name[0].strip(),Action[0].strip(),Category[0].strip(),Path[0].strip(),Process_Name[0].strip(),User[0]))

                Event_desc="Windows Defender failed to take action against Malware - details : Severity ( %s ) , Name ( %s ) , Action ( %s ) , Catgeory ( %s ) , Path ( %s ) , Process Name ( %s ) , User ( %s ) "%(Severity[0].strip(),Name[0].strip(),Action[0].strip(),Category[0].strip(),Path[0].strip(),Process_Name[0].strip(),User[0])

                Windows_Defender_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Windows_Defender_events[0]['Detection Rule'].append("Windows Defender failed to take action against Malware")
                Windows_Defender_events[0]['Detection Domain'].append("Threat")
                Windows_Defender_events[0]['Severity'].append("Critical")
                Windows_Defender_events[0]['Event Description'].append(Event_desc)
                Windows_Defender_events[0]['Event ID'].append(row['Event ID'])
                Windows_Defender_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            if row['Event ID'] == "1116" or row['Event ID']=="1006":
                #print("##### " + row['Date and Time'] + " ####  ", end='')
                #print(" Windows Defender Found Malware - details : Severity ( %s ) , Name ( %s ) , Catgeory ( %s ) , Path ( %s ) , Process Name ( %s ) , User ( %s ) "%(Severity[0].strip(),Name[0].strip(),Category[0].strip(),Path[0].strip(),Process_Name[0].strip(),User[0]))

                Event_desc="Windows Defender Found Malware - details : Severity ( %s ) , Name ( %s ) , Catgeory ( %s ) , Path ( %s ) , Process Name ( %s ) , User ( %s ) "%(Severity[0].strip(),Name[0].strip(),Category[0].strip(),Path[0].strip(),Process_Name[0].strip(),User[0])
                Windows_Defender_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Windows_Defender_events[0]['Detection Rule'].append("Windows Defender Found Malware")
                Windows_Defender_events[0]['Detection Domain'].append("Threat")
                Windows_Defender_events[0]['Severity'].append("Critical")
                Windows_Defender_events[0]['Event Description'].append(Event_desc)
                Windows_Defender_events[0]['Event ID'].append(row['Event ID'])
                Windows_Defender_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            if  row['Event ID']=="1013":
                #print("##### " + row['Date and Time'] + " ####  ", end='')
                #print(" Windows Defender deleted history of malwares - details : User ( %s ) "%(User[0]))

                Event_desc=" Windows Defender deleted history of malwares - details : User ( %s ) "%(User[0])
                Windows_Defender_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Windows_Defender_events[0]['Detection Rule'].append("Windows Defender deleted history of malwares")
                Windows_Defender_events[0]['Detection Domain'].append("Audit")
                Windows_Defender_events[0]['Severity'].append("High")
                Windows_Defender_events[0]['Event Description'].append(Event_desc)
                Windows_Defender_events[0]['Event ID'].append(row['Event ID'])
                Windows_Defender_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            if  row['Event ID'] == "1015" :
                #print("##### " + row['Date and Time'] + " ####  ", end='')
                #print(" Windows Defender detected suspicious behavious Malware - details : Severity ( %s ) , Name ( %s ) , Catgeory ( %s ) , Path ( %s ) , Process Name ( %s ) , User ( %s ) "%(Severity[0].strip(),Name[0].strip(),Category[0].strip(),Path[0].strip(),Process_Name[0].strip(),User[0]))

                Event_desc="Windows Defender detected suspicious behavior Malware - details : Severity ( %s ) , Name ( %s ) , Catgeory ( %s ) , Path ( %s ) , Process Name ( %s ) , User ( %s ) "%(Severity[0].strip(),Name[0].strip(),Category[0].strip(),Path[0].strip(),Process_Name[0].strip(),User[0])
                Windows_Defender_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Windows_Defender_events[0]['Detection Rule'].append("Windows Defender detected suspicious behavior Malware")
                Windows_Defender_events[0]['Detection Domain'].append("Threat")
                Windows_Defender_events[0]['Severity'].append("Critical")
                Windows_Defender_events[0]['Event Description'].append(Event_desc)
                Windows_Defender_events[0]['Event ID'].append(row['Event ID'])
                Windows_Defender_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            if  row['Event ID'] == "5001" :
                #print("##### " + row['Date and Time'] + " ####  ", end='')
                #print("Windows Defender real-time protection disabled")

                Event_desc="Windows Defender real-time protection disabled"
                Windows_Defender_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Windows_Defender_events[0]['Detection Rule'].append("Windows Defender real-time protection disabled")
                Windows_Defender_events[0]['Detection Domain'].append("Audit")
                Windows_Defender_events[0]['Severity'].append("Critical")
                Windows_Defender_events[0]['Event Description'].append(Event_desc)
                Windows_Defender_events[0]['Event ID'].append(row['Event ID'])
                Windows_Defender_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            if  row['Event ID'] == "5004" :
                #print("##### " + row['Date and Time'] + " ####  ", end='')
                #print(" Windows Defender real-time protection configuration changed")

                Event_desc="Windows Defender real-time protection configuration changed"
                Windows_Defender_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Windows_Defender_events[0]['Detection Rule'].append("Windows Defender real-time protection configuration changed")
                Windows_Defender_events[0]['Detection Domain'].append("Audit")
                Windows_Defender_events[0]['Severity'].append("Critical")
                Windows_Defender_events[0]['Event Description'].append(Event_desc)
                Windows_Defender_events[0]['Event ID'].append(row['Event ID'])
                Windows_Defender_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            if  row['Event ID'] == "5007" :
                #print("##### " + row['Date and Time'] + " ####  ", end='')
                #print(" Windows Defender antimalware platform configuration changed")

                Event_desc="Windows Defender antimalware platform configuration changed"
                Windows_Defender_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Windows_Defender_events[0]['Detection Rule'].append("Windows Defender antimalware platform configuration changed")
                Windows_Defender_events[0]['Detection Domain'].append("Audit")
                Windows_Defender_events[0]['Severity'].append("Critical")
                Windows_Defender_events[0]['Event Description'].append(Event_desc)
                Windows_Defender_events[0]['Event ID'].append(row['Event ID'])
                Windows_Defender_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            if  row['Event ID'] == "5010" :
                #print("##### " + row['Date and Time'] + " ####  ", end='')
                #print(" Windows Defender scanning for malware is disabled")

                Event_desc="Windows Defender scanning for malware is disabled"
                Windows_Defender_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Windows_Defender_events[0]['Detection Rule'].append("Windows Defender scanning for malware is disabled")
                Windows_Defender_events[0]['Detection Domain'].append("Audit")
                Windows_Defender_events[0]['Severity'].append("Critical")
                Windows_Defender_events[0]['Event Description'].append(Event_desc)
                Windows_Defender_events[0]['Event ID'].append(row['Event ID'])
                Windows_Defender_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            if  row['Event ID'] == "5012" :
                print("##### " + row['Date and Time'] + " ####  ", end='')
                print(" Windows Defender scanning for viruses is disabled")

                Event_desc="Windows Defender scanning for viruses is disabled"
                Windows_Defender_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Windows_Defender_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Windows_Defender_events[0]['Detection Rule'].append("Windows Defender scanning for viruses is disabled")
                Windows_Defender_events[0]['Detection Domain'].append("Audit")
                Windows_Defender_events[0]['Severity'].append("Critical")
                Windows_Defender_events[0]['Event Description'].append(Event_desc)
                Windows_Defender_events[0]['Event ID'].append(row['Event ID'])
                Windows_Defender_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))


def detect_events_scheduled_task_log(file_name='Defender-logs.csv',winevent=False):
    with open(file_name, newline='') as csvfile:

        """if winevent==True:
            list =csv.DictReader(csvfile, fieldnames=('Level', 'Date and Time', 'Source', 'Event ID', 'Task Category', 'Details',))
        else:
            list = csv.DictReader(csvfile,
                              fieldnames=(
                              "Details", "Event ID", "Version", "Qualifiers", "Level", "Task", "Opcode", "Keywords",
                              "RecordId", "ProviderName", "ProviderId", "LogName", "ProcessId", "ThreadId",
                              "MachineName", "UserId", "Date and Time", "ActivityId", "RelatedActivityId",
                              "ContainerLog", "MatchedQueryIds", "Bookmark", "LevelDisplayName", "OpcodeDisplayName",
                              "TaskDisplayName", "KeywordsDisplayNames", "Properties"))
"""
        if open(file_name,"r").read(1000).find("\"Message\",\"Id\",\"Version\"")>0:
            list = csv.DictReader(csvfile, fieldnames=(
            "Details", "Event ID", "Version", "Qualifiers", "Level", "Task", "Opcode", "Keywords", "RecordId",
            "ProviderName", "ProviderId", "LogName", "ProcessId", "ThreadId", "MachineName", "UserId", "Date and Time",
            "ActivityId", "RelatedActivityId", "ContainerLog", "MatchedQueryIds", "Bookmark", "LevelDisplayName",
            "OpcodeDisplayName", "TaskDisplayName", "KeywordsDisplayNames", "Properties"))

        else:
            list = csv.DictReader(csvfile, fieldnames=(
            'Level', 'Date and Time', 'Source', 'Event ID', 'Task Category', 'Details',))

        for row in list:
            if row['Details']==None:
                continue
            task_register=task_register_rex.match(row['Details'])
            task_update = task_update_rex.match(row['Details'])
            task_delete = task_delete_rex.match(row['Details'])

            #schedule task registered
            if row['Event ID']=="106" :
                #print("##### " + row['Date and Time'] + " ####  ", end='')
                if task_register.group(1).strip()=="S-1-5-18" and task_register.group(2).find("\\Microsoft\\Windows\\WindowsUpdate")!=0:
                    #print("schedule task registered with Name ( %s ) by user ( NT AUTHORITY\SYSTEM ) " % (task_register.group(2)))
                    Event_desc ="schedule task registered with Name ( %s ) by user ( NT AUTHORITY\SYSTEM ) " % (task_register.group(2))
                else:
                    #print("schedule task registered with Name ( %s ) by user ( %s ) " % (
                    #    task_register.group(2), task_register.group(1)))
                    Event_desc ="schedule task registered with Name ( %s ) by user ( %s ) " % (task_register.group(2), task_register.group(1))


                ScheduledTask_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                ScheduledTask_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                ScheduledTask_events[0]['Detection Rule'].append("schedule task registered")
                ScheduledTask_events[0]['Detection Domain'].append("Audit")
                ScheduledTask_events[0]['Severity'].append("High")
                ScheduledTask_events[0]['Event Description'].append(Event_desc)
                ScheduledTask_events[0]['Schedule Task Name'].append(task_register.group(2))
                ScheduledTask_events[0]['Event ID'].append(row['Event ID'])
                ScheduledTask_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            #schedule task updated
            if row['Event ID']=="140" :
                #print("##### " + row['Date and Time'] + " ####  ", end='')
                if task_update.group(1).strip()=="S-1-5-18" and task_update.group(2).find("\\Microsoft\\Windows\\WindowsUpdate")!=0:
                    #print("schedule task updated with Name ( %s ) by user ( NT AUTHORITY\SYSTEM ) " % (task_update.group(2)))
                    Event_desc ="schedule task updated with Name ( %s ) by user ( NT AUTHORITY\SYSTEM ) " % (task_update.group(2))
                else:
                    #print("schedule task updated with Name ( %s ) by user ( %s ) " % (
                    #    task_update.group(2), task_update.group(1)))
                    Event_desc ="schedule task updated with Name ( %s ) by user ( %s ) " % (
                        task_update.group(2), task_update.group(1))

                ScheduledTask_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                ScheduledTask_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                ScheduledTask_events[0]['Detection Rule'].append("schedule task updated")
                ScheduledTask_events[0]['Detection Domain'].append("Audit")
                ScheduledTask_events[0]['Severity'].append("Medium")
                ScheduledTask_events[0]['Event Description'].append(Event_desc)
                ScheduledTask_events[0]['Event ID'].append(row['Event ID'])
                ScheduledTask_events[0]['Schedule Task Name'].append(task_update.group(2))
                ScheduledTask_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            # schedule task deleted
            if row['Event ID']=="141" :
                #print("##### " + row['Date and Time'] + " ####  ", end='')
                if task_delete.group(1).strip()=="S-1-5-18" and task_delete.group(2).find("\\Microsoft\\Windows\\WindowsUpdate")!=0:
                    #print("schedule task deleted with Name ( %s ) by user ( NT AUTHORITY\SYSTEM ) " % (task_delete.group(2)))
                    Event_desc ="schedule task deleted with Name ( %s ) by user ( NT AUTHORITY\SYSTEM ) " % (task_delete.group(2))
                else:
                    #print("schedule task deleted with Name ( %s ) by user ( %s ) " % (
                    #task_delete.group(2), task_delete.group(1)))
                    Event_desc ="schedule task deleted with Name ( %s ) by user ( %s ) " % (task_delete.group(2), task_delete.group(1))

                ScheduledTask_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                ScheduledTask_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                ScheduledTask_events[0]['Detection Rule'].append("schedule task deleted")
                ScheduledTask_events[0]['Detection Domain'].append("Audit")
                ScheduledTask_events[0]['Severity'].append("High")
                ScheduledTask_events[0]['Event Description'].append(Event_desc)
                ScheduledTask_events[0]['Schedule Task Name'].append(task_delete.group(2))
                ScheduledTask_events[0]['Event ID'].append(row['Event ID'])
                ScheduledTask_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))


def detect_events_system_log(file_name='system-logs.csv',winevent=False):

    with open(file_name, newline='') as csvfile:

        """if winevent==True:
            list =csv.DictReader(csvfile, fieldnames=('Level', 'Date and Time', 'Source', 'Event ID', 'Task Category', 'Details',))
        else:
            list = csv.DictReader(csvfile,
                              fieldnames=(
                              "Details", "Event ID", "Version", "Qualifiers", "Level", "Task", "Opcode", "Keywords",
                              "RecordId", "ProviderName", "ProviderId", "LogName", "ProcessId", "ThreadId",
                              "MachineName", "UserId", "Date and Time", "ActivityId", "RelatedActivityId",
                              "ContainerLog", "MatchedQueryIds", "Bookmark", "LevelDisplayName", "OpcodeDisplayName",
                              "TaskDisplayName", "KeywordsDisplayNames", "Properties"))
"""
        if open(file_name,"r").read(1000).find("\"Message\",\"Id\",\"Version\"")>0:
            list = csv.DictReader(csvfile, fieldnames=(
            "Details", "Event ID", "Version", "Qualifiers", "Level", "Task", "Opcode", "Keywords", "RecordId",
            "ProviderName", "ProviderId", "LogName", "ProcessId", "ThreadId", "MachineName", "UserId", "Date and Time",
            "ActivityId", "RelatedActivityId", "ContainerLog", "MatchedQueryIds", "Bookmark", "LevelDisplayName",
            "OpcodeDisplayName", "TaskDisplayName", "KeywordsDisplayNames", "Properties"))

        else:
            list = csv.DictReader(csvfile, fieldnames=(
            'Level', 'Date and Time', 'Source', 'Event ID', 'Task Category', 'Details',))


        for row in list:
            if row['Details']==None:
                continue
            Service_Account = Service_Account_rex.findall(row['Details'])
            Service_File_Name = Service_File_Name_rex.findall(row['Details'])
            Service_Type = Service_Type_rex.findall(row['Details'])
            Service_Name = Service_Name_rex.findall(row['Details'])
            Service_and_state=Service_and_state_rex.findall(row['Details'])
            Service_Start_Type=Service_Start_Type_rex.findall(row['Details'])
            Start_Type_Service_Name=StartType_rex.findall(row['Details'])

            # System Logs cleared
            if (row['Event ID']=="104") :
                Event_desc="System Logs Cleared"
                #System_events[0]['Date and Time'].append(datetime.strptime(record["timestamp"],'%Y-%m-%d %I:%M:%S.%f %Z').isoformat())
                System_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                System_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                System_events[0]['Detection Rule'].append(
                    "System Logs Cleared")
                System_events[0]['Detection Domain'].append("Audit")
                System_events[0]['Severity'].append("Critical")
                System_events[0]['Service Name'].append("N/A")
                System_events[0]['Event Description'].append(Event_desc)
                System_events[0]['Event ID'].append(row['Event ID'])
                System_events[0]['Original Event Log'].append(str(row['Details']).replace("\r", " "))

            if (row['Event ID']=="7045" or row['Event ID']=="601") and (row['Details'].strip().find("\\temp\\") > -1 or row['Details'].strip().find(
                    "\\tmp\\") > -1):
                Event_desc="Service Installed with executable in TEMP Folder"
                System_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                System_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                System_events[0]['Detection Rule'].append(
                    "Service Installed with executable in TEMP Folder ")
                System_events[0]['Detection Domain'].append("Threat")
                System_events[0]['Service Name'].append(Service_Name[0].strip())
                System_events[0]['Severity'].append("Critical")
                System_events[0]['Event Description'].append(Event_desc)
                System_events[0]['Event ID'].append(row['Event ID'])
                System_events[0]['Original Event Log'].append(str(row['Details']).replace("\r", " "))

            #Service installed in the system
            if row['Event ID']=="7045" or row['Event ID']=="601" :
                #print("##### " + row['Date and Time'] + " ####  ", end='')
                #print("Service installed in the system with Name ( %s ) , File Name ( %s ) , Service Type ( %s ) , Service Start Type ( %s ) , Service Account ( %s )"%(Service_Name[0].strip(),Service_File_Name[0].strip(),Service_Type[0].strip(),Service_Start_Type[0].strip(),Service_Account[0]))


                Event_desc="Service installed in the system with Name ( %s ) , File Name ( %s ) , Service Type ( %s ) , Service Start Type ( %s ) , Service Account ( %s )"%(Service_Name[0].strip(),Service_File_Name[0].strip(),Service_Type[0].strip(),Service_Start_Type[0].strip(),Service_Account[0])
                System_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                System_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                System_events[0]['Detection Rule'].append("Service installed in the system")
                System_events[0]['Detection Domain'].append("Audit")
                System_events[0]['Severity'].append("High")
                System_events[0]['Service Name'].append(Service_Name[0].strip())
                System_events[0]['Event Description'].append(Event_desc)
                System_events[0]['Event ID'].append(row['Event ID'])
                System_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            # Service entered new state
            #if (row['Event ID']=="7036" or row['Event ID']=="7040") and Service_and_state[0][0].strip() in critical_services and ( Service_and_state[0][1].strip()=="stopped" or Service_and_state[0][1].strip()=="disabled" ) :
            if row['Event ID']=="7036" and Service_and_state[0][0].strip() in critical_services and ( Service_and_state[0][1].strip()=="stopped" or Service_and_state[0][1].strip()=="disabled" ) :
                #print("##### " + row['Date and Time'] + " ####  ", end='')
                #print("Service with Name ( %s ) entered ( %s ) state "%(Service_and_state.group(1),Service_and_state.group(2)))
                #print(str(row['Details']).replace("\r"," "))
                Event_desc="Service with Name ( %s ) entered ( %s ) state "%(Service_and_state[0][1].strip(),Service_and_state[0][1].strip())
                System_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                System_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                System_events[0]['Detection Rule'].append("Service State Changed")
                System_events[0]['Detection Domain'].append("Audit")
                System_events[0]['Severity'].append("Medium")
                System_events[0]['Service Name'].append(Service_and_state[0][1].strip())
                System_events[0]['Event Description'].append(Event_desc)
                System_events[0]['Event ID'].append(row['Event ID'])
                System_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            #Service Start Type Changed
            if (row['Event ID']=="7040"  ) :
                #print("##### " + row['Date and Time'] + " ####  ", end='')
                #print("Service with Name ( %s ) entered ( %s ) state "%(Service_and_state.group(1),Service_and_state.group(2)))
                #print(str(row['Details']).replace("\r"," "))
                Event_desc="Service with Name ( %s ) changed start type"%(Start_Type_Service_Name[0].strip())
                System_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                System_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                System_events[0]['Detection Rule'].append("Service Start Type Changed")
                System_events[0]['Detection Domain'].append("Audit")
                System_events[0]['Severity'].append("Medium")
                System_events[0]['Service Name'].append(Start_Type_Service_Name[0].strip())
                System_events[0]['Event Description'].append(Event_desc)
                System_events[0]['Event ID'].append(row['Event ID'])
                System_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))



def detect_events_powershell_operational_log(file_name='powershell-logs.csv',winevent=False):

    with open(file_name, newline='') as csvfile:

        """
        if winevent==True:
            list =csv.DictReader(csvfile, fieldnames=('Level', 'Date and Time', 'Source', 'Event ID', 'Task Category', 'Details',))
        else:
            list = csv.DictReader(csvfile,
                              fieldnames=(
                              "Details", "Event ID", "Version", "Qualifiers", "Level", "Task", "Opcode", "Keywords",
                              "RecordId", "ProviderName", "ProviderId", "LogName", "ProcessId", "ThreadId",
                              "MachineName", "UserId", "Date and Time", "ActivityId", "RelatedActivityId",
                              "ContainerLog", "MatchedQueryIds", "Bookmark", "LevelDisplayName", "OpcodeDisplayName",
                              "TaskDisplayName", "KeywordsDisplayNames", "Properties"))
        """

        if open(file_name,"r").read(1000).find("\"Message\",\"Id\",\"Version\"")>0:
            list = csv.DictReader(csvfile, fieldnames=(
            "Details", "Event ID", "Version", "Qualifiers", "Level", "Task", "Opcode", "Keywords", "RecordId",
            "ProviderName", "ProviderId", "LogName", "ProcessId", "ThreadId", "MachineName", "UserId", "Date and Time",
            "ActivityId", "RelatedActivityId", "ContainerLog", "MatchedQueryIds", "Bookmark", "LevelDisplayName",
            "OpcodeDisplayName", "TaskDisplayName", "KeywordsDisplayNames", "Properties"))

        else:
            list = csv.DictReader(csvfile, fieldnames=(
            'Level', 'Date and Time', 'Source', 'Event ID', 'Task Category', 'Details',))

        for row in list:
            if row['Details']==None:
                continue
            Host_Application = Host_Application_rex.findall(row['Details'])
            User =User_rex.findall(row['Details'])
            Engine_Version = Engine_Version_rex.findall(row['Details'])
            Command_Name = Command_Name_rex.findall(row['Details'])
            Command_Type = Command_Type_rex.findall(row['Details'])
            Error_Message = Error_Message_rex.findall(row['Details'])
            Suspicious=[]
            host_app=""

            if row['Details'].strip().find("\\temp\\") > -1 or row['Details'].strip().find(
                    "\\tmp\\") > -1:
                Event_desc="Powershell  Operation including TEMP Folder"
                Powershell_Operational_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Powershell_Operational_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Powershell_Operational_events[0]['Detection Rule'].append(
                    "Powershell Module logging - Operation including TEMP folder ")
                Powershell_Operational_events[0]['Detection Domain'].append("Threat")
                Powershell_Operational_events[0]['Severity'].append("High")
                Powershell_Operational_events[0]['Event Description'].append(Event_desc)
                Powershell_Operational_events[0]['Event ID'].append(row['Event ID'])
                Powershell_Operational_events[0]['Original Event Log'].append(str(row['Details']).replace("\r", " "))


            #Powershell Module logging will record portions of scripts, some de-obfuscated code
            if row['Event ID']=="4103" :
                if len(Host_Application) == 0:
                    host_app = ""
                else:
                    host_app = Host_Application[0].strip()
                for i in Suspicious_powershell_commands:
                    if i in row['Details']:
                        Suspicious.append(i)

                if len(Suspicious)>0:
                    #print("##### " + row['Date and Time'] + " #### EventID=4103 ### Powershell Module logging #### ", end='')
                    #print("Found User ("+User[0].strip()+") run Suspicious PowerShell commands that include ("+",".join(Suspicious)+") in event with Command Name ("+Command_Name[0].strip()+") and full command ("+Host_Application[0].strip()+") ", end='')#, check event details "+row['Details'])
                    Event_desc = "Found User (" + User[
                        0].strip() + ") run Suspicious PowerShell commands that include (" + ",".join(
                        Suspicious) + ") in event with Command Name (" + Command_Name[
                                     0].strip() + ") and full command (" + host_app + ") "

                    if len(Error_Message)>0:
                        #print("Error Message ("+Error_Message[0].strip()+")")
                        Event_desc =Event_desc+"Error Message ("+Error_Message[0].strip()+")"
                    #else:
                        #print("")

                    Powershell_Operational_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                    Powershell_Operational_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                    Powershell_Operational_events[0]['Detection Rule'].append("Powershell Module logging - Malicious Commands Detected")
                    Powershell_Operational_events[0]['Detection Domain'].append("Threat")
                    Powershell_Operational_events[0]['Severity'].append("Critical")
                    Powershell_Operational_events[0]['Event Description'].append(Event_desc)
                    Powershell_Operational_events[0]['Event ID'].append(row['Event ID'])
                    Powershell_Operational_events[0]['Original Event Log'].append(str(row['Details']).replace("\r", " "))

            Suspicious = []
            #captures powershell script block Execute a Remote Command
            if row['Event ID']=="4104"  or row['Event ID']=="24577" :
                for i in Suspicious_powershell_commands:
                    if i in row['Details']:
                        Suspicious.append(i)

                if len(Suspicious)>0:
                    #print("##### " + row['Date and Time'] + " #### EventID=4104 #### powershell script block ####", end='')
                    #print("Found Suspicious PowerShell commands that include ("+",".join(Suspicious)+") , check event details "+row['Details'])

                    Event_desc ="Found Suspicious PowerShell commands that include ("+",".join(Suspicious)+") , check event details "+row['Details']
                    Powershell_Operational_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                    Powershell_Operational_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                    Powershell_Operational_events[0]['Detection Rule'].append("powershell script block - Found Suspicious PowerShell commands ")
                    Powershell_Operational_events[0]['Detection Domain'].append("Threat")
                    Powershell_Operational_events[0]['Severity'].append("Critical")
                    Powershell_Operational_events[0]['Event Description'].append(Event_desc)
                    Powershell_Operational_events[0]['Event ID'].append(row['Event ID'])
                    Powershell_Operational_events[0]['Original Event Log'].append(str(row['Details']).replace("\r", " "))
            Suspicious = []

            #capture PowerShell ISE Operation
            if row['Event ID']=="24577" :
                for i in Suspicious_powershell_commands:
                    if i in row['Details']:
                        Suspicious.append(i)

                if len(Suspicious)>0:
                    #print("##### " + row['Date and Time'] + " #### EventID=4104 #### PowerShell ISE Operation ####  ", end='')
                    #print("Found Suspicious PowerShell commands that include ("+",".join(Suspicious)+") , check event details "+row['Details'])


                    Event_desc ="Found Suspicious PowerShell commands that include ("+",".join(Suspicious)+") , check event details "+row['Details']
                    Powershell_Operational_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                    Powershell_Operational_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                    Powershell_Operational_events[0]['Detection Rule'].append("PowerShell ISE Operation - Found Suspicious PowerShell commands")
                    Powershell_Operational_events[0]['Detection Domain'].append("Threat")
                    Powershell_Operational_events[0]['Severity'].append("Critical")
                    Powershell_Operational_events[0]['Event Description'].append(Event_desc)
                    Powershell_Operational_events[0]['Event ID'].append(row['Event ID'])
                    Powershell_Operational_events[0]['Original Event Log'].append(str(row['Details']).replace("\r", " "))

            Suspicious = []

            #Executing Pipeline
            if row['Event ID']=="4100":
                if len(Host_Application) == 0:
                    host_app = ""
                else:
                    host_app = Host_Application[0].strip()
                for i in Suspicious_powershell_commands:
                    if row['Details'].find(i)>-1:
                        Suspicious.append(i)
                if len(Suspicious)>0:
                    #print("##### " + row['Date and Time'] + " #### EventID=4100 #### Executing Pipeline ####", end='')
                    #print("Found User ("+User[0].strip()+") run Suspicious PowerShell commands that include ("+",".join(Suspicious)+") in event with Command Name ("+Command_Name[0].strip()+") and full command ("+Host_Application[0].strip()+") ", end='')#, check event details "+row['Details'])
                    Event_desc = "Found User (" + User[
                        0].strip() + ") run Suspicious PowerShell commands that include (" + ",".join(
                        Suspicious) + ") in event with Command Name (" + Command_Name[
                                     0].strip() + ") and full command (" + host_app + ") "

                    if len(Error_Message)>0:
                        #print(Error_Message[0].strip())
                        Event_desc = Event_desc + "Error Message (" + Error_Message[0].strip() + ")"
                    #else:
                        #print("")
                    Powershell_Operational_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                    Powershell_Operational_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                    Powershell_Operational_events[0]['Detection Rule'].append("Powershell Executing Pipeline - Suspicious Powershell Commands detected")
                    Powershell_Operational_events[0]['Detection Domain'].append("Threat")
                    Powershell_Operational_events[0]['Severity'].append("Critical")
                    Powershell_Operational_events[0]['Event Description'].append(Event_desc)
                    Powershell_Operational_events[0]['Event ID'].append(row['Event ID'])
                    Powershell_Operational_events[0]['Original Event Log'].append(str(row['Details']).replace("\r", " "))

                else:
                    #print("##### " + row['Date and Time'] + " #### EventID=4100 #### Executing Pipeline #### ", end='')
                    #print("Found User ("+User[0].strip()+") run PowerShell with Command Name ("+Command_Name[0].strip()+") and full command ("+Host_Application[0].strip()+") ", end='')#, check event details "+row['Details'])
                    Event_desc = "Found User (" + User[0].strip() + ") run PowerShell with Command Name (" + \
                                 Command_Name[0].strip() + ") and full command (" + host_app + ") "
                    if len(Error_Message)>0:
                        #print("Error Message ("+Error_Message[0].strip()+")")
                        Event_desc = Event_desc + "Error Message ("+Error_Message[0].strip()+")"
                    #else:
                        #print("")

                    Powershell_Operational_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                    Powershell_Operational_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                    Powershell_Operational_events[0]['Detection Rule'].append("Powershell Executing Pipeline - User Powershell Commands ")
                    Powershell_Operational_events[0]['Detection Domain'].append("Audit")
                    Powershell_Operational_events[0]['Severity'].append("High")
                    Powershell_Operational_events[0]['Event Description'].append(Event_desc)
                    Powershell_Operational_events[0]['Event ID'].append(row['Event ID'])
                    Powershell_Operational_events[0]['Original Event Log'].append(str(row['Details']).replace("\r", " "))
            Suspicious = []


def detect_events_powershell_log(file_name='powershell-logs.csv',winevent=False):

    with open(file_name, newline='') as csvfile:

        """if winevent==True:
            list =csv.DictReader(csvfile, fieldnames=('Level', 'Date and Time', 'Source', 'Event ID', 'Task Category', 'Details',))
        else:
            list = csv.DictReader(csvfile,
                              fieldnames=(
                              "Details", "Event ID", "Version", "Qualifiers", "Level", "Task", "Opcode", "Keywords",
                              "RecordId", "ProviderName", "ProviderId", "LogName", "ProcessId", "ThreadId",
                              "MachineName", "UserId", "Date and Time", "ActivityId", "RelatedActivityId",
                              "ContainerLog", "MatchedQueryIds", "Bookmark", "LevelDisplayName", "OpcodeDisplayName",
                              "TaskDisplayName", "KeywordsDisplayNames", "Properties"))
        """

        if open(file_name,"r").read(1000).find("\"Message\",\"Id\",\"Version\"")>0:
            list = csv.DictReader(csvfile, fieldnames=(
            "Details", "Event ID", "Version", "Qualifiers", "Level", "Task", "Opcode", "Keywords", "RecordId",
            "ProviderName", "ProviderId", "LogName", "ProcessId", "ThreadId", "MachineName", "UserId", "Date and Time",
            "ActivityId", "RelatedActivityId", "ContainerLog", "MatchedQueryIds", "Bookmark", "LevelDisplayName",
            "OpcodeDisplayName", "TaskDisplayName", "KeywordsDisplayNames", "Properties"))

        else:
            list = csv.DictReader(csvfile, fieldnames=(
            'Level', 'Date and Time', 'Source', 'Event ID', 'Task Category', 'Details',))


        for row in list:
            if row['Details']==None:
                continue
            Host_Application = HostApplication_rex.findall(row['Details'])
            User =UserId_rex.findall(row['Details'])
            Engine_Version = EngineVersion_rex.findall(row['Details'])
            ScriptName = ScriptName_rex.findall(row['Details'])
            CommandLine= CommandLine_rex.findall(row['Details'])
            Error_Message = ErrorMessage_rex.findall(row['Details'])
            Suspicious=[]
            #Powershell Pipeline Execution details
            host_app=""

            if row['Details'].strip().find("\\temp\\") > -1 or row['Details'].strip().find(
                    "\\tmp\\") > -1:
                Event_desc="Powershell Operation including TEMP Folder"
                Powershell_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Powershell_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Powershell_events[0]['Detection Rule'].append(
                    "Powershell Executing Pipeline - Operation including TEMP folder ")
                Powershell_events[0]['Detection Domain'].append("Threat")
                Powershell_events[0]['Severity'].append("High")
                Powershell_events[0]['Event Description'].append(Event_desc)
                Powershell_events[0]['Event ID'].append(row['Event ID'])
                Powershell_events[0]['Original Event Log'].append(str(row['Details']).replace("\r", " "))


            if row['Event ID']=="800" :
                if len(Host_Application) == 0:
                    host_app = ""
                else:
                    host_app = Host_Application[0].strip()
                for i in Suspicious_powershell_commands:
                    if i in row['Details']:
                        Suspicious.append(i)

                if len(Suspicious)>0:
                    #print("##### " + row['Date and Time'] + " #### EventID=800 ### Powershell Pipeline Execution details #### ", end='')
                    #print("Found User ("+User[0].strip()+") run Suspicious PowerShell commands that include ("+",".join(Suspicious)+") in event with Command Line ("+CommandLine[0].strip()+") and full command ("+Host_Application[0].strip()+") ", end='')#, check event details "+row['Details'])
                    Event_desc ="Found User ("+User[0].strip()+") run Suspicious PowerShell commands that include ("+",".join(Suspicious)+") in event with Command Line ("+CommandLine[0].strip()+") and full command ("+host_app+") "
                    if len(Error_Message)>0:
                        Event_desc = Event_desc +"Error Message ("+Error_Message[0].strip()+")"
                        #print("Error Message ("+Error_Message[0].strip()+")")
                    #else:
                    #    print("")

                    Powershell_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                    Powershell_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                    Powershell_events[0]['Detection Rule'].append("Powershell Executing Pipeline - Suspicious Powershell Commands detected")
                    Powershell_events[0]['Detection Domain'].append("Threat")
                    Powershell_events[0]['Severity'].append("Critical")
                    Powershell_events[0]['Event Description'].append(Event_desc)
                    Powershell_events[0]['Event ID'].append(row['Event ID'])
                    Powershell_events[0]['Original Event Log'].append(str(row['Details']).replace("\r", " "))

            Suspicious = []

            if row['Event ID']=="600" or row['Event ID']=="400" or row['Event ID']=="403" :
                if len(Host_Application) == 0:
                    host_app = ""
                else:
                    host_app = Host_Application[0].strip()
                for i in Suspicious_powershell_commands:
                    if i in row['Details']:
                        Suspicious.append(i)

                if len(Suspicious)>0:
                    #print("##### " + row['Date and Time'] + " #### EventID="+row['Event ID'].strip()+" ### Engine state is changed #### ", end='')
                    #print("Found  Suspicious PowerShell commands that include ("+",".join(Suspicious)+") in event with Command Line ("+CommandLine[0].strip()+") and full command ("+Host_Application[0].strip()+") ", end='')#, check event details "+row['Details'])
                    Event_desc ="Found  Suspicious PowerShell commands that include (" + ",".join(
                        Suspicious) + ") in event with Command Line (" + CommandLine[
                        0].strip() + ") and full command (" + host_app + ") "

                    if len(Error_Message)>0:
                        Event_desc = Event_desc + "Error Message (" + Error_Message[0].strip() + ")"
                        #print("Error Message ("+Error_Message[0].strip()+")")
                    #else:
                    #    print("")
                    Powershell_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                    Powershell_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                    Powershell_events[0]['Detection Rule'].append("Suspicious PowerShell commands Detected")
                    Powershell_events[0]['Detection Domain'].append("Threat")
                    Powershell_events[0]['Severity'].append("Critical")
                    Powershell_events[0]['Event Description'].append(Event_desc)
                    Powershell_events[0]['Event ID'].append(row['Event ID'])
                    Powershell_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))


            Suspicious = []


            if row['Event ID']!="600" and row['Event ID']!="400" or row['Event ID']!="403" or row['Event ID']!="800":
                for i in Suspicious_powershell_commands:
                    if i in row['Details']:
                        Suspicious.append(i)

                if len(Suspicious)>0:
                    Event_desc ="Found  Suspicious PowerShell commands that include (" + ",".join(Suspicious) + ") in event "
                    Powershell_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                    Powershell_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                    Powershell_events[0]['Detection Rule'].append("Suspicious PowerShell commands Detected")
                    Powershell_events[0]['Detection Domain'].append("Threat")
                    Powershell_events[0]['Severity'].append("Critical")
                    Powershell_events[0]['Event Description'].append(Event_desc)
                    Powershell_events[0]['Event ID'].append(row['Event ID'])
                    Powershell_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))
            Suspicious = []
def detect_events_TerminalServices_LocalSessionManager_log(file_name='powershell-logs.csv',winevent=False):

    with open(file_name, newline='') as csvfile:

        """if winevent==True:
            list =csv.DictReader(csvfile, fieldnames=('Level', 'Date and Time', 'Source', 'Event ID', 'Task Category', 'Details',))
        else:
            list = csv.DictReader(csvfile,
                              fieldnames=(
                              "Details", "Event ID", "Version", "Qualifiers", "Level", "Task", "Opcode", "Keywords",
                              "RecordId", "ProviderName", "ProviderId", "LogName", "ProcessId", "ThreadId",
                              "MachineName", "UserId", "Date and Time", "ActivityId", "RelatedActivityId",
                              "ContainerLog", "MatchedQueryIds", "Bookmark", "LevelDisplayName", "OpcodeDisplayName",
                              "TaskDisplayName", "KeywordsDisplayNames", "Properties"))

        """


        if open(file_name,"r").read(1000).find("\"Message\",\"Id\",\"Version\"")>0:
            list = csv.DictReader(csvfile, fieldnames=(
            "Details", "Event ID", "Version", "Qualifiers", "Level", "Task", "Opcode", "Keywords", "RecordId",
            "ProviderName", "ProviderId", "LogName", "ProcessId", "ThreadId", "MachineName", "UserId", "Date and Time",
            "ActivityId", "RelatedActivityId", "ContainerLog", "MatchedQueryIds", "Bookmark", "LevelDisplayName",
            "OpcodeDisplayName", "TaskDisplayName", "KeywordsDisplayNames", "Properties"))

        else:
            list = csv.DictReader(csvfile, fieldnames=(
            'Level', 'Date and Time', 'Source', 'Event ID', 'Task Category', 'Details',))


        for row in list:
            if row['Details']==None:
                continue

            User =User_Terminal_rex.findall(row['Details'])
            Source_Network_Address=Source_Network_Address_Terminal_rex.findall(row['Details'])

            if (row['Event ID']=="21" or row['Event ID']=="25" ) :
                if User[0].strip() not in TerminalServices_Summary[0]['User']:
                    TerminalServices_Summary[0]['User'].append(User[0].strip())
                    TerminalServices_Summary[0]['Number of Logins'].append(1)
                else :
                    TerminalServices_Summary[0]['Number of Logins'][TerminalServices_Summary[0]['User'].index(User[0].strip())]=TerminalServices_Summary[0]['Number of Logins'][TerminalServices_Summary[0]['User'].index(User[0].strip())]+1


            # Remote Desktop Services: Session logon succeeded
            if row['Event ID']=="21" or row['Event ID']=="25" :
                #print(Source_Network_Address[0][0])
                #print(len(Source_Network_Address))
                if len(Source_Network_Address)>0:
                    #print(IPAddress(Source_Network_Address[0][0].strip()).is_private())
                    if  Source_Network_Address[0][0].strip()=="127.0.0.1":
                        #print("##### " + row['Date and Time'] + " #### EventID=" + row['Event ID'].strip() + " ### Remote Desktop Services: Session logon succeeded: #### ", end='')
                        #print("Found User ("+User[0].strip()+") connecting from Local Host ( 127.0.0.1 ) which means attacker is using tunnel to connect RDP ")

                        Event_desc ="Found User ("+User[0].strip()+") connecting from Local Host ( 127.0.0.1 ) which means attacker is using tunnel to connect RDP "
                        TerminalServices_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                        TerminalServices_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                        TerminalServices_events[0]['Detection Rule'].append("User connected RDP from Local host - Possible Socks Proxy being used")
                        TerminalServices_events[0]['Detection Domain'].append("Threat")
                        TerminalServices_events[0]['Severity'].append("Critical")
                        TerminalServices_events[0]['Event Description'].append(Event_desc)
                        TerminalServices_events[0]['Event ID'].append(row['Event ID'])
                        TerminalServices_events[0]['Original Event Log'].append(str(row['Details']).replace("\r", " "))

                    try:
                        if Source_Network_Address[0][0].strip()!="127.0.0.1" and not IPAddress(Source_Network_Address[0][0].strip()).is_private():
                            #print("##### " + row['Date and Time'] + " #### EventID=" + row['Event ID'].strip() + " ### Remote Desktop Services: Session logon succeeded: #### ", end='')
                            #print("Found User ("+User[0].strip()+") connecting from public IP (" +Source_Network_Address[0][0].strip()+") ")

                            Event_desc ="Found User ("+User[0].strip()+") connecting from public IP (" +Source_Network_Address[0][0].strip()+") "
                            TerminalServices_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                            TerminalServices_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                            TerminalServices_events[0]['Detection Rule'].append("User Connecting RDP from Public IP")
                            TerminalServices_events[0]['Detection Domain'].append("Audit")
                            TerminalServices_events[0]['Severity'].append("Critical")
                            TerminalServices_events[0]['Event Description'].append(Event_desc)
                            TerminalServices_events[0]['Event ID'].append(row['Event ID'])
                            TerminalServices_events[0]['Original Event Log'].append(str(row['Details']).replace("\r", " "))
                    except:
                        continue

def detect_events_Microsoft_Windows_WinRM_CSV_log(file_name='powershell-logs.csv',winevent=False):

    with open(file_name, newline='') as csvfile:
        """
        if winevent==True:
            list =csv.DictReader(csvfile, fieldnames=('Level', 'Date and Time', 'Source', 'Event ID', 'Task Category', 'Details',))
        else:
            list = csv.DictReader(csvfile,
                              fieldnames=(
                              "Details", "Event ID", "Version", "Qualifiers", "Level", "Task", "Opcode", "Keywords",
                              "RecordId", "ProviderName", "ProviderId", "LogName", "ProcessId", "ThreadId",
                              "MachineName", "UserId", "Date and Time", "ActivityId", "RelatedActivityId",
                              "ContainerLog", "MatchedQueryIds", "Bookmark", "LevelDisplayName", "OpcodeDisplayName",
                              "TaskDisplayName", "KeywordsDisplayNames", "Properties"))


        """

        if open(file_name,"r").read(1000).find("\"Message\",\"Id\",\"Version\"")>0:
            list = csv.DictReader(csvfile, fieldnames=(
            "Details", "Event ID", "Version", "Qualifiers", "Level", "Task", "Opcode", "Keywords", "RecordId",
            "ProviderName", "ProviderId", "LogName", "ProcessId", "ThreadId", "MachineName", "UserId", "Date and Time",
            "ActivityId", "RelatedActivityId", "ContainerLog", "MatchedQueryIds", "Bookmark", "LevelDisplayName",
            "OpcodeDisplayName", "TaskDisplayName", "KeywordsDisplayNames", "Properties"))

        else:
            list = csv.DictReader(csvfile, fieldnames=(
            'Level', 'Date and Time', 'Source', 'Event ID', 'Task Category', 'Details',))


        for row in list:
            if row['Details']==None:
                continue

            Connection=Connection_rex.findall(row['Details'])
            #src_device=src_device_rex.findall(row['Details'])
            #User_ID=User_ID_rex.findall(row['Details'])

            #connection is initiated using WinRM - Powershell remoting
            if row['Event ID']=="6":

                #print("##### " + row['Date and Time'] + " #### EventID=" + row['Event ID'].strip() + " ### connection is initiated using WinRM from this machine - Powershell remoting  #### ", end='')
                #print("User Connected to ("+ Connection[0].strip() +") using WinRM - powershell remote ")
                Event_desc="User Connected to ("+ Connection[0].strip() +") using WinRM - powershell remote "
                WinRM_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                WinRM_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                WinRM_events[0]['Detection Rule'].append("connection is initiated using WinRM from this machine - Powershell remoting")
                WinRM_events[0]['Detection Domain'].append("Audit")
                WinRM_events[0]['Severity'].append("High")
                WinRM_events[0]['Event Description'].append(Event_desc)
                WinRM_events[0]['Event ID'].append(row['Event ID'])
                WinRM_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))
            if row['Event ID']=="91":

                #print("##### " + row['Date and Time'] + " #### EventID=" + row['Event ID'].strip() + " ### connection is initiated using WinRM to this machine - Powershell remoting  #### ", end='')
                #print("User Connected to this machine using WinRM - powershell remote - check the system logs for more information")

                Event_desc="User Connected to remote machine using WinRM - powershell remote - check eventlog viewer"
                WinRM_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                WinRM_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                WinRM_events[0]['Detection Rule'].append("connection is initiated using WinRM to this machine - Powershell remoting")
                WinRM_events[0]['Detection Domain'].append("Audit")
                WinRM_events[0]['Severity'].append("High")
                WinRM_events[0]['Event Description'].append(Event_desc)
                WinRM_events[0]['Event ID'].append(row['Event ID'])
                WinRM_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))
def detect_events_Microsoft_Windows_WinRM_XML_log(file_name='powershell-logs.csv'):

    root = ET.parse('winrm.xml').getroot()
    #print(root)
    for i in root:
        #print(i.attrib)

        #for d in i.findall("{http://schemas.microsoft.com/win/2004/08/events/event}EventData"):
        #    for x in d:
        #        print(x)
        for d in i.findall("{http://schemas.microsoft.com/win/2004/08/events/event}System"):
            if d.find('{http://schemas.microsoft.com/win/2004/08/events/event}EventID').text=="6":
                try:
                    print("##### " + d.find('{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated').attrib['SystemTime'] + " #### EventID= " +d.find('{http://schemas.microsoft.com/win/2004/08/events/event}EventID').text +"  ### connection is initiated using WinRM - Powershell remoting  ##### User with ID ("+d.find('{http://schemas.microsoft.com/win/2004/08/events/event}Security').attrib['UserID']+") is connecting from current machine ("+d.find('{http://schemas.microsoft.com/win/2004/08/events/event}Computer').text +") to ("+ i.find("{http://schemas.microsoft.com/win/2004/08/events/event}EventData").find("{http://schemas.microsoft.com/win/2004/08/events/event}Data").text +") using WinRM - powershell remote " )

                    Event_desc = "##### " + d.find('{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated').attrib['SystemTime'] + " #### EventID= " +d.find('{http://schemas.microsoft.com/win/2004/08/events/event}EventID').text +"  ### connection is initiated using WinRM - Powershell remoting  ##### User with ID ("+d.find('{http://schemas.microsoft.com/win/2004/08/events/event}Security').attrib['UserID']+") is connecting from current machine ("+d.find('{http://schemas.microsoft.com/win/2004/08/events/event}Computer').text +") to ("+ i.find("{http://schemas.microsoft.com/win/2004/08/events/event}EventData").find("{http://schemas.microsoft.com/win/2004/08/events/event}Data").text +") using WinRM - powershell remote "
                    WinRM_events[0]['Date and Time'].append(d.find('{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated').attrib['SystemTime'])
                    WinRM_events[0]['Detection Rule'].append(
                        "connection is initiated using WinRM from this machine - Powershell remoting")
                    WinRM_events[0]['Detection Domain'].append("Audit")
                    WinRM_events[0]['Severity'].append("High")
                    WinRM_events[0]['Event Description'].append(Event_desc)
                    WinRM_events[0]['Event ID'].append(d.find('{http://schemas.microsoft.com/win/2004/08/events/event}EventID').text)
                    WinRM_events[0]['Original Event Log'].append("check the logs")
                except:
                    continue

            if d.find('{http://schemas.microsoft.com/win/2004/08/events/event}EventID').text=="91":
                try:
                    print("##### " + d.find('{http://schemas.microsoft.com/win/2004/08/events/event}TimeCreated').attrib['SystemTime'] + " #### EventID= " +d.find('{http://schemas.microsoft.com/win/2004/08/events/event}EventID').text +"  ### connection is initiated using WinRM - Powershell remoting  ##### User with ID ("+d.find('{http://schemas.microsoft.com/win/2004/08/events/event}Security').attrib['UserID']+") connected to current machine ("+d.find('{http://schemas.microsoft.com/win/2004/08/events/event}Computer').text +") using WinRM - powershell remote " )
                except:
                    continue



def detect_events_Sysmon_log(file_name='sysmon-logs.csv',winevent=False):

    with open(file_name, newline='') as csvfile:

        """if winevent==True:
            list =csv.DictReader(csvfile, fieldnames=('Level', 'Date and Time', 'Source', 'Event ID', 'Task Category', 'Details',))
        else:
            list = csv.DictReader(csvfile,
                              fieldnames=(
                              "Details", "Event ID", "Version", "Qualifiers", "Level", "Task", "Opcode", "Keywords",
                              "RecordId", "ProviderName", "ProviderId", "LogName", "ProcessId", "ThreadId",
                              "MachineName", "UserId", "Date and Time", "ActivityId", "RelatedActivityId",
                              "ContainerLog", "MatchedQueryIds", "Bookmark", "LevelDisplayName", "OpcodeDisplayName",
                              "TaskDisplayName", "KeywordsDisplayNames", "Properties"))

        """

        if open(file_name,"r").read(1000).find("\"Message\",\"Id\",\"Version\"")>0:
            list = csv.DictReader(csvfile, fieldnames=(
            "Details", "Event ID", "Version", "Qualifiers", "Level", "Task", "Opcode", "Keywords", "RecordId",
            "ProviderName", "ProviderId", "LogName", "ProcessId", "ThreadId", "MachineName", "UserId", "Date and Time",
            "ActivityId", "RelatedActivityId", "ContainerLog", "MatchedQueryIds", "Bookmark", "LevelDisplayName",
            "OpcodeDisplayName", "TaskDisplayName", "KeywordsDisplayNames", "Properties"))

        else:
            list = csv.DictReader(csvfile, fieldnames=(
            'Level', 'Date and Time', 'Source', 'Event ID', 'Task Category', 'Details',))

        for row in list:
            if row['Details']==None:
                continue

            CommandLine=Sysmon_CommandLine_rex.findall(row['Details'])
            ProcessGuid=Sysmon_ProcessGuid_rex.findall(row['Details'])
            ProcessId=Sysmon_ProcessId_rex.findall(row['Details'])
            Image=Sysmon_Image_rex.findall(row['Details'])
            FileVersion=Sysmon_FileVersion_rex.findall(row['Details'])
            Company=Sysmon_Company_rex.findall(row['Details'])
            Product=Sysmon_Product_rex.findall(row['Details'])
            Description=Sysmon_Description_rex.findall(row['Details'])
            User=Sysmon_User_rex.findall(row['Details'])
            LogonGuid=Sysmon_LogonGuid_rex.findall(row['Details'])
            TerminalSessionId=Sysmon_TerminalSessionId_rex.findall(row['Details'])
            MD5=Sysmon_Hashes_MD5_rex.findall(row['Details'])
            SHA256=Sysmon_Hashes_SHA256_rex.findall(row['Details'])
            ParentProcessGuid=Sysmon_ParentProcessGuid_rex.findall(row['Details'])
            ParentProcessId=Sysmon_ParentProcessId_rex.findall(row['Details'])
            ParentImage=Sysmon_ParentImage_rex.findall(row['Details'])
            ParentCommandLine=Sysmon_ParentCommandLine_rex.findall(row['Details'])
            CurrentDirectory=Sysmon_CurrentDirectory_rex.findall(row['Details'])
            OriginalFileName=Sysmon_OriginalFileName_rex.findall(row['Details'])
            TargetObject=Sysmon_TargetObject_rex.findall(row['Details'])
            Protocol=Sysmon_Protocol_rex.findall(row['Details'])
            SourceIp=Sysmon_SourceIp_rex.findall(row['Details'])
            SourceHostname=Sysmon_SourceHostname_rex.findall(row['Details'])
            SourcePort=Sysmon_SourcePort_rex.findall(row['Details'])
            DestinationIp=Sysmon_DestinationIp_rex.findall(row['Details'])
            DestinationHostname=Sysmon_DestinationHostname_rex.findall(row['Details'])
            DestinationPort=Sysmon_DestinationPort_rex.findall(row['Details'])
            StartFunction=Sysmon_StartFunction_rex.findall(row['Details'])
            SourceImage=Sysmon_SourceImage_rex.findall(row['Details'])
            TargetImage=Sysmon_TargetImage_rex.findall(row['Details'])

            temp=[]
            #Powershell with Suspicious Argument covers [ T1086 ,
            if row['Event ID']=="1" and Image[0].strip().find("powershell.exe")>-1:
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
                    Sysmon_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                    Sysmon_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                    Sysmon_events[0]['Detection Rule'].append('[ T1086 ]  Powershell with Suspicious Argument')
                    Sysmon_events[0]['Detection Domain'].append("Threat")
                    Sysmon_events[0]['Severity'].append("Critical")
                    Sysmon_events[0]['Event Description'].append(Event_desc)
                    Sysmon_events[0]['Event ID'].append(row['Event ID'])
                    Sysmon_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))


            #[  T1543 ] Sc.exe manipulating windows services
            if row['Event ID']=="1" and Image[0].strip().find("\\sc.exe")>-1 and ( CommandLine[0].find("create")>-1 or CommandLine[0].find("start")>-1 or CommandLine[0].find("config")>-1 or  OriginalFileName[0].find("create")>-1 or OriginalFileName[0].find("start")>-1 or OriginalFileName[0].find("config")>-1):

                """print("##### " + row[
                    'Date and Time'] + " #### EventID=1 ### [  T1543 ] Sc.exe manipulating windows services #### ", end='')
                print(
                    "Found User (" + User[0].strip() + ") Trying to manipulate windows services usign Sc.exe with Command Line (" + CommandLine[
                        0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )")"""

                Event_desc="Found User (" + User[0].strip() + ") Trying to manipulate windows services usign Sc.exe with Command Line (" + CommandLine[
                        0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )"
                Sysmon_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Sysmon_events[0]['Detection Rule'].append('[  T1543 ] Sc.exe manipulating windows services')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(row['Event ID'])
                Sysmon_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            # [ T1059 ] wscript or cscript runing script
            if row['Event ID']=="1" and ( Image[0].strip().find("\\wscript.exe")>-1 or Image[0].strip().find("\\cscript.exe")>-1 ):

                """print("##### " + row['Date and Time'] + " #### EventID=1 ### [  T1059 ] wscript or cscript runing script #### ", end='')
                print(
                    "Found User (" + User[0].strip() + ") Trying to run wscript or cscript with Command Line (" + CommandLine[
                        0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )")"""

                Event_desc="Found User (" + User[0].strip() + ") Trying to run wscript or cscript with Command Line (" + CommandLine[
                        0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )"
                Sysmon_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Sysmon_events[0]['Detection Rule'].append('[ T1059 ] wscript or cscript runing script')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(row['Event ID'])
                Sysmon_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))


            #  [T1170] Detecting  Mshta
            if row['Event ID']=="1" and ( Image[0].strip().find("\\mshta.exe")>-1  ):

                """print("##### " + row['Date and Time'] + " #### EventID=1 ### [ T1218.005 ] Detecting  Mshta #### ", end='')
                print(
                    "Found User (" + User[0].strip() + ") Trying to run mshta with Command Line (" + CommandLine[
                        0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )")"""

                Event_desc="Found User (" + User[0].strip() + ") Trying to run mshta with Command Line (" + CommandLine[
                        0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )"
                Sysmon_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Sysmon_events[0]['Detection Rule'].append('[ T1218.005 ] Mshta found running in the system')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(row['Event ID'])
                Sysmon_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            #Detect Psexec with accepteula flag
            if  row['Event ID'] == "13" and (
                    TargetObject[0].strip().find("psexec") > -1 ) :
                """print("##### " + row[
                    'Date and Time'] + " #### EventID=13 ### Psexec Detected in the system #### ", end='')
                print(
                    "Found User (" + User[0].strip() + ") Trying to run psexec with process Image :" + Image[0].strip() )"""

                Event_desc="Found User (" + User[0].strip() + ") Trying to run psexec with process Image :" + Image[0].strip()
                Sysmon_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Sysmon_events[0]['Detection Rule'].append('Psexec Detected in the system')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("Critical")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(row['Event ID'])
                Sysmon_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))


            # [T1053] Scheduled Task - Process
            if row['Event ID']=="1" and ( Image[0].strip().find("\\taskeng.exe")>-1 or Image[0].strip().find("\\svchost.exe")>-1 ) and ParentImage[0].strip().find("services.exe")==-1 and ParentImage[0].strip().find("?")==-1 :

                """
                print("##### " + row['Date and Time'] + " #### EventID=1 ### [T1053] Scheduled Task - Process #### ", end='')
                print(
                    "Found User (" + User[0].strip() + ") Trying to run taskeng.exe or svchost.exe with Command Line (" + CommandLine[
                        0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )")
                """
                Event_desc="Found User (" + User[0].strip() + ") Trying to run taskeng.exe or svchost.exe with Command Line (" + CommandLine[
                        0].strip() + ") and Parent Image :"+ ParentImage[0].strip()+" , Parent CommandLine (" + ParentCommandLine[0].strip() + ") " +"in directory : ( "+CurrentDirectory[0].strip() + " )"

                Sysmon_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Sysmon_events[0]['Detection Rule'].append('[T1053] Scheduled Task - Process')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("Medium")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(row['Event ID'])
                Sysmon_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))


            #Prohibited Process connecting to internet
            if row['Event ID']=="3" and ( Image[0].strip().find("powershell.exe")>-1 or Image[0].strip().find("mshta.exe")>-1 or Image[0].strip().find("cscript.exe")>-1 or Image[0].strip().find("regsvr32.exe")>-1  or Image[0].strip().find("certutil.exe")>-1 ):
                #temp.append()
                #print("##### " + row[
                #    'Date and Time'] + " #### EventID=3 ### Prohibited Process connecting to internet #### ", end='')
                #print(
                #    "Found User (" + User[0].strip() + ") run process "+Image[0].strip()+" and initiated network connection from hostname ( "+ SourceHostname[0].strip()+" and IP ( "+SourceIp[0].strip() +" ) to hostname ( "+ DestinationHostname[0].strip()+" ) , IP ( " +DestinationIp[0].strip()+" ) and port ( "+DestinationPort[0].strip()+" )")

                Event_desc="User (" + User[0].strip() + ") run process "+Image[0].strip()+" and initiated network connection from hostname ( "+ SourceHostname[0].strip()+" and IP ( "+SourceIp[0].strip() +" ) to hostname ( "+ DestinationHostname[0].strip()+" ) , IP ( " +DestinationIp[0].strip()+" ) and port ( "+DestinationPort[0].strip()+" )"
                Sysmon_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Sysmon_events[0]['Detection Rule'].append('Prohibited Process connecting to internet')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("Critical")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(row['Event ID'])
                Sysmon_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            #Detecting WMI attacks
            if row['Event ID']=="1" and ( ParentCommandLine[0].strip().find("WmiPrvSE.exe")>-1 or Image[0].strip().find("WmiPrvSE.exe")>-1 ):

                Event_desc="User (" + User[0].strip() + ") run command through WMI with process ("+Image[0].strip()+ ") and commandline ( "+CommandLine[
                        0].strip() +" )"
                Sysmon_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Sysmon_events[0]['Detection Rule'].append('Command run remotely Using WMI')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("Critical")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(row['Event ID'])
                Sysmon_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            #Detecting IIS/Exchange Exploitation
            if row['Event ID']=="1" and ( ParentCommandLine[0].strip().find("w3wp.exe")>-1 or Image[0].strip().find("w3wp.exe")>-1 ):

                Event_desc="IIS run command with user (" + User[0].strip() + ") and process name ("+Image[0].strip()+ ") and commandline ( "+CommandLine[
                        0].strip() +" )"
                Sysmon_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Sysmon_events[0]['Detection Rule'].append('Detect IIS/Exchange Exploitation')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("Critical")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(row['Event ID'])
                Sysmon_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            # [T1055] Process Injection
            if row['Event ID']=="8" and ( StartFunction[0].strip().lower().find("loadlibrary")>-1  ):

                Event_desc="Process ( %s) attempted process injection on process ( %s)"%(SourceImage[0],TargetImage[0])
                Sysmon_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Sysmon_events[0]['Detection Rule'].append('[T1055] Process Injection')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("Critical")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(row['Event ID'])
                Sysmon_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            # [T1082] System Information Discovery
            if row['Event ID']=="1" and ( CommandLine[0].strip().find("sysinfo.exe")>-1 or Image[0].strip().find("sysinfo.exe")>-1 or CommandLine[0].strip().find("whoami.exe")>-1 or Image[0].strip().find("whoami.exe")>-1 ):

                Event_desc="System Information Discovery Process ( %s) ith commandline ( %s) "%(Image[0].strip(),CommandLine[0].strip())
                Sysmon_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Sysmon_events[0]['Detection Rule'].append('[T1082] System Information Discovery')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("Critical")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(row['Event ID'])
                Sysmon_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))

            #  [T1117] Bypassing Application Whitelisting with Regsvr32
            if row['Event ID']=="1" and ( Image[0].strip().find("regsvr32.exe")>-1 or Image[0].strip().find("rundll32.exe")>-1 or Image[0].strip().find("certutil.exe")>-1 ):

                Event_desc="[T1117] Bypassing Application Whitelisting with Regsvr32 , Process ( %s) with commandline ( %s)"%(Image[0].strip(),CommandLine[0].strip())
                Sysmon_events[0]['Date and Time'].append(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p').isoformat())
                Sysmon_events[0]['timestamp'].append(datetime.timestamp(datetime.strptime(row['Date and Time'],'%m/%d/%Y %I:%M:%S %p')))
                Sysmon_events[0]['Detection Rule'].append('[T1117] Bypassing Application Whitelisting with Regsvr32')
                Sysmon_events[0]['Detection Domain'].append("Threat")
                Sysmon_events[0]['Severity'].append("High")
                Sysmon_events[0]['Event Description'].append(Event_desc)
                Sysmon_events[0]['Event ID'].append(row['Event ID'])
                Sysmon_events[0]['Original Event Log'].append(str(row['Details']).replace("\r"," "))
