import traceback
import logging
from lib.Banner import *
import argparse
import pandas as pd
import lib.EvtxDetection as EvtxDetection
import lib.CSVDetection as CSVDetection
import lib.EvtxHunt as EvtxHunt
import lib.SigmaHunter as SigmaHunter
from evtx import PyEvtxParser
from sys import exit
from pytz import timezone
from dateutil import tz
import glob
import os
import re
from pathlib import Path as libPath
from datetime import datetime
import dateutil.parser
import multiprocessing
import time
import pickle
import platform
timestart=None
timeend=None
Output=""
Path=""
Security_path=""
system_path=""
scheduledtask_path=""
defender_path=""
powershell_path=""
powershellop_path=""
terminal_path=""
temp_dir="temp"
winrm_path=""
sysmon_path=""
objectaccess=False
processexec=False
logons=False
frequencyanalysis=False
allreport=False
Security_path_list=[]
system_path_list=[]
scheduledtask_path_list=[]
defender_path_list=[]
powershell_path_list=[]
powershellop_path_list=[]
terminal_path_list=[]
terminal_Client_path_list=[]
winrm_path_list=[]
sysmon_path_list=[]
group_policy_path_list=[]
SMB_SERVER_path_list=[]
SMB_CLIENT_path_list=[]
UserProfile_path_list=[]
RDPClient_Resolved_User=[]
WinRM_Resolved_User=[]
input_timezone=tz.tzlocal()
CPU_Core=0
Logon_Events=[{'Date and Time':[],'timestamp':[],'Event ID':[],'Account Name':[],'Account Domain':[],'Logon Type':[],'Logon Process':[],'Source IP':[],'Workstation Name':[],'Computer Name':[],'Channel':[],'Original Event Log':[]}]

Executed_Powershell_Summary=[{'Command': [], 'Number of Execution': []}]
Executed_Process_Summary=[{'Process Name':[],'Number of Execution':[]}]
TerminalServices_Summary=[{'User':[],'Number of Logins':[]}]
Security_Authentication_Summary=[{'User':[],'Number of Failed Logins':[],'Number of Successful Logins':[]}]
Sysmon_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[],'Computer Name':[],'Channel':[]}]
WinRM_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'UserID':[],'Event ID':[],'Original Event Log':[],'Computer Name':[],'Channel':[]}]
Security_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[],'Computer Name':[],'Channel':[]}]
System_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Service Name':[],'Image Path':[],'Event Description':[],'Event ID':[],'Original Event Log':[],'Computer Name':[],'Channel':[]}]
ScheduledTask_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Schedule Task Name':[],'Image Path':[],'Event Description':[],'Event ID':[],'Original Event Log':[],'Computer Name':[],'Channel':[]}]
Powershell_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[],'Computer Name':[],'Channel':[]}]
Powershell_Operational_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[],'Computer Name':[],'Channel':[]}]
TerminalServices_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'User':[],'Source IP':[],'Original Event Log':[],'Computer Name':[],'Channel':[]}]
TerminalServices_RDPClient_events=[{'Date and Time': [], 'timestamp': [], 'Detection Rule': [], 'Severity': [], 'Detection Domain': [],'Event Description': [], 'Event ID': [], 'UserID': [], 'Source IP': [], 'Computer Name': [], 'Channel': [],'Original Event Log': []}]
Windows_Defender_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[],'Computer Name':[],'Channel':[]}]
Timesketch_events=[{'message':[],'timestamp':[],'datetime':[],'timestamp_desc':[],'Event Description':[],'Severity':[],'Detection Domain':[],'Event ID':[],'Original Event Log':[],'Computer Name':[],'Channel':[]}]
Object_Access_Events=[{'Date and Time':[],'timestamp':[],'Event ID':[],'Account Name':[],'Account Domain':[],'Object Name':[],'Object Type':[],'Process Name':[],'Computer Name':[],'Channel':[],'Original Event Log':[]}]
Group_Policy_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Group Policy Name':[],'Policy Extension Name':[],'Event ID':[],'Original Event Log':[],'Computer Name':[],'Channel':[]}]
Executed_Process_Events=[{'DateTime':[],'timestamp':[],'EventID':[],'ProcessName':[],'User':[],'ParentProcessName':[],'RawLog':[]}]
SMB_Server_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Client Address':[],'UserName':[],'Share Name':[],'File Name':[],'Event ID':[],'Computer Name':[],'Channel':[],'Original Event Log':[]}]
SMB_Client_events=[{'Date and Time':[],'timestamp':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Share Name':[],'File Name':[],'Event ID':[],'Computer Name':[],'Channel':[],'Original Event Log':[]}]
User_SIDs = {'User': [], 'SID': []}
Frequency_Analysis_Security={}
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


def evtxdetect_auto():
    global timestart,timeend,logons,Output,allreport,SMB_Server_events,User_SIDs,SMB_Client_events,TerminalServices_RDPClient_events,Frequency_Analysis_TerminalServices,Executed_Process_Events,Group_Policy_events,Object_Access_Events,input_timezone,Logon_Events,Executed_Process_Summary,TerminalServices_Summary,Security_Authentication_Summary,Sysmon_events,WinRM_events,Security_events,System_events,ScheduledTask_events,Powershell_events,Powershell_Operational_events,TerminalServices_events,Windows_Defender_events,Timesketch_events,TerminalServices_Summary,Security_Authentication_Summary,Executed_Powershell_Summary
    process_list = []

    try:
        #print(Security_path)
        userprofile=multiprocessing.Process(target= EvtxDetection.multiprocess, args = (UserProfile_path_list,EvtxDetection.detect_events_UserProfileService_log,input_timezone,timestart,timeend,objectaccess,processexec,logons,frequencyanalysis,allreport,Output,CPU_Core))
        userprofile.start()
        process_list.append(userprofile)
    except IOError :
        print("Error Analyzing User Profile logs: ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing User Profile logs")
        logging.error(traceback.format_exc())
    try:
        #print(Security_path)
        sec=multiprocessing.Process(target= EvtxDetection.multiprocess, args = (Security_path_list,EvtxDetection.detect_events_security_log,input_timezone,timestart,timeend,objectaccess,processexec,logons,frequencyanalysis,allreport,Output,CPU_Core,temp_dir))
        sec.start()
        process_list.append(sec)
    except IOError :
        print("Error Analyzing Security logs: ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing Security logs")
        logging.error(traceback.format_exc())
    try:
        #EvtxDetection.multiprocess(system_path_list,EvtxDetection.detect_events_system_log,input_timezone,timestart,timeend)
        sys=multiprocessing.Process(target= EvtxDetection.multiprocess, args = (system_path_list,EvtxDetection.detect_events_system_log,input_timezone,timestart,timeend,objectaccess,processexec,logons,frequencyanalysis,allreport,Output,CPU_Core,temp_dir))
        sys.start()
        process_list.append(sys)
    except IOError :
        print("Error Analyzing System logs : ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing System logs ")
        logging.error(traceback.format_exc())
    try :
        #EvtxDetection.multiprocess(powershellop_path_list,EvtxDetection.detect_events_powershell_operational_log,input_timezone,timestart,timeend)
        pwshop=multiprocessing.Process(target= EvtxDetection.multiprocess, args = (powershellop_path_list,EvtxDetection.detect_events_powershell_operational_log,input_timezone,timestart,timeend,objectaccess,processexec,logons,frequencyanalysis,allreport,Output,CPU_Core,temp_dir))
        pwshop.start()
        process_list.append(pwshop)
    except IOError :
        print("Error Analyzing Powershell Operational logs : ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing Powershell Operational logs ")
        logging.error(traceback.format_exc())
    try :
        #EvtxDetection.multiprocess(powershell_path_list,EvtxDetection.detect_events_powershell_log,input_timezone,timestart,timeend)
        pwsh=multiprocessing.Process(target= EvtxDetection.multiprocess, args = (powershell_path_list,EvtxDetection.detect_events_powershell_log,input_timezone,timestart,timeend,objectaccess,processexec,logons,frequencyanalysis,allreport,Output,CPU_Core,temp_dir))
        pwsh.start()
        process_list.append(pwsh)
    except IOError :
        print("Error Analyzing Powershell logs : ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing Powershell logs ")
        logging.error(traceback.format_exc())
    try :
        #EvtxDetection.multiprocess(terminal_path_list,EvtxDetection.detect_events_TerminalServices_LocalSessionManager_log,input_timezone,timestart,timeend)
        terminal=multiprocessing.Process(target= EvtxDetection.multiprocess, args = (terminal_path_list,EvtxDetection.detect_events_TerminalServices_LocalSessionManager_log,input_timezone,timestart,timeend,objectaccess,processexec,logons,frequencyanalysis,allreport,Output,CPU_Core,temp_dir))
        terminal.start()
        process_list.append(terminal)
    except IOError :
        print("Error Analyzing TerminalServices LocalSessionManager logs: ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing TerminalServices LocalSessionManager logs")
        logging.error(traceback.format_exc())
    try :
        #EvtxDetection.multiprocess(terminal_path_list,EvtxDetection.detect_events_TerminalServices_LocalSessionManager_log,input_timezone,timestart,timeend)
        terminal_client=multiprocessing.Process(target= EvtxDetection.multiprocess, args = (terminal_Client_path_list,EvtxDetection.detect_events_TerminalServices_RDPClient_log,input_timezone,timestart,timeend,objectaccess,processexec,logons,frequencyanalysis,allreport,Output,CPU_Core,temp_dir))
        terminal_client.start()
        process_list.append(terminal_client)
    except IOError :
        print("Error Analyzing TerminalServices RDP Client logs: ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing TerminalServices RDP Client logs")
        logging.error(traceback.format_exc())

    try:
        #EvtxDetection.multiprocess(scheduledtask_path_list,EvtxDetection.detect_events_scheduled_task_log,input_timezone,timestart,timeend)
        scheduled=multiprocessing.Process(target= EvtxDetection.multiprocess, args = (scheduledtask_path_list,EvtxDetection.detect_events_scheduled_task_log,input_timezone,timestart,timeend,objectaccess,processexec,logons,frequencyanalysis,allreport,Output,CPU_Core,temp_dir))
        scheduled.start()
        process_list.append(scheduled)
    except IOError :
        print("Error Analyzing Scheduled Task logs : ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing Scheduled Task logs ")
        logging.error(traceback.format_exc())

    try:
        #EvtxDetection.multiprocess(defender_path_list,EvtxDetection.detect_events_windows_defender_log,input_timezone,timestart,timeend)
        defen=multiprocessing.Process(target= EvtxDetection.multiprocess, args = (defender_path_list,EvtxDetection.detect_events_windows_defender_log,input_timezone,timestart,timeend,objectaccess,processexec,logons,frequencyanalysis,allreport,Output,CPU_Core,temp_dir))
        defen.start()
        process_list.append(defen)

    except IOError :
        print("Error Analyzing Windows Defender logs : ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing Windows Defender logs ")
        logging.error(traceback.format_exc())
    try:
        #EvtxDetection.multiprocess(winrm_path_list,EvtxDetection.detect_events_Microsoft_Windows_WinRM,input_timezone,timestart,timeend)
        winrm=multiprocessing.Process(target= EvtxDetection.multiprocess, args = (winrm_path_list,EvtxDetection.detect_events_Microsoft_Windows_WinRM,input_timezone,timestart,timeend,objectaccess,processexec,logons,frequencyanalysis,allreport,Output,CPU_Core,temp_dir))
        winrm.start()
        process_list.append(winrm)

    except IOError :
        print("Error Analyzing WinRM logs : ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing WinRM logs ")
        logging.error(traceback.format_exc())

    try:
        #EvtxDetection.multiprocess(sysmon_path_list,EvtxDetection.detect_events_Sysmon_log,input_timezone,timestart,timeend)
        sysmon=multiprocessing.Process(target= EvtxDetection.multiprocess, args = (sysmon_path_list,EvtxDetection.detect_events_Sysmon_log,input_timezone,timestart,timeend,objectaccess,processexec,logons,frequencyanalysis,allreport,Output,CPU_Core,temp_dir))
        sysmon.start()
        process_list.append(sysmon)

    except IOError :
        print("Error Analyzing Sysmon logs ")
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing Sysmon logs ")
        logging.error(traceback.format_exc())

    try:
        #EvtxDetection.multiprocess(group_policy_path_list,EvtxDetection.detect_events_group_policy_log,input_timezone,timestart,timeend)
        gp=multiprocessing.Process(target= EvtxDetection.multiprocess, args = (group_policy_path_list,EvtxDetection.detect_events_group_policy_log,input_timezone,timestart,timeend,objectaccess,processexec,logons,frequencyanalysis,allreport,Output,CPU_Core,temp_dir))
        gp.start()
        process_list.append(gp)

    except IOError :
        print("Error Analyzing Group Policy logs ")
        print("File Path Does Not Exist")
    #except Exception as e:
    #    print("Error Analyzing Group Policy logs ")
    #    logging.error(traceback.format_exc())

    try:
        #EvtxDetection.multiprocess(SMB_SERVER_path_list,EvtxDetection.detect_events_SMB_Server_log,input_timezone,timestart,timeend)
        smbserv=multiprocessing.Process(target= EvtxDetection.multiprocess, args = (SMB_SERVER_path_list,EvtxDetection.detect_events_SMB_Server_log,input_timezone,timestart,timeend,objectaccess,processexec,logons,frequencyanalysis,allreport,Output,CPU_Core,temp_dir))
        smbserv.start()
        process_list.append(smbserv)

    except IOError :
        print("Error Analyzing SMB Server logs ")
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing Group Policy logs ")
        logging.error(traceback.format_exc())

    try:
        #EvtxDetection.multiprocess(SMB_CLIENT_path_list,EvtxDetection.detect_events_SMB_Client_log,input_timezone,timestart,timeend)
        smbcli=multiprocessing.Process(target= EvtxDetection.multiprocess, args = (SMB_CLIENT_path_list,EvtxDetection.detect_events_SMB_Client_log,input_timezone,timestart,timeend,objectaccess,processexec,logons,frequencyanalysis,allreport,Output,CPU_Core,temp_dir))
        smbcli.start()
        process_list.append(smbcli)

    except IOError :
        print("Error Analyzing SMB Client logs ")
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing Group Policy logs ")
        logging.error(traceback.format_exc())

    for process in process_list:
        process.join()
    print("preparing results")

    Sysmon_events = EvtxDetection.Sysmon_events
    WinRM_events =EvtxDetection.WinRM_events
    Security_events =EvtxDetection.Security_events
    System_events =EvtxDetection.System_events
    ScheduledTask_events =EvtxDetection.ScheduledTask_events
    Powershell_events =EvtxDetection.Powershell_events
    Powershell_Operational_events =EvtxDetection.Powershell_Operational_events
    TerminalServices_events =EvtxDetection.TerminalServices_events
    TerminalServices_RDPClient_events =EvtxDetection.TerminalServices_RDPClient_events
    Windows_Defender_events =EvtxDetection.Windows_Defender_events
    Timesketch_events =EvtxDetection.Timesketch_events
    TerminalServices_Summary=EvtxDetection.TerminalServices_Summary
    Executed_Process_Summary=EvtxDetection.Executed_Process_Summary
    Executed_Powershell_Summary=EvtxDetection.Executed_Powershell_Summary
    Security_Authentication_Summary =EvtxDetection.Security_Authentication_Summary
    Logon_Events =EvtxDetection.Logon_Events
    Object_Access_Events=EvtxDetection.Object_Access_Events
    Group_Policy_events=EvtxDetection.Group_Policy_events
    Executed_Process_Events=EvtxDetection.Executed_Process_Events
    SMB_Server_events=EvtxDetection.SMB_Server_events
    SMB_Client_events=EvtxDetection.SMB_Client_events
    Frequency_Analysis_Security=EvtxDetection.Frequency_Analysis_Security
    Frequency_Analysis_Windows_Defender=EvtxDetection.Frequency_Analysis_Windows_Defender
    Frequency_Analysis_SMB_Client=EvtxDetection.Frequency_Analysis_SMB_Client
    Frequency_Analysis_Group_Policy=EvtxDetection.Frequency_Analysis_Group_Policy
    Frequency_Analysis_Powershell_Operational=EvtxDetection.Frequency_Analysis_Powershell_Operational
    Frequency_Analysis_Powershell=EvtxDetection.Frequency_Analysis_Powershell
    Frequency_Analysis_ScheduledTask=EvtxDetection.Frequency_Analysis_ScheduledTask
    Frequency_Analysis_WinRM=EvtxDetection.Frequency_Analysis_WinRM
    Frequency_Analysis_System=EvtxDetection.Frequency_Analysis_System
    Frequency_Analysis_Sysmon=EvtxDetection.Frequency_Analysis_Sysmon
    Frequency_Analysis_SMB_Server=EvtxDetection.Frequency_Analysis_SMB_Server
    Frequency_Analysis_TerminalServices=EvtxDetection.Frequency_Analysis_TerminalServices
    if os.path.exists(temp_dir + "_User_SIDs_report.csv"):
        #User_SIDs = pd.DataFrame(pd.read_csv(temp_dir + "_User_SIDs_report.csv"))
        User_SIDs = pd.DataFrame(pd.read_csv(temp_dir + "_User_SIDs_report.csv")).to_dict(orient='list')
    else:
        print(f"{temp_dir + '_User_SIDs_report.csv'} does not exist.")
        #User_SIDs = pd.DataFrame(User_SIDs)
    #User_SIDs=EvtxDetection.User_SIDs
    resolveSID()
def auto_detect(path):
    global input_timezone
    EventID_rex = re.compile('<EventID.*>(.*)<\/EventID>', re.IGNORECASE)
    Channel_rex = re.compile('<Channel.*>(.*)<\/Channel>', re.IGNORECASE)
    Computer_rex = re.compile('<Computer.*>(.*)<\/Computer>', re.IGNORECASE)


    if os.path.isdir(path):
        files=list(libPath(path).rglob("*.[eE][vV][tT][xX]"))
        #files=glob.glob(path+"/**/"+"*.evtx")
    elif os.path.isfile(path):
        files=glob.glob(path)
    else:
        print("Issue with the path" )
        return
    #print("hunting ( %s ) in files ( %s )"%(str_regex,files))
    #user_string = input('please enter a string to convert to regex: ')
    for file in files:
        file=str(file)
        print("Analyzing "+file)
        try:
            parser = PyEvtxParser(file)
        except:
            print("Issue analyzing "+file +"\nplease check if its not corrupted")
            continue
        try:

            for record in parser.records():
                Channel = Channel_rex.findall(record['data'])
                if Channel[0].strip()=="Security":
                    Security_path_list.append(file)
                    break
                if Channel[0].strip()=="System":
                    system_path_list.append(file)
                    break
                if Channel[0].strip()=="Windows PowerShell":
                    powershell_path_list.append(file)
                    break
                if Channel[0].strip()=="Microsoft-Windows-PowerShell/Operational":
                    powershellop_path_list.append(file)
                    break
                if Channel[0].strip()=="Microsoft-Windows-TerminalServices-LocalSessionManager/Operational":
                    terminal_path_list.append(file)
                    break
                if Channel[0].strip()=="Microsoft-Windows-TaskScheduler/Operational":
                    scheduledtask_path_list.append(file)
                    break
                if Channel[0].strip()=="Microsoft-Windows-Windows Defender/Operational":
                    defender_path_list.append(file)
                    break
                if Channel[0].strip()=="Microsoft-Windows-WinRM/Operational":
                    winrm_path_list.append(file)
                    break
                if Channel[0].strip()=="Microsoft-Windows-Sysmon/Operational":
                    sysmon_path_list.append(file)
                    break
                if Channel[0].strip()=="Microsoft-Windows-GroupPolicy/Operational":
                    group_policy_path_list.append(file)
                    break
                if Channel[0].strip()=="Microsoft-Windows-SMBServer/Operational":
                    SMB_SERVER_path_list.append(file)
                    break
                if Channel[0].strip()=="Microsoft-Windows-SmbClient/Security":
                    SMB_CLIENT_path_list.append(file)
                    break
                if Channel[0].strip()=="Microsoft-Windows-User Profile Service/Operational":
                    UserProfile_path_list.append(file)
                    #print("file added")
                    break
                if Channel[0].strip()=="Microsoft-Windows-TerminalServices-RDPClient/Operational":
                    terminal_Client_path_list.append(file)
                    #print("file added")
                    break

                break
        except:
            print("issue assigning path")
    evtxdetect_auto()
def threat_hunt(path,str_regex,eid,hunt_file):
    global timestart,timeend,input_timezone, Output
    import os
    regex_file=[]
    #try:
    if 1==1:
        if hunt_file is not None:
            if os.path.isfile(hunt_file):
                print(regex_file)
                regex_file=open(hunt_file).read().split("\n")
                regex_file.remove('')
                print(regex_file)
            else:
                print("Issue with the hunt file path" )
                return
        if os.path.isdir(path):
            files=list(libPath(path).rglob("*.[eE][vV][tT][xX]"))
        elif os.path.isfile(path):
            files=glob.glob(path)

        else:
            print("Issue with the path" )
            return

        #user_string = input('please enter a string to convert to regex: ')
        if str_regex is not None:
            regex=[str_regex]
        elif str_regex is None and len(regex_file)>0:
            regex=regex_file
        print("hunting ( %s ) in files ( %s )"%(regex,files))
        EvtxHunt.Evtx_hunt(files,regex,eid,input_timezone,Output,timestart,timeend)
    #except Exception as e:
    #    print("Error in hunting module ")
def report():
    global Output,User_SIDs
    timesketch=Output+"_TimeSketch.csv"
    Report=Output+"_Report.xlsx"
    LogonEvents=Output+"_Logon_Events.csv"
    ObjectAccess=Output+"_Object_Access_Events.csv"
    ProcessEvents=Output+"_Process_Execution_Events.csv"
    Collected_SIDs=Output+"_Collected_SIDs.csv"
    print("preparing report")
    if os.path.exists(temp_dir + "_User_SIDs_report.csv"):
        User_SIDs = pd.DataFrame(pd.read_csv(temp_dir + "_User_SIDs_report.csv"))
    else:
        print(f"{temp_dir + '_User_SIDs_report.csv'} does not exist.")
        User_SIDs = pd.DataFrame(User_SIDs)
    if os.path.exists(temp_dir + "_Sysmon_report.csv"):
        Sysmon = pd.DataFrame(pd.read_csv(temp_dir + "_Sysmon_report.csv"))
    else:
        print(f"{temp_dir + '_Sysmon_report.csv'} does not exist.")
        Sysmon = pd.DataFrame(Sysmon_events[0])
    if os.path.exists(temp_dir + "_System_report.csv"):
        System = pd.DataFrame(pd.read_csv(temp_dir + "_System_report.csv"))
    else:
        print(f"{temp_dir + '_System_report.csv'} does not exist.")
        System = pd.DataFrame(System_events[0])
    if os.path.exists(temp_dir + "_Powershell_report.csv"):
        Powershell = pd.DataFrame(pd.read_csv(temp_dir + "_Powershell_report.csv"))
    else:
        print(f"{temp_dir + '_Powershell_report.csv'} does not exist.")
        Powershell = pd.DataFrame(Powershell_events[0])
    if os.path.exists(temp_dir + "_Powershell_Operational_report.csv"):
        Powershell_Operational = pd.DataFrame(pd.read_csv(temp_dir + "_Powershell_Operational_report.csv"))
    else:
        print(f"{temp_dir + '_Powershell_Operational_report.csv'} does not exist.")
        Powershell_Operational = pd.DataFrame(Powershell_Operational_events[0])
    if os.path.exists(temp_dir + "_Security_report.csv"):
        Security = pd.DataFrame(pd.read_csv(temp_dir + "_Security_report.csv"))
    else:
        print(f"{temp_dir + '_Security_report.csv'} does not exist.")
        Security = pd.DataFrame(Security_events[0])
    if os.path.exists(temp_dir + "_TerminalServices_report.csv"):
        TerminalServices = pd.DataFrame(pd.read_csv(temp_dir + "_TerminalServices_report.csv"))
    else:
        print(f"{temp_dir + '_TerminalServices_report.csv'} does not exist.")
        TerminalServices = pd.DataFrame(TerminalServices_events[0])
    if os.path.exists(temp_dir + "_WinRM_events_report.csv"):
        WinRM = pd.DataFrame(pd.read_csv(temp_dir + "_WinRM_events_report.csv"))
        #print(WinRM_Resolved_User)
        if len(WinRM_Resolved_User)>0:
            try:
                WinRM['Resolved User Name']=WinRM_Resolved_User
                WinRM=WinRM[['Date and Time','timestamp','Detection Rule','Severity','Detection Domain','Event Description','UserID','Resolved User Name','Event ID','Original Event Log','Computer Name','Channel']]
            except:
                print("Error resolving SIDs for WinRM")
    else:
        print(f"{temp_dir + '_WinRM_events_report.csv'} does not exist.")
        WinRM = pd.DataFrame(WinRM_events[0])
    if os.path.exists(temp_dir + "_TerminalServices_RDPClient_report.csv"):
        TerminalClient = pd.DataFrame(pd.read_csv(temp_dir + "_TerminalServices_RDPClient_report.csv"))
        #print(RDPClient_Resolved_User)
        if len(RDPClient_Resolved_User) > 0:
            try:
                TerminalClient['Resolved User Name'] = RDPClient_Resolved_User
                TerminalClient = TerminalClient[['Date and Time', 'timestamp', 'Detection Rule', 'Severity', 'Detection Domain', 'Event Description','Event ID', 'UserID', 'Resolved User Name', 'Source IP', 'Computer Name', 'Channel', 'Original Event Log']]
            except:
                print("Error resolving SIDs for Terminal Client")
    else:
        print(f"{temp_dir + '_TerminalServices_RDPClient_report.csv'} does not exist.")
        TerminalClient = pd.DataFrame(TerminalServices_RDPClient_events[0])

    if os.path.exists(temp_dir + "_Defender_report.csv"):
        Windows_Defender = pd.DataFrame(pd.read_csv(temp_dir + "_Defender_report.csv"))
    else:
        print(f"{temp_dir + '_Defender_report.csv'} does not exist.")
        Windows_Defender = pd.DataFrame(Windows_Defender_events[0])
    if os.path.exists(temp_dir + "_ScheduledTask_report.csv"):
        ScheduledTask = pd.DataFrame(pd.read_csv(temp_dir + "_ScheduledTask_report.csv"))
    else:
        print(f"{temp_dir + '_ScheduledTask_report.csv'} does not exist.")
        ScheduledTask = pd.DataFrame(ScheduledTask_events[0])

    if os.path.exists(temp_dir + "_Group_Policy_report.csv"):
        GroupPolicy = pd.DataFrame(pd.read_csv(temp_dir + "_Group_Policy_report.csv"))
    else:
        print(f"{temp_dir + '_Group_Policy_report.csv'} does not exist.")
        GroupPolicy = pd.DataFrame(Group_Policy_events[0])
    if os.path.exists(temp_dir + "_SMB_Server_report.csv"):
        SMBServer = pd.DataFrame(pd.read_csv(temp_dir + "_SMB_Server_report.csv"))
    else:
        print(f"{temp_dir + '_SMB_Server_report.csv'} does not exist.")
        SMBServer = pd.DataFrame(SMB_Server_events[0])
    if os.path.exists(temp_dir + "_SMB_Client_report.csv"):
        SMBClient = pd.DataFrame(pd.read_csv(temp_dir + "_SMB_Client_report.csv"))
    else:
        print(f"{temp_dir + '_SMB_Client_report.csv'} does not exist.")
        SMBClient= pd.DataFrame(SMB_Client_events[0])

    # if os.path.exists(temp_dir + "_Executed_Powershell_report.csv"):
    #     ExecutedPowershell_Summary = pd.DataFrame(pd.read_csv(temp_dir + "_Executed_Powershell_report.csv"))

    if os.path.exists(temp_dir + "Powershell_Execution_Events.pickle"):
        with open(temp_dir + "Powershell_Execution_Events.pickle", 'rb') as handle:
            #Authentication_Summary=pd.DataFrame(pickle.load(handle))
            Powershell_Execution_dataframes=pickle.load(handle)
            #print(Security_Authentication_dataframes[0])
            result=pd.concat(Powershell_Execution_dataframes, axis=0)
            #ExecutedProcess_Summary=result.groupby('User').agg({'Number of Failed Logins': 'sum', 'Number of Successful Logins': 'sum'})
            ExecutedPowershell_Summary =result.groupby('Command',as_index=False)['Number of Execution'].sum()
    else:
        print(f"{temp_dir + '_Executed_Powershell_report.csv'} does not exist.")
        ExecutedPowershell_Summary = pd.DataFrame(Executed_Powershell_Summary[0])


    if os.path.exists(temp_dir + "Security_Authentication.pickle"):
        with open(temp_dir + "Security_Authentication.pickle", 'rb') as handle:
            #Authentication_Summary=pd.DataFrame(pickle.load(handle))
            Security_Authentication_dataframes=pickle.load(handle)
            #print(Security_Authentication_dataframes[0])
            result=pd.concat(Security_Authentication_dataframes, axis=0)
            Authentication_Summary=result.groupby('User',as_index=False).agg(
                {'Number of Failed Logins': 'sum', 'Number of Successful Logins': 'sum'})
            #print(Authentication_Summary)

    #if os.path.exists(temp_dir + "_Security_Authentication_report.csv"):
        #Authentication_Summary = pd.DataFrame(pd.read_csv(temp_dir + "_Security_Authentication_report.csv"))

    else:
        print(f"{temp_dir + '_Security_Authentication_report.csv'} does not exist.")
        Authentication_Summary = pd.DataFrame(Security_Authentication_Summary[0])

    # if os.path.exists(temp_dir + "_Executed_Process_report.csv"):
    #     ExecutedProcess_Summary = pd.DataFrame(pd.read_csv(temp_dir + "_Executed_Process_report.csv"))
    if os.path.exists(temp_dir + "Executed_Process_Events.pickle"):
        with open(temp_dir + "Executed_Process_Events.pickle", 'rb') as handle:
            #Authentication_Summary=pd.DataFrame(pickle.load(handle))
            Process_Execution_dataframes=pickle.load(handle)
            #print(Security_Authentication_dataframes[0])
            result=pd.concat(Process_Execution_dataframes, axis=0)
            #ExecutedProcess_Summary=result.groupby('User').agg({'Number of Failed Logins': 'sum', 'Number of Successful Logins': 'sum'})
            ExecutedProcess_Summary =result.groupby('Process Name',as_index=False)['Number of Execution'].sum()
            #print(Authentication_Summary)
    else:
        print(f"{temp_dir + '_Executed_Process_report.csv'} does not exist.")
        ExecutedProcess_Summary = pd.DataFrame(Executed_Process_Summary[0])

    # TerminalClient = pd.DataFrame(pd.read_csv(temp_dir+"_TerminalServices_RDPClient_report.csv"))
    # TerminalClient['Resolved User Name']=RDPClient_Resolved_User
    # TerminalClient=TerminalClient[['Date and Time', 'timestamp', 'Detection Rule', 'Severity', 'Detection Domain','Event Description', 'Event ID', 'UserID','Resolved User Name', 'Source IP', 'Computer Name', 'Channel','Original Event Log']]
    # Windows_Defender = pd.DataFrame(pd.read_csv(temp_dir+"_Defender_report.csv"))
    # ScheduledTask = pd.DataFrame(pd.read_csv(temp_dir+"_ScheduledTask_report.csv"))
    # GroupPolicy = pd.DataFrame(pd.read_csv(temp_dir+"_Group_Policy_report.csv"))
    # SMBServer= pd.DataFrame(pd.read_csv(temp_dir+"_SMB_Server_report.csv"))
    # SMBClient= pd.DataFrame(pd.read_csv(temp_dir+"_SMB_Clientr_report.csv"))
    # WinRM['Resolved User Name']=WinRM_Resolved_User
    # WinRM=WinRM[['Date and Time','timestamp','Detection Rule','Severity','Detection Domain','Event Description','UserID','Resolved User Name','Event ID','Original Event Log','Computer Name','Channel']]


    Terminal_Services_Summary = TerminalServices['User'].value_counts().reset_index() # pd.DataFrame(TerminalServices_Summary[0])
    Terminal_Services_Summary.columns = ['User', 'Authentication Counts']


    #Logon_Events_pd=pd.DataFrame(Logon_Events[0])
    #Object_Access_Events_pd=pd.DataFrame(Object_Access_Events[0])
    #ExecutedProcess_Events_pd=pd.DataFrame(Executed_Process_Events[0])
    # allresults=pd.DataFrame([TerminalServices,Powershell_Operational],columns=['Date and Time', 'Detection Rule','Detection Domain','Severity','Event Description','Event ID','Original Event Log'])
    allresults = pd.concat(
        [ScheduledTask, Powershell_Operational, Sysmon, System, Powershell, Security,TerminalClient, TerminalServices, WinRM,
         Windows_Defender,GroupPolicy,SMBServer,SMBClient], join="inner", ignore_index=True)
    allresults = allresults.rename(columns={'Date and Time': 'datetime', 'Detection Rule': 'message'})
    allresults['timestamp_desc'] = ""
    allresults = allresults[
        ['message','timestamp', 'datetime', 'timestamp_desc', 'Detection Domain', 'Severity', 'Event Description', 'Event ID',
         'Original Event Log','Computer Name','Channel']]
    Result_Summary_Severity=allresults["Severity"].value_counts().reset_index()
    Result_Summary_Severity.columns = ['Severity', 'Counts']
    Result_Summary_Detections=allresults["message"].value_counts().reset_index()
    Result_Summary_Detections.columns = ['Detection', 'Counts']
    allresults.to_csv(timesketch, index=False)
    User_SIDs.to_csv(Collected_SIDs, index=False)
    print("Time Sketch Report saved as "+timesketch)
    #Logon_Events_pd.to_csv(LogonEvents, index=False)
    if (logons==True or allreport==True):
        print("Logon Events Report saved as "+LogonEvents)
    #Object_Access_Events_pd.to_csv(ObjectAccess, index=False)
    if (objectaccess==True or allreport==True):
        print("Object Access Events Report saved as "+ObjectAccess)
    #ExecutedProcess_Events_pd.to_csv(ProcessEvents, index=False)
    if (processexec==True or allreport==True):
        print("Process Execution Events Report saved as "+ProcessEvents)

    # Sysmon=Sysmon.reset_index()
    # Sysmon=Sysmon.drop(['index'],axis=1)
    writer = pd.ExcelWriter(Report, engine='xlsxwriter', engine_kwargs={'options':{'encoding': 'utf-8'}})
    Result_Summary_Severity.to_excel(writer, sheet_name='Result Summary', index=False)
    Result_Summary_Detections.to_excel(writer, sheet_name='Result Summary' , startrow=len(Result_Summary_Severity)+3, index=False)
    System.to_excel(writer, sheet_name='System Events', index=False)
    Powershell.to_excel(writer, sheet_name='Powershell Events', index=False)
    Powershell_Operational.to_excel(writer, sheet_name='Powershell_Operational Events', index=False)
    Sysmon.to_excel(writer, sheet_name='Sysmon Events', index=False)
    Security.to_excel(writer, sheet_name='Security Events', index=False)
    TerminalServices.to_excel(writer, sheet_name='TerminalServices Events', index=False)
    TerminalClient.to_excel(writer, sheet_name='RDP Client Events', index=False)
    WinRM.to_excel(writer, sheet_name='WinRM Events', index=False)
    Windows_Defender.to_excel(writer, sheet_name='Windows_Defender Events', index=False)
    ScheduledTask.to_excel(writer, sheet_name='ScheduledTask Events', index=False)
    GroupPolicy.to_excel(writer, sheet_name='Group Policy Events', index=False)
    SMBClient.to_excel(writer, sheet_name='SMB Client Events', index=False)
    SMBServer.to_excel(writer, sheet_name='SMB Server Events', index=False)
    Terminal_Services_Summary.to_excel(writer, sheet_name='Terminal Services Logon Summary', index=False)
    Authentication_Summary.to_excel(writer, sheet_name='Security Authentication Summary', index=False)
    ExecutedProcess_Summary.to_excel(writer, sheet_name='Executed Process Summary', index=False)
    ExecutedPowershell_Summary.to_excel(writer, sheet_name='Executed Powershell Summary', index=False)
    User_SIDs.to_excel(writer, sheet_name='Collected User SIDs', index=False)
    writer.book.use_zip64()
    writer.close()
    print("Report saved as "+Report)

################################################################################################################
    # if (frequencyanalysis==True or allreport==True):
    #     Frequency_Security=pd.DataFrame(list(Frequency_Analysis_Security.items()),columns=["EventID","Count"]).sort_values(by=['Count'],ascending=False)
    #     Frequency_Defender=pd.DataFrame(list(Frequency_Analysis_Windows_Defender.items()),columns=["EventID","Count"]).sort_values(by=['Count'],ascending=False)
    #     Frequency_SMB_Client=pd.DataFrame(list(Frequency_Analysis_SMB_Client.items()),columns=["EventID","Count"]).sort_values(by=['Count'],ascending=False)
    #     Frequency_Group_Policy=pd.DataFrame(list(Frequency_Analysis_Group_Policy.items()),columns=["EventID","Count"]).sort_values(by=['Count'],ascending=False)
    #     Frequency_Powershell_Operational=pd.DataFrame(list(Frequency_Analysis_Powershell_Operational.items()),columns=["EventID","Count"]).sort_values(by=['Count'],ascending=False)
    #     Frequency_Powershell=pd.DataFrame(list(Frequency_Analysis_Powershell.items()),columns=["EventID","Count"]).sort_values(by=['Count'],ascending=False)
    #     Frequency_ScheduledTask=pd.DataFrame(list(Frequency_Analysis_ScheduledTask.items()),columns=["EventID","Count"]).sort_values(by=['Count'],ascending=False)
    #     Frequency_WinRM=pd.DataFrame(list(Frequency_Analysis_WinRM.items()),columns=["EventID","Count"]).sort_values(by=['Count'],ascending=False)
    #     Frequency_Sysmon=pd.DataFrame(list(Frequency_Analysis_Sysmon.items()),columns=["EventID","Count"]).sort_values(by=['Count'],ascending=False)
    #     Frequency_SMB_Server=pd.DataFrame(list(Frequency_Analysis_SMB_Server.items()),columns=["EventID","Count"]).sort_values(by=['Count'],ascending=False)
    #     Frequency_TerminalServices=pd.DataFrame(list(Frequency_Analysis_TerminalServices.items()),columns=["EventID","Count"]).sort_values(by=['Count'],ascending=False)
    #     Frequency_System=pd.DataFrame(list(Frequency_Analysis_System.items()),columns=["EventID","Count"]).sort_values(by=['Count'],ascending=False)
    #
    #     writer = pd.ExcelWriter("EventID_Frequency_Analysis.xls", engine='xlsxwriter', options={'encoding': 'utf-8'})
    #     Frequency_System.to_excel(writer, sheet_name='System', index=False)
    #     Frequency_Powershell.to_excel(writer, sheet_name='Powershell', index=False)
    #     Frequency_Powershell_Operational.to_excel(writer, sheet_name='Powershell_Operational', index=False)
    #     Frequency_Sysmon.to_excel(writer, sheet_name='Sysmon', index=False)
    #     Frequency_Security.to_excel(writer, sheet_name='Security', index=False)
    #     Frequency_TerminalServices.to_excel(writer, sheet_name='TerminalServices', index=False)
    #     Frequency_WinRM.to_excel(writer, sheet_name='WinRM', index=False)
    #     Frequency_Defender.to_excel(writer, sheet_name='Windows_Defender', index=False)
    #     Frequency_ScheduledTask.to_excel(writer, sheet_name='ScheduledTask', index=False)
    #     Frequency_Group_Policy.to_excel(writer, sheet_name='Group Policy', index=False)
    #     Frequency_SMB_Client.to_excel(writer, sheet_name='SMB Client', index=False)
    #     Frequency_SMB_Server.to_excel(writer, sheet_name='SMB Server', index=False)
    #
    #     writer.book.use_zip64()
    #     writer.save()
    #
    #     print("Frequency Analysis Report saved as "+"EventID_Frequency_Analysis.xls")
##################################################################################################################
    print("Detection Summary :\n############################################\nNumber of incidents by Severity:\n"+allresults["Severity"].value_counts().to_string()+"\n############################################\nNumber of incidents by Detection Rule:\n"+allresults["message"].value_counts().to_string()+"\n\n")



def convert_list():
    global timestart,timeend,User_SIDs,SMB_Server_events,SMB_Client_events,TerminalServices_RDPClient_events,Executed_Process_Events,Group_Policy_events,Object_Access_Events,input_timezone,Logon_Events,Executed_Process_Summary,TerminalServices_Summary,Security_Authentication_Summary,Sysmon_events,WinRM_events,Security_events,System_events,ScheduledTask_events,Powershell_events,Powershell_Operational_events,TerminalServices_events,Windows_Defender_events,Timesketch_events,TerminalServices_Summary,Security_Authentication_Summary,Executed_Powershell_Summary
    Results=[Executed_Powershell_Summary,SMB_Server_events,User_SIDs,SMB_Client_events,TerminalServices_RDPClient_events,Executed_Process_Events,Group_Policy_events,Object_Access_Events,Logon_Events,Executed_Process_Summary,TerminalServices_Summary,Security_Authentication_Summary,Sysmon_events,WinRM_events,Security_events,System_events,ScheduledTask_events,Powershell_events,Powershell_Operational_events,TerminalServices_events,Windows_Defender_events,TerminalServices_Summary,Security_Authentication_Summary
]
    for result in Results:
        for i in result[0]:
            result[0][i]=list(result[0][i])

def resolveSID():
    global TerminalServices_RDPClient_events,WinRM_events,User_SIDs,RDPClient_Resolved_User,WinRM_Resolved_User
    if os.path.exists(temp_dir + "_WinRM_events_report.csv"):
        WinRM_events[0] = pd.DataFrame(pd.read_csv(temp_dir + "_WinRM_events_report.csv")).to_dict(orient='list')
    if os.path.exists(temp_dir + "_TerminalServices_RDPClient_report.csv"):
        TerminalServices_RDPClient_events[0] = pd.DataFrame(pd.read_csv(temp_dir + "_TerminalServices_RDPClient_report.csv")).to_dict(orient='list')
    RDPClient_Resolved_User=[]
    WinRM_Resolved_User=[]
    for SID in TerminalServices_RDPClient_events[0]["UserID"]:
        if SID in User_SIDs["SID"]:
            RDPClient_Resolved_User.append(User_SIDs["User"][User_SIDs["SID"].index(SID)])
        else:
            RDPClient_Resolved_User.append("Could not be resolved")

    for SID in WinRM_events[0]["UserID"]:
        if SID in User_SIDs["SID"]:
            WinRM_Resolved_User.append(User_SIDs["User"][User_SIDs["SID"].index(SID)])
        else:
            WinRM_Resolved_User.append("Could not be resolved")
    #print("user sid"+str(User_SIDs["SID"]))
    #print("RDPCLient : "+str(RDPClient_Resolved_User))
    #print("WinRM : " + str(WinRM_Resolved_User))
def create_temp_dir():
    global temp_dir

    temp_dir= "temp/"

    if not os.path.exists(temp_dir):
        os.makedirs(temp_dir)
        print(f"{temp_dir} has been created")
    else:
        print(f"{temp_dir} already exists")

def create_out_dir(output):
    global temp_dir



    if not os.path.exists(output):
        os.makedirs(output)
        print(f"output folder {output} has been created")
    else:
        print(f"output folder {output} already exists")


    return output+"/"+output

def clean_temp_dir():
    global temp_dir
    if os.path.exists(temp_dir):
        for root, dirs, files in os.walk(temp_dir, topdown=False):
            for name in files:
                os.remove(os.path.join(root, name))
            for name in dirs:
                os.rmdir(os.path.join(root, name))
        os.rmdir(temp_dir)

def main():
    tic = time.time()
    print(Banner)
    global CPU_Core,timestart,timeend,Output,objectaccess,Path,processexec,logons,frequencyanalysis,Security_path,system_path,scheduledtask_path,defender_path,powershell_path,powershellop_path,terminal_path,winrm_path,sysmon_path,input_timezone,objectaccess,processexec,logons,frequencyanalysis,allreport
    parser = argparse.ArgumentParser()
    parser.add_argument("-p","--path", help="path to folder containing windows event logs , APT-Hunter will detect each log type automatically")
    parser.add_argument("-o", "--out",help="output file name")
    parser.add_argument("-tz","--timezone", help="default Timezone is Local timezone , you can enter ( 'local' : for local timzone , <Country time zone> : like (Asia/Dubai) )")
    parser.add_argument("-hunt","--hunt", help="String or regex to be searched in evtx log path")
    parser.add_argument("-huntfile","--huntfile", help="file contain Strings or regex to be searched in evtx log path ( strings should be new line separated )")
    parser.add_argument("-eid","--eid", help="Event ID to search if you chosed the hunt module")
    parser.add_argument("-start","--start", help="Start time for timeline ( use ISO format Ex:2022-04-03T20:56+04:00 )")
    parser.add_argument("-end","--end", help="End time for timeline ( use ISO format Ex: 2022-04-03T20:56+04:00 or 2022-04-03T20:56 or 2022-04-03 20:56 or 2022-04-03 )")
    parser.add_argument("-procexec","--procexec", help="Produce Process Execution report",action='store_true')
    parser.add_argument("-logon","--logon", help="Produce Success and faild authentication report",action='store_true')
    parser.add_argument("-objaccess","--objaccess", help="Produce Object Access report",action='store_true')
    parser.add_argument("-allreport","--allreport", help="Produce all reports",action='store_true')
    parser.add_argument("-sigma","--sigma", help="use sigma module to search logs using sigma rules",action='store_true')
    parser.add_argument("-rules","--rules", help="path to sigma rules in json format")
    #parser.add_argument("-evtfreq","--evtfreq", help="Produce event ID frequency analysis report",action='store_true')
    parser.add_argument("-cores","--cores", help="cpu cores to be used in multiprocessing , default is half the number of availble CPU cores")
    args = parser.parse_args()
    if args.out is not None:
        Output=create_out_dir(args.out)
    if (args.path is None ):# and args.security is None and args.system is None and args.scheduledtask is None and args.defender is None and args.powershell is None and args.powershellop is None and args.terminal is None and args.winrm is None and args.sysmon is None):
        print("You didn't specify a path for the logs \nuse --help to print help message")
        exit()
    #if args.type is None and args.hunt is None:
    #    print("log type must be defined using -t \ncsv( logs from get-eventlog or windows event log GUI or logs from Get-WinEvent ) , evtx ( EVTX extension windows event log )\nuse --help to print help message")
    #    exit()
    else:
        #if args.path is not None:
        Path=args.path
        objectaccess=args.objaccess
        processexec=args.procexec
        logons=args.logon
        #frequencyanalysis=args.evtfreq
        allreport=args.allreport
        CPU_Core=0
        print(f"all reports value : {allreport}\nlogons value {logons}")
        try:
            if args.start is not None and args.end is not None:
                timestart=datetime.timestamp(dateutil.parser.isoparse(args.start))
                timeend=datetime.timestamp(dateutil.parser.isoparse(args.end))
        except:
            print("Error parsing time , please use ISO format with timestart and timeend Ex: (2022-04-03T20:56+04:00 or 2022-04-03T20:56 or 2022-04-03 20:56 or 2022-04-03)")
            exit()

        if args.timezone is not None:
            if args.timezone.lower()=="local":
                input_timezone=tz.tzlocal()
            else:
                input_timezone=timezone(args.timezone)
        if args.cores is not None:
            try:
                CPU_Core=int(args.cores)
            except:
                print(f"Error using supplied CPU cores {args.cores}")
                exit(0)
        if args.sigma is not False:
            if args.rules is not None:
                SigmaHunter.Sigma_Analyze(Path,args.rules,Output)
            else:
                print("Please include rules path ex : --rules rules.json")
            toc = time.time()
            print('Done in {:.4f} seconds'.format(toc-tic))
            return
        if args.hunt is not None:
            if args.eid is not None:
                threat_hunt(Path,args.hunt,args.eid,None)
            else:
                threat_hunt(Path,args.hunt,None,None)
            toc = time.time()
            print('Done in {:.4f} seconds'.format(toc-tic))
            return
        if args.hunt is None and args.huntfile is not None:
            if args.eid is not None:
                threat_hunt(Path,None,args.eid,args.huntfile)
            else:
                threat_hunt(Path,None,None,args.huntfile)
            toc = time.time()
            print('Done in {:.4f} seconds'.format(toc-tic))
            return


        #if args.type is None or args.type=="evtx":
        try:
            create_temp_dir()
            auto_detect(Path)
            #convert_list()
            report()
            clean_temp_dir()
        except Exception as e:
            print("Error "+str(e))
            clean_temp_dir()

        toc = time.time()
        print('Analysis finished in {:.4f} seconds'.format(toc-tic))
        return



if __name__ == '__main__':
    if  platform.system().lower()=="windows":
        multiprocessing.freeze_support()

    main()
