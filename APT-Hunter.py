import traceback
import logging
from lib.Banner import *
import argparse
import pandas as pd
import lib.EvtxDetection as EvtxDetection
import lib.CSVDetection as CSVDetection


Output=""
Path=""
Security_path=""
system_path=""
scheduledtask_path=""
defender_path=""
powershell_path=""
powershellop_path=""
terminal_path=""
winrm_path=""
sysmon_path=""

TerminalServices_Summary=[{'User':[],'Number of Logins':[]}]
Security_Authentication_Summary=[{'User':[],'Number of Failed Logins':[],'Number of Successful Logins':[]}]
Sysmon_events=[{'Date and Time':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[]}]
WinRM_events=[{'Date and Time':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[]}]
Security_events=[{'Date and Time':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[]}]
System_events=[{'Date and Time':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Service Name':[],'Event Description':[],'Event ID':[],'Original Event Log':[]}]
ScheduledTask_events=[{'Date and Time':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Schedule Task Name':[],'Event Description':[],'Event ID':[],'Original Event Log':[]}]
Powershell_events=[{'Date and Time':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[]}]
Powershell_Operational_events=[{'Date and Time':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[]}]
TerminalServices_events=[{'Date and Time':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[]}]
Windows_Defender_events=[{'Date and Time':[],'Detection Rule':[],'Severity':[],'Detection Domain':[],'Event Description':[],'Event ID':[],'Original Event Log':[]}]
Timesketch_events=[{'message':[],'datetime':[],'timestamp_desc':[],'Event Description':[],'Severity':[],'Detection Domain':[],'Event ID':[],'Original Event Log':[]}]




def evtxdetect():
    global TerminalServices_Summary,Security_Authentication_Summary,Sysmon_events,WinRM_events,Security_events,System_events,ScheduledTask_events,Powershell_events,Powershell_Operational_events,TerminalServices_events,Windows_Defender_events,Timesketch_events,TerminalServices_Summary,Security_Authentication_Summary
    try:
        print(Security_path)
        EvtxDetection.detect_events_security_log(Security_path)
    except IOError :
        print("Error Analyzing Security logs: ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing Security logs")
        logging.error(traceback.format_exc())
    try:
        EvtxDetection.detect_events_system_log(system_path)
    except IOError :
        print("Error Analyzing System logs : ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing System logs ")
        logging.error(traceback.format_exc())
    try :
        EvtxDetection.detect_events_powershell_operational_log(powershellop_path)
    except IOError :
        print("Error Analyzing Powershell Operational logs : ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing Powershell Operational logs ")
        logging.error(traceback.format_exc())
    try :
        EvtxDetection.detect_events_powershell_log(powershell_path)
    except IOError :
        print("Error Analyzing Powershell logs : ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing Powershell logs ")
        logging.error(traceback.format_exc())
    try :
        EvtxDetection.detect_events_TerminalServices_LocalSessionManager_log(terminal_path)
    except IOError :
        print("Error Analyzing TerminalServices LocalSessionManager logs: ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing TerminalServices LocalSessionManager logs")
        logging.error(traceback.format_exc())
    try:
        EvtxDetection.detect_events_scheduled_task_log(scheduledtask_path)
    except IOError :
        print("Error Analyzing Scheduled Task logs : ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing Scheduled Task logs ")
        logging.error(traceback.format_exc())

    try:
        EvtxDetection.detect_events_windows_defender_log(defender_path)
    except IOError :
        print("Error Analyzing Windows Defender logs : ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing Windows Defender logs ")
        logging.error(traceback.format_exc())
    try:
        EvtxDetection.detect_events_Microsoft_Windows_WinRM(winrm_path)
    except IOError :
        print("Error Analyzing WinRM logs : ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing WinRM logs ")
        logging.error(traceback.format_exc())

    try:
        EvtxDetection.detect_events_Sysmon_log(sysmon_path)
    except IOError :
        print("Error Analyzing Sysmon logs ")
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing Sysmon logs ")
        logging.error(traceback.format_exc())


    Sysmon_events = EvtxDetection.Sysmon_events
    WinRM_events =EvtxDetection.WinRM_events
    Security_events =EvtxDetection.Security_events
    System_events =EvtxDetection.System_events
    ScheduledTask_events =EvtxDetection.ScheduledTask_events
    Powershell_events =EvtxDetection.Powershell_events
    Powershell_Operational_events =EvtxDetection.Powershell_Operational_events
    TerminalServices_events =EvtxDetection.TerminalServices_events
    Windows_Defender_events =EvtxDetection.Windows_Defender_events
    Timesketch_events =EvtxDetection.Timesketch_events
    TerminalServices_Summary=EvtxDetection.TerminalServices_Summary
    Security_Authentication_Summary =EvtxDetection.Security_Authentication_Summary

def csvdetect(winevent):
    global TerminalServices_Summary,Security_Authentication_Summary,Sysmon_events,WinRM_events,Security_events,System_events,ScheduledTask_events,Powershell_events,Powershell_Operational_events,TerminalServices_events,Windows_Defender_events,Timesketch_events,TerminalServices_Summary,Security_Authentication_Summary
    try:
        #print(Security_path,winevent)
        CSVDetection.detect_events_security_log(Security_path,winevent)
    except IOError :
        print("Error Analyzing Security logs: ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing Security logs")
        logging.error(traceback.format_exc())
    try:
        CSVDetection.detect_events_system_log(system_path,winevent)
    except IOError :
        print("Error Analyzing System logs : ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing System logs ")
        logging.error(traceback.format_exc())
    try :
        CSVDetection.detect_events_powershell_operational_log(powershellop_path,winevent)
    except IOError :
        print("Error Analyzing Powershell Operational logs : ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing Powershell Operational logs ")
        logging.error(traceback.format_exc())
    try :
        CSVDetection.detect_events_powershell_log(powershell_path,winevent)
    except IOError :
        print("Error Analyzing Powershell logs : ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing Powershell logs ")
        logging.error(traceback.format_exc())
    try :
        CSVDetection.detect_events_TerminalServices_LocalSessionManager_log(terminal_path,winevent)
    except IOError :
        print("Error Analyzing TerminalServices LocalSessionManager logs: ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing TerminalServices LocalSessionManager logs")
        logging.error(traceback.format_exc())
    try:
        CSVDetection.detect_events_scheduled_task_log(scheduledtask_path,winevent)
    except IOError :
        print("Error Analyzing Scheduled Task logs : ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing Scheduled Task logs ")
        logging.error(traceback.format_exc())

    try:
        CSVDetection.detect_events_windows_defender_log(defender_path,winevent)
    except IOError :
        print("Error Analyzing Windows Defender logs : ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing Windows Defender logs ")
        logging.error(traceback.format_exc())
    try:
        CSVDetection.detect_events_Microsoft_Windows_WinRM_CSV_log(winrm_path,winevent)
    except IOError :
        print("Error Analyzing WinRM logs : ", end='')
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing WinRM logs ")
        logging.error(traceback.format_exc())

    try:
        CSVDetection.detect_events_Sysmon_log(sysmon_path,winevent)
    except IOError :
        print("Error Analyzing Sysmon logs ")
        print("File Path Does Not Exist")
    except Exception as e:
        print("Error Analyzing Sysmon logs ")
        logging.error(traceback.format_exc())


    Sysmon_events = CSVDetection.Sysmon_events
    WinRM_events =CSVDetection.WinRM_events
    Security_events =CSVDetection.Security_events
    System_events =CSVDetection.System_events
    ScheduledTask_events =CSVDetection.ScheduledTask_events
    Powershell_events =CSVDetection.Powershell_events
    Powershell_Operational_events =CSVDetection.Powershell_Operational_events
    TerminalServices_events =CSVDetection.TerminalServices_events
    Windows_Defender_events =CSVDetection.Windows_Defender_events
    Timesketch_events =CSVDetection.Timesketch_events
    TerminalServices_Summary=CSVDetection.TerminalServices_Summary
    Security_Authentication_Summary =CSVDetection.Security_Authentication_Summary


def report():
    global Output
    timesketch=Output+"_TimeSketch.csv"
    Report=Output+"_Report.xlsx"
    Sysmon = pd.DataFrame(Sysmon_events[0])
    System = pd.DataFrame(System_events[0])
    Powershell = pd.DataFrame(Powershell_events[0])
    Powershell_Operational = pd.DataFrame(Powershell_Operational_events[0])
    Security = pd.DataFrame(Security_events[0])
    TerminalServices = pd.DataFrame(TerminalServices_events[0])
    WinRM = pd.DataFrame(WinRM_events[0])
    Windows_Defender = pd.DataFrame(Windows_Defender_events[0])
    ScheduledTask = pd.DataFrame(ScheduledTask_events[0])
    Terminal_Services_Summary = pd.DataFrame(TerminalServices_Summary[0])
    Authentication_Summary = pd.DataFrame(Security_Authentication_Summary[0])

    # allresults=pd.DataFrame([TerminalServices,Powershell_Operational],columns=['Date and Time', 'Detection Rule','Detection Domain','Severity','Event Description','Event ID','Original Event Log'])
    allresults = pd.concat(
        [ScheduledTask, Powershell_Operational, Sysmon, System, Powershell, Security, TerminalServices, WinRM,
         Windows_Defender], join="inner", ignore_index=True)
    allresults = allresults.rename(columns={'Date and Time': 'datetime', 'Detection Rule': 'message'})
    allresults['timestamp_desc'] = ""
    allresults = allresults[
        ['message', 'datetime', 'timestamp_desc', 'Detection Domain', 'Severity', 'Event Description', 'Event ID',
         'Original Event Log']]
    allresults.to_csv(timesketch, index=False)
    print("Time Sketch Report saved as "+timesketch)
    # Sysmon=Sysmon.reset_index()
    # Sysmon=Sysmon.drop(['index'],axis=1)
    writer = pd.ExcelWriter(Report, engine='xlsxwriter', options={'encoding': 'utf-8'})
    System.to_excel(writer, sheet_name='System Events', index=False)
    Powershell.to_excel(writer, sheet_name='Powershell Events', index=False)
    Powershell_Operational.to_excel(writer, sheet_name='Powershell_Operational Events', index=False)
    Sysmon.to_excel(writer, sheet_name='Sysmon Events', index=False)
    Security.to_excel(writer, sheet_name='Security Events', index=False)
    TerminalServices.to_excel(writer, sheet_name='TerminalServices Events', index=False)
    WinRM.to_excel(writer, sheet_name='WinRM Events', index=False)
    Windows_Defender.to_excel(writer, sheet_name='Windows_Defender Events', index=False)
    ScheduledTask.to_excel(writer, sheet_name='ScheduledTask Events', index=False)
    Terminal_Services_Summary.to_excel(writer, sheet_name='Terminal Services Logon Summary', index=False)
    Authentication_Summary.to_excel(writer, sheet_name='Security Authentication Summary', index=False)
    writer.save()
    print("Report saved as "+Report)



def main():
    print(Banner)
    global Output,Path,Security_path,system_path,scheduledtask_path,defender_path,powershell_path,powershellop_path,terminal_path,winrm_path,sysmon_path
    parser = argparse.ArgumentParser()
    parser.add_argument("-p","--path", help="path to folder containing windows event logs generated by the powershell log collector")
    parser.add_argument("-o", "--out",
                        help="output file name")
    parser.add_argument("-t","--type", help="csv ( logs from get-eventlog or windows event log GUI or logs from Get-WinEvent ) , evtx ( EVTX extension windows event log )",choices=["csv","evtx"])
    parser.add_argument("--security", help="Path to Security Logs")
    parser.add_argument("--system", help="Path to System Logs")
    parser.add_argument("--scheduledtask", help="Path to Scheduled Tasks Logs")
    parser.add_argument("--defender", help="Path to Defender Logs")
    parser.add_argument("--powershell", help="Path to Powershell Logs")
    parser.add_argument("--powershellop", help="Path to Powershell Operational Logs")
    parser.add_argument("--terminal", help="Path to TerminalServices LocalSessionManager Logs")
    parser.add_argument("--winrm", help="Path to Winrm Logs")
    parser.add_argument("--sysmon", help="Path to Sysmon Logs")


    args = parser.parse_args()
    if args.out is not None:
        Output=args.out
    if (args.path is None and args.security is None and args.system is None and args.scheduledtask is None and args.defender is None and args.powershell is None and args.powershellop is None and args.terminal is None and args.winrm is None and args.sysmon is None):
        print("You didn't specify a path for any log \nuse --help to print help message")
        exit()
    if args.type is None:
        print("log type must be defined using -t \ncsv( logs from get-eventlog or windows event log GUI or logs from Get-WinEvent ) , evtx ( EVTX extension windows event log )\nuse --help to print help message")
        exit()
    else:
        if args.path is not None:
            Path=args.path
            if args.type=="evtx":
                Security_path=Path+"/Security.evtx"
                system_path =Path+"/System.evtx"
                scheduledtask_path = Path+"/TaskScheduler.evtx"
                defender_path = Path+"/Windows_Defender.evtx"
                powershell_path = Path+"/Windows_PowerShell.evtx"
                powershellop_path = Path+"/Powershell_Operational.evtx"
                terminal_path = Path+"/LocalSessionManager.evtx"
                winrm_path = Path+"/WinRM.evtx"
                sysmon_path = Path+"/Sysmon.evtx"
            if args.type=="csv":
                Security_path=Path+"/Security.csv"
                system_path =Path+"/System.csv"
                scheduledtask_path = Path+"/TaskScheduler.csv"
                defender_path = Path+"/Windows_Defender.csv"
                powershell_path = Path+"/Windows_PowerShell.csv"
                powershellop_path = Path+"/Powershell_Operational.csv"
                terminal_path = Path+"/LocalSessionManager.csv"
                winrm_path = Path+"/WinRM.csv"
                sysmon_path = Path+"/Sysmon.csv"
        if args.security  is not None:
            Security_path = args.security

        if args.system  is not None:
            system_path=args.system

        if args.scheduledtask  is not None:
            scheduledtask_path=args.scheduledtask

        if args.defender  is not None:
            defender_path=args.defender
        if args.powershell  is not None:
            powershell_path=args.powershell
        if args.powershellop  is not None:
            powershellop_path=args.powershellop
        if args.terminal  is not None:
            terminal_path=args.terminal
        if args.winrm  is not None:
            winrm_path=args.winrm
        if args.sysmon  is not None:
            sysmon_path=args.sysmon
        if args.type=="evtx":
            evtxdetect()
        if args.type=="csv":
            csvdetect(True)
        report()


main()
