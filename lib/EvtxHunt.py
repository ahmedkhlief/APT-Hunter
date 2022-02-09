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

Hunting_events=[{'Date and Time':[],'timestamp':[],'Channel':[],'Computer':[],'Event ID':[],'Original Event Log':[]}]

EventID_rex = re.compile('<EventID.*>(.*)<\/EventID>', re.IGNORECASE)
Channel_rex = re.compile('<Channel.*>(.*)<\/Channel>', re.IGNORECASE)
Computer_rex = re.compile('<Computer.*>(.*)<\/Computer>', re.IGNORECASE)
def Evtx_hunt(files,str_regex,input_timzone,output):
    for file in files:
        file=str(file)
        print("Analyzing "+file)
        try:
            parser = PyEvtxParser(file)
        except:
            print("Issue analyzing "+file +"\nplease check if its not corrupted")
            continue
        try:
            rex=re.compile(str_regex, re.IGNORECASE)
            for record in parser.records():

                EventID = EventID_rex.findall(record['data'])

                if len(EventID) > 0:
                    Computer = Computer_rex.findall(record['data'])
                    Channel = Channel_rex.findall(record['data'])
                    if len(Channel)>0:
                        channel=Channel[0]
                    else:
                        channel=" "
                    #print(record['data'])
                #    if record['data'].lower().find(str_regex.lower())>-1:
                    if rex.findall(record['data']):
                        #print("EventID : "+EventID[0]+" , Data : "+record['data'])
                        Hunting_events[0]['timestamp'].append(datetime.timestamp(isoparse(parse(record["timestamp"]).astimezone(input_timzone).isoformat())))
                        Hunting_events[0]['Date and Time'].append(parse(record["timestamp"]).astimezone(input_timzone).isoformat())
                        Hunting_events[0]['Channel'].append(channel)
                        Hunting_events[0]['Event ID'].append(EventID[0])
                        Hunting_events[0]['Computer'].append(Computer[0])
                        Hunting_events[0]['Original Event Log'].append(str(record['data']).replace("\r", " ").replace("\n", " "))
        except Exception as e:
            print("issue searching log : "+record['data']+"\n Error : "+print(e))
        hunt_report(output)


def hunt_report(output):
    global Hunting_events
    Events = pd.DataFrame(Hunting_events[0])
    Events.to_csv(output+"_hunting.csv", index=False)
