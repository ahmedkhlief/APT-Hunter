# APT-Hunter
APT-Hunter is Threat Hunting tool for windows event logs which made by purple team mindset to provide detect APT movements hidden in the sea of windows event logs to decrease the time to uncover suspicious activity . this tool will make a good use of the windows event logs collected and make sure to not miss critical events configured to be detected. If you are a Threat Hunter , Incident Responder or forensic investigator , i assure you will enjoy using this tool , why ? i will discuss the reason in this article and how it will make your life easy just it made mine . Kindly note this tool is heavily tested but still a beta version and may contain bugs .

```bash

  /$$$$$$  /$$$$$$$  /$$$$$$$$         /$$   /$$                       /$$
 /$$__  $$| $$__  $$|__  $$__/        | $$  | $$                      | $$
| $$  \ $$| $$  \ $$   | $$           | $$  | $$ /$$   /$$ /$$$$$$$  /$$$$$$    /$$$$$$   /$$$$$$
| $$$$$$$$| $$$$$$$/   | $$    /$$$$$$| $$$$$$$$| $$  | $$| $$__  $$|_  $$_/   /$$__  $$ /$$__  $$
| $$__  $$| $$____/    | $$   |______/| $$__  $$| $$  | $$| $$  \ $$  | $$    | $$$$$$$$| $$  \__/
| $$  | $$| $$         | $$           | $$  | $$| $$  | $$| $$  | $$  | $$ /$$| $$_____/| $$
| $$  | $$| $$         | $$           | $$  | $$|  $$$$$$/| $$  | $$  |  $$$$/|  $$$$$$$| $$
|__/  |__/|__/         |__/           |__/  |__/ \______/ |__/  |__/   \___/   \_______/|__/

                                                                By : Ahmed Khlief , @ahmed_khlief
                                                                Version : 2.0

usage: APT-Hunter.py [-h] [-p PATH] [-o OUT] [-tz TIMEZONE] [-hunt HUNT]

optional arguments:
  -h, --help            show this help message and exit
  -p PATH, --path PATH  path to folder containing windows event logs , APT-
                        Hunter will detect each log type automatically
  -o OUT, --out OUT     output file name
  -tz TIMEZONE, --timezone TIMEZONE
                        default Timezone is UTC , you can enter ( 'local' :
                        for local timzone , <Country time zone> : like
                        (Asia/Dubai) )
  -hunt HUNT, --hunt HUNT
                        String or regex to be searched in evtx log path

```
Full information about the tool and how its used in this article : [introducing-apt-hunter-threat-hunting-tool-using-windows-event-log](https://shells.systems/introducing-apt-hunter-threat-hunting-tool-via-windows-event-log/)

New Version Announcement : [APT-Hunter V2.0 : More than 200 use cases and new features](https://shells.systems/apt-hunter-v2-0-more-than-200-use-cases-and-new-features/)
[Latest Release](https://github.com/ahmedkhlief/APT-Hunter/releases/tag/V2.0-Beta)

Author :

Twitter : [@ahmed_khlief](https://twitter.com/ahmed_khlief)

Linkedin : [Ahmed Khlief](https://www.linkedin.com/in/ahmed-khlief-499321a7)

# How to Use APT-Hunter

The first thing to do is to collect the logs if you didn’t and with powershell log collectors its easy to collect the needed logs automatically you just run the powershell scripts as administrator .

- To collect the logs in EVTX format
```powershell
curl https://raw.githubusercontent.com/ahmedkhlief/APT-Hunter/main/windows-log-collector-full-v3-EVTX.ps1 -o windows-log-collector-full-v3-EVTX.ps1
. .\windows-log-collector-full-v3-EVTX.ps1
```

- To collect the logs in CSV format
```powershell
curl https://raw.githubusercontent.com/ahmedkhlief/APT-Hunter/main/windows-log-collector-full-v3-CSV.ps1 -o windows-log-collector-full-v3-CSV.ps1
. .\windows-log-collector-full-v3-EVTX.ps1
```
> **Note**: Windows users please use the latest release : [Latest Release](https://github.com/ahmedkhlief/APT-Hunter/releases)

APT-Hunter built using python3 so in order to use the tool you need to install the required libraries ( **python3.9 is not supported yet**).

`python3 -m pip install -r requirements.txt`

APT-Hunter is easy to use you just use the argument -h to print help to see the options needed .

` python3 APT-Hunter.py -h`

`usage: APT-Hunter.py [-h] [-p PATH] [-o OUT] `

`  -h, --help            show this help message and exit`

`  -p PATH, --path PATH  path to folder containing windows event logs in EVTX format`

` -o : name of the project which will be used in the generated output sheets`


The remaining arguments if you want to analyze single type of logs.

# Usage:

Analyzing EVTX files ,you can provide directory containg the logs or a single file and APT hunter will detect the type of logs.

```python
python3 APT-Hunter.py -p /opt/wineventlog/ -o Project1
```
- Hunting using String or regex :

```python
python3 APT-Hunter.py  -hunt "psexec" -p /opt/wineventlog/ -o Project2`

python3 APT-Hunter.py  -hunt "(psexec|psexesvc)" -p /opt/wineventlog/ -o Project2`
```
# The result will be available in two sheets :

`Project1_Report.xlsx` : this excel sheet will include all the events detected from every windows logs provided to APT-Hunter

`Project1_TimeSketch.csv` : This CSV file you can upload it to timesketch in order to have timeline analysis that will help you see the full picture of the attack .

`Project1_Logon_Events.csv` : ALl logon events with parsed fields (Date, User , Source IP , Logon Process , Workstation Name , Logon Type , Device Name , Original Log ) as columns . This CSV file you can upload it to timesketch in order to have timeline analysis .
# Docker
Alternatively you can use run the tool from a docker container.
- Build the image
```bash
docker build -t apt-hunter .
```
- Run the tool
```bash
docker run --rm  -it -v $PWD:/apt-hunter apt-hunter [OPTIONS...]
# Example
docker run --rm  -it -v $PWD:/apt-hunter apt-hunter -h
docker run --rm  -it -v $PWD:/apt-hunter apt-hunter -p wineventlog  -o Project2
``` 
> **Note**: Make sure to have the logs directory and the output path in the current directory. 
# Credits :

I would like to thank [Joe Maccry](https://www.linkedin.com/in/joemccray/) for his amazing contribution in Sysmon use cases ( more than 100 use cases added by Joe )
