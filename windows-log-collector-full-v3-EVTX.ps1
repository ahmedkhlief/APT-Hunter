try{
New-Item -ItemType "directory" -Path "wineventlog"

}
catch
{
echo "can't create a new directory"
}

try{
 wevtutil epl Security wineventlog/Security.evtx
}
catch 
{
echo "Can't retrieve Security Logs"
}

try
{
 wevtutil epl System wineventlog/System.evtx
}
catch 
{
echo "Can't retrieve System Logs"
}

try{
wevtutil epl Application  wineventlog/Application.evtx
}
catch 
{
echo "Can't retrieve Application Logs"
}


try{
wevtutil epl "Windows PowerShell"  wineventlog/Windows_PowerShell.evtx
}
catch 
{
echo "Can't retrieve Windows PowerShell Logs"
}

try{
wevtutil epl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational"  wineventlog/LocalSessionManager.evtx
}
catch 
{
echo "Can't retrieve Microsoft-Windows-TerminalServices-LocalSessionManager/Operational Logs"
}

try{
wevtutil epl "Microsoft-Windows-Windows Defender/Operational"  wineventlog/Windows_Defender.evtx
}
catch 
{
echo "Can't retrieve Microsoft-Windows-Windows Defender/Operational Logs"
}

try{
wevtutil epl Microsoft-Windows-TaskScheduler/Operational  wineventlog/TaskScheduler.evtx
}
catch 
{
echo "Can't retrieve Microsoft-Windows-TaskScheduler/Operational Logs"
}

try{
wevtutil epl Microsoft-Windows-WinRM/Operational  wineventlog/WinRM.evtx
}
catch 
{
echo "Can't retrieve Microsoft-Windows-WinRM/Operational Logs"
}

try{
wevtutil epl Microsoft-Windows-Sysmon/Operational  wineventlog/Sysmon.evtx
}
catch 
{
echo "Can't retrieve Microsoft-Windows-Sysmon/Operational Logs"
}


try{
wevtutil epl Microsoft-Windows-PowerShell/Operational  wineventlog/Powershell_Operational.evtx
}
catch 
{
echo "Can't retrieve Microsoft-Windows-PowerShell/Operational Logs"
}


try
{
Compress-Archive -Path wineventlog -DestinationPath ./logs.zip
}
catch
{
echo "couldn't compress the the log folder "
}
