try{
New-Item -ItemType "directory" -Path "wineventlog"

}
catch
{
echo "can't create a new directory"
}

try{
get-eventlog -log Security | export-csv wineventlog/Security.csv
}
catch 
{
echo "Can't retrieve Security Logs"
}

try
{
Get-WinEvent -LogName System | export-csv wineventlog/System.csv
}
catch 
{
echo "Can't retrieve System Logs"
}

try{
Get-WinEvent -LogName Application | export-csv wineventlog/Application.csv
}
catch 
{
echo "Can't retrieve Application Logs"
}


try{
Get-WinEvent -LogName "Windows PowerShell" | export-csv wineventlog/Windows_PowerShell.csv
}
catch 
{
echo "Can't retrieve Windows PowerShell Logs"
}

try{
Get-WinEvent -LogName "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" | export-csv wineventlog/LocalSessionManager.csv
}
catch 
{
echo "Can't retrieve Microsoft-Windows-TerminalServices-LocalSessionManager/Operational Logs"
}

try{
Get-WinEvent -LogName "Microsoft-Windows-Windows Defender/Operational" | export-csv wineventlog/Windows_Defender.csv
}
catch 
{
echo "Can't retrieve Microsoft-Windows-Windows Defender/Operational Logs"
}

try{
Get-WinEvent -LogName Microsoft-Windows-TaskScheduler/Operational | export-csv wineventlog/TaskScheduler.csv
}
catch 
{
echo "Can't retrieve Microsoft-Windows-TaskScheduler/Operational Logs"
}

try{
Get-WinEvent -LogName Microsoft-Windows-WinRM/Operational | export-csv wineventlog/WinRM.csv
}
catch 
{
echo "Can't retrieve Microsoft-Windows-WinRM/Operational Logs"
}

try{
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | export-csv wineventlog/Sysmon.csv
}
catch 
{
echo "Can't retrieve Microsoft-Windows-Sysmon/Operational Logs"
}


try{
Get-WinEvent -LogName Microsoft-Windows-PowerShell/Operational | export-csv wineventlog/Powershell_Operational.csv
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
