from evtx import PyEvtxParser
import glob
import os
import re
from pathlib import Path as libPath
import pandas as pd
import json
import sqlite3
from flatten_json import flatten
import time
import multiprocessing

Alldata={'Original_Event_Log':[],'TargetObject': [], 'Channel': [], 'Computer': [], 'Correlation': [], 'EventID': [], 'EventRecordID': [], 'ProcessID': [], 'ThreadID': [], 'Keywords': [], 'Level': [], 'Opcode': [], 'Guid': [], 'Name': [], 'UserID': [], 'Task': [], 'SystemTime': [], 'Version': [], 'Status': [], 'ActivityID': [], 'Context': [], 'ErrorCode': [], 'AppId': [], 'DCName': [], 'Binary': [], 'Qualifiers': [], 'Security': [], 'Path': [], 'ScriptBlockText': [], 'param1': [], 'param2': [], 'ContextInfo': [], 'Payload': [], 'UserData': [], 'State': [], 'EventType': [], 'AccountName': [], 'ProcessName': [], 'LogonType': [], 'TaskName': [], 'Message': [], 'Provider': [], 'updateGuid': [], 'updateRevisionNumber': [], 'updateTitle': [], 'DeviceName': [], 'DeviceNameLength': [], 'ClientProcessId': [], 'PossibleCause': [], 'User': [], 'ProviderName': [], 'Query': [], 'value': [], 'Action': [], 'ApplicationPath': [], 'ModifyingApplication': [], 'Origin': [], 'Protocol': [], 'RuleName': [], 'SchemaVersion': [], 'ServiceName': [], 'Filename': [], 'PackagePath': [], 'FileNameBuffer': [], 'UserName': [], 'ShareName': [], 'NewState': [], 'Param3': [], 'EventSourceName': [], 'NumberOfGroupPolicyObjects': [], 'ProcessingMode': [], 'ProcessingTimeInMilliseconds': [], 'HostName': [], 'Ipaddress': [], 'NewTime': [], 'OldTime': [], 'HiveName': [], 'ErrorDescription': [], 'Address': [], 'AddressLength': [], 'QueryName': [], 'TSId': [], 'UserSid': [], 'DeviceTime': [], 'DeviceVersionMajor': [], 'DeviceVersionMinor': [], 'FinalStatus': [], 'ImagePath': [], 'ServiceType': [], 'StartType': [], 'ExtensionId': [], 'ExtensionName': [], 'ShutdownActionType': [], 'ShutdownEventCode': [], 'ShutdownReason': [], 'Group': [], 'IdleStateCount': [], 'Number': [], 'BootMode': [], 'BuildVersion': [], 'MajorVersion': [], 'MinorVersion': [], 'QfeVersion': [], 'ServiceVersion': [], 'StartTime': [], 'StopTime': [], 'TimeSource': [], 'Targetname': [], 'Caption': [], 'ErrorMessage': [], 'RetryMinutes': [], 'Description': [], 'Type': [], 'OperationType': [], 'CommandLine': [], 'PackageName': [], 'Data': [], 'LogonId': [], 'ServerName': [], 'ObjectName': [], 'AccessList': [], 'AccessMask': [], 'HandleId': [], 'ObjectServer': [], 'ObjectType': [], 'SubjectDomainName': [], 'SubjectLogonId': [], 'SubjectUserName': [], 'SubjectUserSid': [], 'NewProcessId': [], 'NewProcessName': [], 'ParentProcessName': [], 'TargetDomainName': [], 'TargetLogonId': [], 'TargetUserName': [], 'TargetUserSid': [], 'TokenElevationType': [], 'NewValue': [], 'ObjectValueName': [], 'OldValue': [], 'Properties': [], 'PrivilegeList': [], 'Service': [], 'AuthenticationPackageName': [], 'ImpersonationLevel': [], 'IpPort': [], 'KeyLength': [], 'LmPackageName': [], 'LogonGuid': [], 'LogonProcessName': [], 'TransmittedServices': [], 'WorkstationName': [], 'CallerProcessName': [], 'TargetSid': [], 'TaskContentNew': [], 'AuditPolicyChanges': [], 'SourceProcessId': [], 'TargetProcessId': [], 'TransactionId': [], 'TargetInfo': [], 'TargetLogonGuid': [], 'TargetServerName': [], 'Details': [], 'PackageFullName': [], 'processPath': [], 'Provider_Name': [], 'Accesses': [], 'AccountDomain': [], 'AccountExpires': [], 'AddonName': [], 'AllowedToDelegateTo': [], 'Application': [], 'AttributeLDAPDisplayName': [], 'AttributeValue': [], 'AuditSourceName': [], 'CallingProcessName': [], 'CallTrace': [], 'Company': [], 'CreationUtcTime': [], 'CurrentDirectory': [], 'DestinationAddress': [], 'DestinationHostname': [], 'DestinationIp': [], 'DestinationIsIpv6': [], 'DestinationPort': [], 'DestinationPortName': [], 'DestPort': [], 'Detail': [], 'DetectionSource': [], 'DeviceClassName': [], 'DeviceDescription': [], 'DisplayName': [], 'EngineVersion': [], 'EventSourceId': [], 'ExtraInfo': [], 'FailureCode': [], 'FailureReason': [], 'FileVersion': [], 'FilterHostProcessID': [], 'GrantedAccess': [], 'GroupDomain': [], 'GroupName': [], 'GroupSid': [], 'Hash': [], 'Hashes': [], 'HomeDirectory': [], 'HomePath': [], 'HostApplication': [], 'HostVersion': [], 'Image': [], 'ImageLoaded': [], 'Initiated': [], 'IntegrityLevel': [], 'LayerRTID': [], 'LDAPDisplayName': [], 'LogonHours': [], 'NewName': [], 'NewThreadId': [], 'NewUacValue': [], 'NotificationPackageName': [], 'ObjectClass': [], 'OldUacValue': [], 'OriginalFileName': [], 'ParentCommandLine': [], 'ParentImage': [], 'ParentProcessGuid': [], 'ParentProcessId': [], 'PasswordLastSet': [], 'PerfStateCount': [], 'PipeName': [], 'PreviousTime': [], 'PrimaryGroupId': [], 'ProcessCommandLine': [], 'ProcessGuid': [], 'Product': [], 'ProfilePath': [], 'ProtocolHostProcessID': [], 'PuaCount': [], 'PuaPolicyId': [], 'Publisher': [], 'QueryResults': [], 'QueryStatus': [], 'RelativeTargetName': [], 'ResourceManager': [], 'SAMAccountName': [], 'ScriptPath': [], 'SecurityPackageName': [], 'ServerID': [], 'ServerURL': [], 'ServicePrincipalNames': [], 'ShareLocalPath': [], 'SidHistory': [], 'Signature': [], 'SignatureStatus': [], 'Signed': [], 'SourceAddress': [], 'SourceHostname': [], 'SourceImage': [], 'SourceIp': [], 'SourceNetworkAddress': [], 'SourceIsIpv6': [], 'SourcePort': [], 'SourcePortName': [], 'SourceProcessGuid': [], 'StartAddress': [], 'StartFunction': [], 'StartModule': [], 'SubStatus': [], 'TargetFileName': [], 'TargetImage': [], 'TargetProcessAddress': [], 'TargetProcessGuid': [], 'TaskContent': [], 'TerminalSessionId': [], 'ThrottleStateCount': [], 'TicketEncryptionType': [], 'TicketOptions': [], 'UserAccountControl': [], 'UserParameters': [], 'UserPrincipalName': [], 'UserWorkstations': [], 'UtcTime': [], 'Workstation': [], 'ParentIntegrityLevel': [], 'ParentUser': []}

mapping={'Original_Event_Log':['Original_Event_Log'],'TargetObject': ['Event_EventData_TargetObject'], 'Channel': ['Event_System_Channel', 'Event_RenderingInfo_Channel'], 'Computer': ['Event_System_Computer'], 'Correlation': ['Event_System_Correlation'], 'EventID': ['Event_System_EventID', 'Event_System_EventID_#text'], 'EventRecordID': ['Event_System_EventRecordID'], 'ProcessID': ['Event_EventData_ProcessID', 'Event_EventData_ProcessId', 'Event_System_Execution_#attributes_ProcessID', 'Event_UserData_Operation_StartedOperational_ProcessID', 'Event_UserData_DroppedLeakDiagnosisEventInfo_ProcessId', 'Event_UserData_CompatibilityFixEvent_ProcessId', 'Event_UserData_Operation_TemporaryEssStarted_Processid', 'Event_EventData_processId'], 'ThreadID': ['Event_System_Execution_#attributes_ThreadID'], 'Keywords': ['Event_System_Keywords'], 'Level': ['Event_System_Level', 'Event_RenderingInfo_Level'], 'Opcode': ['Event_System_Opcode', 'Event_RenderingInfo_Opcode'], 'Guid': ['Event_System_Provider_#attributes_Guid', 'Event_EventData_Guid'], 'Name': ['Event_EventData_name', 'Event_System_Provider_#attributes_Name', 'Event_EventData_#attributes_Name', 'Event_UserData_CertNotificationData_CertificateDetails_EKUs_EKU_#attributes_Name', 'Event_EventData_Name', 'Event_UserData_CertNotificationData_CertificateDetails_Template_#attributes_Name', 'Event_UserData_CertNotificationData_NewCertificateDetails_EKUs_EKU_#attributes_Name', 'Event_UserData_CertNotificationData_NewCertificateDetails_Template_#attributes_Name', 'Event_UserData_CertNotificationData_OldCertificateDetails_EKUs_EKU_#attributes_Name', 'Event_UserData_CertNotificationData_OldCertificateDetails_Template_#attributes_Name', 'Event_UserData_MemoryExhaustionInfo_NonPagedPoolInfo_Tag_1_Name', 'Event_UserData_MemoryExhaustionInfo_NonPagedPoolInfo_Tag_2_Name', 'Event_UserData_MemoryExhaustionInfo_NonPagedPoolInfo_Tag_3_Name', 'Event_UserData_MemoryExhaustionInfo_PagedPoolInfo_Tag_1_Name', 'Event_UserData_MemoryExhaustionInfo_PagedPoolInfo_Tag_2_Name', 'Event_UserData_MemoryExhaustionInfo_PagedPoolInfo_Tag_3_Name', 'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_1_Name', 'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_2_Name', 'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_3_Name', 'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_4_Name', 'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_5_Name', 'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_6_Name', 'Event_UserData_EventData_Name'], 'UserID': ['Event_System_Security_#attributes_UserID', 'Event_EventData_UserId'], 'Task': ['Event_System_Task', 'Event_EventData_Task', 'Event_RenderingInfo_Task'], 'SystemTime': ['Event_System_TimeCreated_#attributes_SystemTime'], 'Version': ['Event_System_Version', 'Event_EventData_Version', 'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_1_Version', 'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_2_Version', 'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_3_Version', 'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_4_Version', 'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_5_Version', 'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_6_Version'], 'Status': ['Event_UserData_ChangingDefaultPrinter_Status', 'Event_EventData_Status', 'Event_UserData_EventData_Status'], 'ActivityID': ['Event_System_Correlation_#attributes_ActivityID', 'Event_EventData_ActivityId'], 'Context': ['Event_UserData_LoadPluginFailed_Context', 'Event_UserData_CertNotificationData_#attributes_Context'], 'ErrorCode': ['Event_UserData_LoadPluginFailed_ErrorCode', 'Event_EventData_ErrorCode', 'Event_UserData_CbsUpdateChangeState_ErrorCode', 'Event_UserData_CbsPackageChangeState_ErrorCode', 'Event_ProcessingErrorData_ErrorCode', 'Event_EventData_errorCode'], 'AppId': ['Event_EventData_AppId', 'Event_EventData_AppID'], 'DCName': ['Event_EventData_DCName'], 'Binary': ['Event_EventData_Binary'], 'Qualifiers': ['Event_System_EventID_#attributes_Qualifiers'], 'Security': ['Event_System_Security'], 'Path': ['Event_EventData_Path'], 'ScriptBlockText': ['Event_EventData_ScriptBlockText'], 'param1': ['Event_EventData_param1', 'Event_UserData_EventXML_Param1', 'Event_EventData_Param1'], 'param2': ['Event_EventData_param2', 'Event_UserData_EventXML_Param2', 'Event_EventData_Param2'], 'ContextInfo': ['Event_EventData_ContextInfo'], 'Payload': ['Event_EventData_Payload'], 'UserData': ['Event_EventData_UserData'], 'State': ['Event_EventData_State'], 'EventType': ['Event_UserData_InvalidCommitLimitExhaustion_EventType'], 'AccountName': ['Event_UserData_CertNotificationData_#attributes_AccountName', 'Event_EventData_AccountName'], 'ProcessName': ['Event_UserData_CertNotificationData_#attributes_ProcessName', 'Event_EventData_ProcessName'], 'LogonType': ['Event_EventData_LogonType'], 'TaskName': ['Event_EventData_TaskName'], 'Message': ['Event_EventData_message', 'Event_RenderingInfo_Message', 'Event_EventData_Message'], 'Provider': ['Event_RenderingInfo_Provider'], 'updateGuid': ['Event_EventData_updateGuid'], 'updateRevisionNumber': ['Event_EventData_updateRevisionNumber'], 'updateTitle': ['Event_EventData_updateTitle', 'Event_EventData_UpdateTitle'], 'DeviceName': ['Event_EventData_DeviceName', 'Event_EventData_Prop_DeviceName'], 'DeviceNameLength': ['Event_EventData_DeviceNameLength'], 'ClientProcessId': ['Event_UserData_Operation_ClientFailure_ClientProcessId'], 'PossibleCause': ['Event_UserData_Operation_ClientFailure_PossibleCause', 'Event_UserData_Operation_TemporaryEssStarted_PossibleCause'], 'User': ['Event_UserData_Operation_ClientFailure_User', 'Event_UserData_Operation_TemporaryEssStarted_User', 'Event_EventData_User', 'Event_UserData_EventXML_User'], 'ProviderName': ['Event_UserData_Operation_StartedOperational_ProviderName'], 'Query': ['Event_UserData_Operation_TemporaryEssStarted_Query'], 'value': ['Event_EventData_value', 'Event_EventData_Value'], 'Action': ['Event_EventData_Action', 'Event_UserData_CertNotificationData_Action'], 'ApplicationPath': ['Event_EventData_ApplicationPath'], 'ModifyingApplication': ['Event_EventData_ModifyingApplication'], 'Origin': ['Event_EventData_Origin'], 'Protocol': ['Event_EventData_Protocol', 'Event_EventData_protocol'], 'RuleName': ['Event_EventData_RuleName'], 'SchemaVersion': ['Event_EventData_SchemaVersion'], 'ServiceName': ['Event_EventData_ServiceName'], 'Filename': ['Event_EventData_Filename', 'Event_UserData_EventData_FileName', 'Event_EventData_FileName'], 'PackagePath': ['Event_EventData_PackagePath'], 'FileNameBuffer': ['Event_EventData_FileNameBuffer'], 'UserName': ['Event_UserData_EventData_UserName', 'Event_EventData_UserName', 'Event_EventData_userName', 'Event_EventData_Username'], 'ShareName': ['Event_UserData_EventData_ShareName', 'Event_EventData_ShareName'], 'NewState': ['Event_EventData_NewState'], 'Param3': ['Event_UserData_EventXML_Param3', 'Event_EventData_param3'], 'EventSourceName': ['Event_System_Provider_#attributes_EventSourceName'], 'NumberOfGroupPolicyObjects': ['Event_EventData_NumberOfGroupPolicyObjects'], 'ProcessingMode': ['Event_EventData_ProcessingMode'], 'ProcessingTimeInMilliseconds': ['Event_EventData_ProcessingTimeInMilliseconds'], 'HostName': ['Event_EventData_HostName'], 'Ipaddress': ['Event_EventData_Ipaddress', 'Event_EventData_IpAddress'], 'NewTime': ['Event_EventData_NewTime'], 'OldTime': ['Event_EventData_OldTime'], 'HiveName': ['Event_EventData_HiveName'], 'ErrorDescription': ['Event_EventData_ErrorDescription'], 'Address': ['Event_EventData_Address', 'Event_UserData_EventXML_Address'], 'AddressLength': ['Event_EventData_AddressLength'], 'QueryName': ['Event_EventData_QueryName'], 'TSId': ['Event_EventData_TSId'], 'UserSid': ['Event_EventData_UserSid', 'Event_UserData_EventXML_UserSid', 'Event_EventData_UserSID'], 'DeviceTime': ['Event_EventData_DeviceTime'], 'DeviceVersionMajor': ['Event_EventData_DeviceVersionMajor'], 'DeviceVersionMinor': ['Event_EventData_DeviceVersionMinor'], 'FinalStatus': ['Event_EventData_FinalStatus'], 'ImagePath': ['Event_EventData_ImagePath'], 'ServiceType': ['Event_EventData_ServiceType'], 'StartType': ['Event_EventData_StartType'], 'ExtensionId': ['Event_EventData_ExtensionId'], 'ExtensionName': ['Event_EventData_ExtensionName'], 'ShutdownActionType': ['Event_EventData_ShutdownActionType'], 'ShutdownEventCode': ['Event_EventData_ShutdownEventCode'], 'ShutdownReason': ['Event_EventData_ShutdownReason'], 'Group': ['Event_EventData_Group'], 'IdleStateCount': ['Event_EventData_IdleStateCount'], 'Number': ['Event_EventData_Number', 'Event_EventData_number'], 'BootMode': ['Event_EventData_BootMode'], 'BuildVersion': ['Event_EventData_BuildVersion'], 'MajorVersion': ['Event_EventData_MajorVersion'], 'MinorVersion': ['Event_EventData_MinorVersion'], 'QfeVersion': ['Event_EventData_QfeVersion'], 'ServiceVersion': ['Event_EventData_ServiceVersion'], 'StartTime': ['Event_EventData_StartTime', 'Event_UserData_CompatibilityFixEvent_StartTime'], 'StopTime': ['Event_EventData_StopTime'], 'TimeSource': ['Event_EventData_TimeSource'], 'Targetname': ['Event_EventData_Targetname'], 'Caption': ['Event_EventData_Caption'], 'ErrorMessage': ['Event_EventData_ErrorMessage'], 'RetryMinutes': ['Event_EventData_RetryMinutes'], 'Description': ['Event_EventData_Description'], 'Type': ['Event_EventData_Type'], 'OperationType': ['Event_EventData_OperationType'], 'CommandLine': ['Event_EventData_CommandLine'], 'PackageName': ['Event_EventData_PackageName'], 'Data': ['Event_EventData_Data', 'Event_EventData_Data_#text'], 'LogonId': ['Event_EventData_LogonId'], 'ServerName': ['Event_EventData_ServerName', 'Event_EventData_serverName'], 'ObjectName': ['Event_EventData_ObjectName'], 'AccessList': ['Event_EventData_AccessList'], 'AccessMask': ['Event_EventData_AccessMask'], 'HandleId': ['Event_EventData_HandleId'], 'ObjectServer': ['Event_EventData_ObjectServer'], 'ObjectType': ['Event_EventData_ObjectType'], 'SubjectDomainName': ['Event_EventData_SubjectDomainName'], 'SubjectLogonId': ['Event_EventData_SubjectLogonId'], 'SubjectUserName': ['Event_EventData_SubjectUserName'], 'SubjectUserSid': ['Event_EventData_SubjectUserSid'], 'NewProcessId': ['Event_EventData_NewProcessId'], 'NewProcessName': ['Event_EventData_NewProcessName'], 'ParentProcessName': ['Event_EventData_ParentProcessName'], 'TargetDomainName': ['Event_EventData_TargetDomainName'], 'TargetLogonId': ['Event_EventData_TargetLogonId'], 'TargetUserName': ['Event_EventData_TargetUserName'], 'TargetUserSid': ['Event_EventData_TargetUserSid'], 'TokenElevationType': ['Event_EventData_TokenElevationType'], 'NewValue': ['Event_EventData_NewValue'], 'ObjectValueName': ['Event_EventData_ObjectValueName'], 'OldValue': ['Event_EventData_OldValue'], 'Properties': ['Event_EventData_Properties'], 'PrivilegeList': ['Event_EventData_PrivilegeList'], 'Service': ['Event_EventData_Service'], 'AuthenticationPackageName': ['Event_EventData_AuthenticationPackageName'], 'ImpersonationLevel': ['Event_EventData_ImpersonationLevel'], 'IpPort': ['Event_EventData_IpPort'], 'KeyLength': ['Event_EventData_KeyLength'], 'LmPackageName': ['Event_EventData_LmPackageName'], 'LogonGuid': ['Event_EventData_LogonGuid'], 'LogonProcessName': ['Event_EventData_LogonProcessName'], 'TransmittedServices': ['Event_EventData_TransmittedServices'], 'WorkstationName': ['Event_EventData_WorkstationName'], 'CallerProcessName': ['Event_EventData_CallerProcessName'], 'TargetSid': ['Event_EventData_TargetSid'], 'TaskContentNew': ['Event_EventData_TaskContentNew'], 'AuditPolicyChanges': ['Event_EventData_AuditPolicyChanges'], 'SourceProcessId': ['Event_EventData_SourceProcessId'], 'TargetProcessId': ['Event_EventData_TargetProcessId'], 'TransactionId': ['Event_EventData_TransactionId'], 'TargetInfo': ['Event_EventData_TargetInfo'], 'TargetLogonGuid': ['Event_EventData_TargetLogonGuid'], 'TargetServerName': ['Event_EventData_TargetServerName'], 'Details': ['Event_EventData_Details'], 'PackageFullName': ['Event_EventData_PackageFullName'], 'processPath': ['Event_EventData_processPath'], 'Provider_Name': ['Event_System_Provider_#attributes_Name'], 'Accesses': ['Event_EventData_Accesses'], 'AccountDomain': ['Event_EventData_AccountDomain'], 'AccountExpires': ['Event_EventData_AccountExpires'], 'AddonName': ['Event_EventData_AddonName'], 'AllowedToDelegateTo': ['Event_EventData_AllowedToDelegateTo'], 'Application': ['Event_EventData_Application'], 'AttributeLDAPDisplayName': ['Event_EventData_AttributeLDAPDisplayName'], 'AttributeValue': ['Event_EventData_AttributeValue'], 'AuditSourceName': ['Event_EventData_AuditSourceName'], 'CallingProcessName': ['Event_EventData_CallingProcessName'], 'CallTrace': ['Event_EventData_CallTrace'], 'Company': ['Event_EventData_Company'], 'CreationUtcTime': ['Event_EventData_CreationUtcTime'], 'CurrentDirectory': ['Event_EventData_CurrentDirectory'], 'DestinationAddress': ['Event_EventData_DestinationAddress'], 'DestinationHostname': ['Event_EventData_DestinationHostname'], 'DestinationIp': ['Event_EventData_DestinationIp'], 'DestinationIsIpv6': ['Event_EventData_DestinationIsIpv6'], 'DestinationPort': ['Event_EventData_DestinationPort'], 'DestinationPortName': ['Event_EventData_DestinationPortName'], 'DestPort': ['Event_EventData_DestPort'], 'Detail': ['Event_EventData_Detail'], 'DetectionSource': ['Event_EventData_DetectionSource'], 'DeviceClassName': ['Event_EventData_DeviceClassName'], 'DeviceDescription': ['Event_EventData_DeviceDescription'], 'DisplayName': ['Event_EventData_DisplayName'], 'EngineVersion': ['Event_EventData_EngineVersion'], 'EventSourceId': ['Event_EventData_EventSourceId'], 'ExtraInfo': ['Event_EventData_ExtraInfo'], 'FailureCode': ['Event_EventData_FailureCode'], 'FailureReason': ['Event_EventData_FailureReason'], 'FileVersion': ['Event_EventData_FileVersion'], 'FilterHostProcessID': ['Event_EventData_FilterHostProcessID'], 'GrantedAccess': ['Event_EventData_GrantedAccess'], 'GroupDomain': ['Event_EventData_GroupDomain'], 'GroupName': ['Event_EventData_GroupName'], 'GroupSid': ['Event_EventData_GroupSid'], 'Hash': ['Event_EventData_Hash'], 'Hashes': ['Event_EventData_Hashes'], 'HomeDirectory': ['Event_EventData_HomeDirectory'], 'HomePath': ['Event_EventData_HomePath'], 'HostApplication': ['Event_EventData_HostApplication'], 'HostVersion': ['Event_EventData_HostVersion'], 'Image': ['Event_EventData_Image'], 'ImageLoaded': ['Event_EventData_ImageLoaded'], 'Initiated': ['Event_EventData_Initiated'], 'IntegrityLevel': ['Event_EventData_IntegrityLevel'], 'LayerRTID': ['Event_EventData_LayerRTID'], 'LDAPDisplayName': ['Event_EventData_LDAPDisplayName'], 'LogonHours': ['Event_EventData_LogonHours'], 'NewName': ['Event_EventData_NewName'], 'NewThreadId': ['Event_EventData_NewThreadId'], 'NewUacValue': ['Event_EventData_NewUacValue'], 'NotificationPackageName': ['Event_EventData_NotificationPackageName'], 'ObjectClass': ['Event_EventData_ObjectClass'], 'OldUacValue': ['Event_EventData_OldUacValue'], 'OriginalFileName': ['Event_EventData_OriginalFileName'], 'ParentCommandLine': ['Event_EventData_ParentCommandLine'], 'ParentImage': ['Event_EventData_ParentImage'], 'ParentProcessGuid': ['Event_EventData_ParentProcessGuid'], 'ParentProcessId': ['Event_EventData_ParentProcessId'], 'PasswordLastSet': ['Event_EventData_PasswordLastSet'], 'PerfStateCount': ['Event_EventData_PerfStateCount'], 'PipeName': ['Event_EventData_PipeName'], 'PreviousTime': ['Event_EventData_PreviousTime'], 'PrimaryGroupId': ['Event_EventData_PrimaryGroupId'], 'ProcessCommandLine': ['Event_EventData_ProcessCommandLine'], 'ProcessGuid': ['Event_EventData_ProcessGuid'], 'Product': ['Event_EventData_Product'], 'ProfilePath': ['Event_EventData_ProfilePath'], 'ProtocolHostProcessID': ['Event_EventData_ProtocolHostProcessID'], 'PuaCount': ['Event_EventData_PuaCount'], 'PuaPolicyId': ['Event_EventData_PuaPolicyId'], 'Publisher': ['Event_EventData_Publisher'], 'QueryResults': ['Event_EventData_QueryResults'], 'QueryStatus': ['Event_EventData_QueryStatus'], 'RelativeTargetName': ['Event_EventData_RelativeTargetName'], 'ResourceManager': ['Event_EventData_ResourceManager'], 'SAMAccountName': ['Event_EventData_SamAccountName'], 'ScriptPath': ['Event_EventData_ScriptPath'], 'SecurityPackageName': ['Event_EventData_SecurityPackageName'], 'ServerID': ['Event_EventData_ServerID'], 'ServerURL': ['Event_EventData_ServerURL'], 'ServicePrincipalNames': ['Event_EventData_ServicePrincipalNames'], 'ShareLocalPath': ['Event_EventData_ShareLocalPath'], 'SidHistory': ['Event_EventData_SidHistory'], 'Signature': ['Event_EventData_Signature'], 'SignatureStatus': ['Event_EventData_SignatureStatus'], 'Signed': ['Event_EventData_Signed'], 'SourceAddress': ['Event_EventData_SourceAddress'], 'SourceHostname': ['Event_EventData_SourceHostname'], 'SourceImage': ['Event_EventData_SourceImage'], 'SourceIp': ['Event_EventData_SourceIp'], 'SourceNetworkAddress': ['Event_EventData_SourceNetworkAddress'], 'SourceIsIpv6': ['Event_EventData_SourceIsIpv6'], 'SourcePort': ['Event_EventData_SourcePort'], 'SourcePortName': ['Event_EventData_SourcePortName'], 'SourceProcessGuid': ['Event_EventData_SourceProcessGuid'], 'StartAddress': ['Event_EventData_StartAddress'], 'StartFunction': ['Event_EventData_StartFunction'], 'StartModule': ['Event_EventData_StartModule'], 'SubStatus': ['Event_EventData_SubStatus'], 'TargetFileName': ['Event_EventData_TargetFilename'], 'TargetImage': ['Event_EventData_TargetImage'], 'TargetProcessAddress': ['Event_EventData_TargetProcessAddress'], 'TargetProcessGuid': ['Event_EventData_TargetProcessGuid'], 'TaskContent': ['Event_EventData_TaskContent'], 'TerminalSessionId': ['Event_EventData_TerminalSessionId'], 'ThrottleStateCount': ['Event_EventData_ThrottleStateCount'], 'TicketEncryptionType': ['Event_EventData_TicketEncryptionType'], 'TicketOptions': ['Event_EventData_TicketOptions'], 'UserAccountControl': ['Event_EventData_UserAccountControl'], 'UserParameters': ['Event_EventData_UserParameters'], 'UserPrincipalName': ['Event_EventData_UserPrincipalName'], 'UserWorkstations': ['Event_EventData_UserWorkstations'], 'UtcTime': ['Event_EventData_UtcTime'], 'Workstation': ['Event_EventData_Workstation'], 'ParentIntegrityLevel': ['Event_EventData_ParentIntegrityLevel'], 'ParentUser': ['Event_EventData_ParentUser']}

l = multiprocessing.Lock()




included={}
DB=""
DBconn=""
def search_db(query,DB):
    # Connect to the database
    # conn = sqlite3.connect(DB)
    # cursor = conn.cursor()
    cursor = DBconn.cursor()
    results=[]
    # Define the query
    #query = 'SELECT * FROM employees WHERE name = ?'
    #query="SELECT Original_Event_Log FROM Events WHERE ImageLoaded LIKE '%\\\\Temp\\\\%' ESCAPE '\\'"
    #query="SELECT ImageLoaded FROM AllEvents GROUP BY ImageLoaded"
    #name = 'John Doe'

    # Execute the query
    try:

        cursor.execute(query.replace("Imphash","Hashes").replace("sha1","Hashes").replace("md5","Hashes").replace("sha256","Hashes").replace("*","Original_Event_Log,SystemTime"))
    except Exception as e:
        #print(f"Error {str(e)} with query : \n"+query)
        return results
    # Fetch the results
    results = cursor.fetchall()

    # Print the results
    #for row in results:
    #    print(row)

    # Close the connection

    return results

def optimised_search(DB,output=""):
    global DBconn
    # DB = DB
    # conn = sqlite3.connect(DB)
    searchtime=0
    # Set row factory to dict_factory
    # Read the table into a pandas dataframe
    df = pd.read_sql("""select * from Rules where NOT rule like '%REGEX%'""", DBconn)

    # Convert the dataframe to a datatable
    rules = df.to_dict('records')
    # print(rules.keys())
    # query=rules["rule"][0]
    #tic = time.time()
    Detections = {'DateTime' : [],'title': [], 'description': [], 'Original_Event_Log': [], 'status': [], 'author': [], 'tags': [],
                  'falsepositives': [], 'level': [], 'rule': [], 'id': [], 'filename': []}
    for usecase in rules:
        query = usecase["rule"]
        detected_events=search_db(query, DB)

        if len(detected_events) == 0:
            continue
        for detected in detected_events :
            for field in Detections:
                if field in usecase:
                    # print(usecase)
                    if isinstance(usecase[field], list):

                        Detections[field].append(",".join(usecase[field]))
                    else:
                        Detections[field].append(usecase[field])

                else:
                    if field == "Original_Event_Log":
                        Detections['Original_Event_Log'].append(str(detected[0]))
                    elif field == "DateTime":
                        Detections['DateTime'].append(str(detected[1]))
                    else:
                        Detections[field].append(" ")


    Report = pd.DataFrame(Detections)
    grouped = Report['title'].value_counts()

    cursor = DBconn.cursor()
    writer = pd.ExcelWriter(output+'_'+'Detections.xlsx', engine='xlsxwriter', options={'encoding': 'utf-8'})
    grouped.to_excel(writer, sheet_name='Result Summary')
    Report.to_excel(writer, sheet_name='Detailed Report', index=False)
    writer.book.use_zip64()
    writer.save()
    # Report.to_csv(output+'_'+'Detections.csv', index=False)
    # grouped.to_csv(output+'_'+'grouped.csv')
    #toc = time.time()
    #print('Done in {:.4f} seconds'.format(toc - tic))

def auto_detect(path):
    global input_timezone


    if os.path.isdir(path):
        files=list(libPath(path).rglob("*.[eE][vV][tT][xX]"))

    elif os.path.isfile(path):
        files=glob.glob(path)
    else:
        print("Issue with the path" )
        return

    return files


def Create_DB(db):
    # Connect to SQLite database
    conn = sqlite3.connect(db)
    Events = pd.DataFrame(Alldata)
    c = conn.cursor()
    Create="CREATE TABLE IF NOT EXISTS Events ( "
    for key in Alldata.keys():
        Create+="\'"+key+"\'"+" TEXT COLLATE NOCASE,"
    Create+="ID INTEGER,  PRIMARY KEY(ID AUTOINCREMENT) )"
    #print(Create)
    Index="""CREATE INDEX IF NOT EXISTS "EVENTID_INDEX" ON "Events" ("EventID");"""
    c.execute(Create)
    c.execute(Index)
    c.close()


def insert_into_db_mp(Alldata,db):
    # Connect to SQLite database
    conn = sqlite3.connect(db)
    Events = pd.DataFrame(Alldata)
    Events.to_sql(name='Events', con=conn, if_exists='append', index=False)

    conn.commit()
    conn.close()

Fields={}


def RulesToDB(rules_file,DB):
    with open(rules_file) as f:
        rules = json.load(f)

    # Connect to SQLite database
    conn = sqlite3.connect(DB)
    c = conn.cursor()

    Detections = {'title': [], 'id': [], 'status': [], 'description': [], 'author': [], 'tags': [],
                  'falsepositives': [], 'level': [], 'rule': [], 'filename': []}

    for usecase in rules:
        for field in Detections:
            if field in usecase:
                # print(usecase)
                if isinstance(usecase[field], list):

                    Detections[field].append(",".join(usecase[field]))
                else:
                    Detections[field].append(usecase[field])
            else:
                Detections[field].append("")
    print("Number of rules "+str(len(Detections["rule"])))
    Report = pd.DataFrame(Detections)
    Report.to_sql('Rules', conn, if_exists='append', index=False)

    conn.commit()
    conn.close()


def optimised_parse_mp(file):
    global checkdata
    Alldata = {'Original_Event_Log': [], 'TargetObject': [], 'Channel': [], 'Computer': [], 'Correlation': [],
               'EventID': [], 'EventRecordID': [], 'ProcessID': [], 'ThreadID': [], 'Keywords': [], 'Level': [],
               'Opcode': [], 'Guid': [], 'Name': [], 'UserID': [], 'Task': [], 'SystemTime': [], 'Version': [],
               'Status': [], 'ActivityID': [], 'Context': [], 'ErrorCode': [], 'AppId': [], 'DCName': [], 'Binary': [],
               'Qualifiers': [], 'Security': [], 'Path': [], 'ScriptBlockText': [], 'param1': [], 'param2': [],
               'ContextInfo': [], 'Payload': [], 'UserData': [], 'State': [], 'EventType': [], 'AccountName': [],
               'ProcessName': [], 'LogonType': [], 'TaskName': [], 'Message': [], 'Provider': [], 'updateGuid': [],
               'updateRevisionNumber': [], 'updateTitle': [], 'DeviceName': [], 'DeviceNameLength': [],
               'ClientProcessId': [], 'PossibleCause': [], 'User': [], 'ProviderName': [], 'Query': [], 'value': [],
               'Action': [], 'ApplicationPath': [], 'ModifyingApplication': [], 'Origin': [], 'Protocol': [],
               'RuleName': [], 'SchemaVersion': [], 'ServiceName': [], 'Filename': [], 'PackagePath': [],
               'FileNameBuffer': [], 'UserName': [], 'ShareName': [], 'NewState': [], 'Param3': [],
               'EventSourceName': [], 'NumberOfGroupPolicyObjects': [], 'ProcessingMode': [],
               'ProcessingTimeInMilliseconds': [], 'HostName': [], 'Ipaddress': [], 'NewTime': [], 'OldTime': [],
               'HiveName': [], 'ErrorDescription': [], 'Address': [], 'AddressLength': [], 'QueryName': [], 'TSId': [],
               'UserSid': [], 'DeviceTime': [], 'DeviceVersionMajor': [], 'DeviceVersionMinor': [], 'FinalStatus': [],
               'ImagePath': [], 'ServiceType': [], 'StartType': [], 'ExtensionId': [], 'ExtensionName': [],
               'ShutdownActionType': [], 'ShutdownEventCode': [], 'ShutdownReason': [], 'Group': [],
               'IdleStateCount': [], 'Number': [], 'BootMode': [], 'BuildVersion': [], 'MajorVersion': [],
               'MinorVersion': [], 'QfeVersion': [], 'ServiceVersion': [], 'StartTime': [], 'StopTime': [],
               'TimeSource': [], 'Targetname': [], 'Caption': [], 'ErrorMessage': [], 'RetryMinutes': [],
               'Description': [], 'Type': [], 'OperationType': [], 'CommandLine': [], 'PackageName': [], 'Data': [],
               'LogonId': [], 'ServerName': [], 'ObjectName': [], 'AccessList': [], 'AccessMask': [], 'HandleId': [],
               'ObjectServer': [], 'ObjectType': [], 'SubjectDomainName': [], 'SubjectLogonId': [],
               'SubjectUserName': [], 'SubjectUserSid': [], 'NewProcessId': [], 'NewProcessName': [],
               'ParentProcessName': [], 'TargetDomainName': [], 'TargetLogonId': [], 'TargetUserName': [],
               'TargetUserSid': [], 'TokenElevationType': [], 'NewValue': [], 'ObjectValueName': [], 'OldValue': [],
               'Properties': [], 'PrivilegeList': [], 'Service': [], 'AuthenticationPackageName': [],
               'ImpersonationLevel': [], 'IpPort': [], 'KeyLength': [], 'LmPackageName': [], 'LogonGuid': [],
               'LogonProcessName': [], 'TransmittedServices': [], 'WorkstationName': [], 'CallerProcessName': [],
               'TargetSid': [], 'TaskContentNew': [], 'AuditPolicyChanges': [], 'SourceProcessId': [],
               'TargetProcessId': [], 'TransactionId': [], 'TargetInfo': [], 'TargetLogonGuid': [],
               'TargetServerName': [], 'Details': [], 'PackageFullName': [], 'processPath': [], 'Provider_Name': [],
               'Accesses': [], 'AccountDomain': [], 'AccountExpires': [], 'AddonName': [], 'AllowedToDelegateTo': [],
               'Application': [], 'AttributeLDAPDisplayName': [], 'AttributeValue': [], 'AuditSourceName': [],
               'CallingProcessName': [], 'CallTrace': [], 'Company': [], 'CreationUtcTime': [], 'CurrentDirectory': [],
               'DestinationAddress': [], 'DestinationHostname': [], 'DestinationIp': [], 'DestinationIsIpv6': [],
               'DestinationPort': [], 'DestinationPortName': [], 'DestPort': [], 'Detail': [], 'DetectionSource': [],
               'DeviceClassName': [], 'DeviceDescription': [], 'DisplayName': [], 'EngineVersion': [],
               'EventSourceId': [], 'ExtraInfo': [], 'FailureCode': [], 'FailureReason': [], 'FileVersion': [],
               'FilterHostProcessID': [], 'GrantedAccess': [], 'GroupDomain': [], 'GroupName': [], 'GroupSid': [],
               'Hash': [], 'Hashes': [], 'HomeDirectory': [], 'HomePath': [], 'HostApplication': [], 'HostVersion': [],
               'Image': [], 'ImageLoaded': [], 'Initiated': [], 'IntegrityLevel': [], 'LayerRTID': [],
               'LDAPDisplayName': [], 'LogonHours': [], 'NewName': [], 'NewThreadId': [], 'NewUacValue': [],
               'NotificationPackageName': [], 'ObjectClass': [], 'OldUacValue': [], 'OriginalFileName': [],
               'ParentCommandLine': [], 'ParentImage': [], 'ParentProcessGuid': [], 'ParentProcessId': [],
               'PasswordLastSet': [], 'PerfStateCount': [], 'PipeName': [], 'PreviousTime': [], 'PrimaryGroupId': [],
               'ProcessCommandLine': [], 'ProcessGuid': [], 'Product': [], 'ProfilePath': [],
               'ProtocolHostProcessID': [], 'PuaCount': [], 'PuaPolicyId': [], 'Publisher': [], 'QueryResults': [],
               'QueryStatus': [], 'RelativeTargetName': [], 'ResourceManager': [], 'SAMAccountName': [],
               'ScriptPath': [], 'SecurityPackageName': [], 'ServerID': [], 'ServerURL': [],
               'ServicePrincipalNames': [], 'ShareLocalPath': [], 'SidHistory': [], 'Signature': [],
               'SignatureStatus': [], 'Signed': [], 'SourceAddress': [], 'SourceHostname': [], 'SourceImage': [],
               'SourceIp': [], 'SourceNetworkAddress': [], 'SourceIsIpv6': [], 'SourcePort': [], 'SourcePortName': [],
               'SourceProcessGuid': [], 'StartAddress': [], 'StartFunction': [], 'StartModule': [], 'SubStatus': [],
               'TargetFileName': [], 'TargetImage': [], 'TargetProcessAddress': [], 'TargetProcessGuid': [],
               'TaskContent': [], 'TerminalSessionId': [], 'ThrottleStateCount': [], 'TicketEncryptionType': [],
               'TicketOptions': [], 'UserAccountControl': [], 'UserParameters': [], 'UserPrincipalName': [],
               'UserWorkstations': [], 'UtcTime': [], 'Workstation': [], 'ParentIntegrityLevel': [], 'ParentUser': []}

    mapping = {'Original_Event_Log': ['Original_Event_Log'], 'TargetObject': ['Event_EventData_TargetObject'],
               'Channel': ['Event_System_Channel', 'Event_RenderingInfo_Channel'],
               'Computer': ['Event_System_Computer'], 'Correlation': ['Event_System_Correlation'],
               'EventID': ['Event_System_EventID', 'Event_System_EventID_#text'],
               'EventRecordID': ['Event_System_EventRecordID'],
               'ProcessID': ['Event_EventData_ProcessID', 'Event_EventData_ProcessId',
                             'Event_System_Execution_#attributes_ProcessID',
                             'Event_UserData_Operation_StartedOperational_ProcessID',
                             'Event_UserData_DroppedLeakDiagnosisEventInfo_ProcessId',
                             'Event_UserData_CompatibilityFixEvent_ProcessId',
                             'Event_UserData_Operation_TemporaryEssStarted_Processid', 'Event_EventData_processId'],
               'ThreadID': ['Event_System_Execution_#attributes_ThreadID'], 'Keywords': ['Event_System_Keywords'],
               'Level': ['Event_System_Level', 'Event_RenderingInfo_Level'],
               'Opcode': ['Event_System_Opcode', 'Event_RenderingInfo_Opcode'],
               'Guid': ['Event_System_Provider_#attributes_Guid', 'Event_EventData_Guid'],
               'Name': ['Event_EventData_name', 'Event_System_Provider_#attributes_Name',
                        'Event_EventData_#attributes_Name',
                        'Event_UserData_CertNotificationData_CertificateDetails_EKUs_EKU_#attributes_Name',
                        'Event_EventData_Name',
                        'Event_UserData_CertNotificationData_CertificateDetails_Template_#attributes_Name',
                        'Event_UserData_CertNotificationData_NewCertificateDetails_EKUs_EKU_#attributes_Name',
                        'Event_UserData_CertNotificationData_NewCertificateDetails_Template_#attributes_Name',
                        'Event_UserData_CertNotificationData_OldCertificateDetails_EKUs_EKU_#attributes_Name',
                        'Event_UserData_CertNotificationData_OldCertificateDetails_Template_#attributes_Name',
                        'Event_UserData_MemoryExhaustionInfo_NonPagedPoolInfo_Tag_1_Name',
                        'Event_UserData_MemoryExhaustionInfo_NonPagedPoolInfo_Tag_2_Name',
                        'Event_UserData_MemoryExhaustionInfo_NonPagedPoolInfo_Tag_3_Name',
                        'Event_UserData_MemoryExhaustionInfo_PagedPoolInfo_Tag_1_Name',
                        'Event_UserData_MemoryExhaustionInfo_PagedPoolInfo_Tag_2_Name',
                        'Event_UserData_MemoryExhaustionInfo_PagedPoolInfo_Tag_3_Name',
                        'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_1_Name',
                        'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_2_Name',
                        'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_3_Name',
                        'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_4_Name',
                        'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_5_Name',
                        'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_6_Name',
                        'Event_UserData_EventData_Name'],
               'UserID': ['Event_System_Security_#attributes_UserID', 'Event_EventData_UserId'],
               'Task': ['Event_System_Task', 'Event_EventData_Task', 'Event_RenderingInfo_Task'],
               'SystemTime': ['Event_System_TimeCreated_#attributes_SystemTime'],
               'Version': ['Event_System_Version', 'Event_EventData_Version',
                           'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_1_Version',
                           'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_2_Version',
                           'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_3_Version',
                           'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_4_Version',
                           'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_5_Version',
                           'Event_UserData_MemoryExhaustionInfo_ProcessInfo_Process_6_Version'],
               'Status': ['Event_UserData_ChangingDefaultPrinter_Status', 'Event_EventData_Status',
                          'Event_UserData_EventData_Status'],
               'ActivityID': ['Event_System_Correlation_#attributes_ActivityID', 'Event_EventData_ActivityId'],
               'Context': ['Event_UserData_LoadPluginFailed_Context',
                           'Event_UserData_CertNotificationData_#attributes_Context'],
               'ErrorCode': ['Event_UserData_LoadPluginFailed_ErrorCode', 'Event_EventData_ErrorCode',
                             'Event_UserData_CbsUpdateChangeState_ErrorCode',
                             'Event_UserData_CbsPackageChangeState_ErrorCode', 'Event_ProcessingErrorData_ErrorCode',
                             'Event_EventData_errorCode'], 'AppId': ['Event_EventData_AppId', 'Event_EventData_AppID'],
               'DCName': ['Event_EventData_DCName'], 'Binary': ['Event_EventData_Binary'],
               'Qualifiers': ['Event_System_EventID_#attributes_Qualifiers'], 'Security': ['Event_System_Security'],
               'Path': ['Event_EventData_Path'], 'ScriptBlockText': ['Event_EventData_ScriptBlockText'],
               'param1': ['Event_EventData_param1', 'Event_UserData_EventXML_Param1', 'Event_EventData_Param1'],
               'param2': ['Event_EventData_param2', 'Event_UserData_EventXML_Param2', 'Event_EventData_Param2'],
               'ContextInfo': ['Event_EventData_ContextInfo'], 'Payload': ['Event_EventData_Payload'],
               'UserData': ['Event_EventData_UserData'], 'State': ['Event_EventData_State'],
               'EventType': ['Event_UserData_InvalidCommitLimitExhaustion_EventType'],
               'AccountName': ['Event_UserData_CertNotificationData_#attributes_AccountName',
                               'Event_EventData_AccountName'],
               'ProcessName': ['Event_UserData_CertNotificationData_#attributes_ProcessName',
                               'Event_EventData_ProcessName'], 'LogonType': ['Event_EventData_LogonType'],
               'TaskName': ['Event_EventData_TaskName'],
               'Message': ['Event_EventData_message', 'Event_RenderingInfo_Message', 'Event_EventData_Message'],
               'Provider': ['Event_RenderingInfo_Provider'], 'updateGuid': ['Event_EventData_updateGuid'],
               'updateRevisionNumber': ['Event_EventData_updateRevisionNumber'],
               'updateTitle': ['Event_EventData_updateTitle', 'Event_EventData_UpdateTitle'],
               'DeviceName': ['Event_EventData_DeviceName', 'Event_EventData_Prop_DeviceName'],
               'DeviceNameLength': ['Event_EventData_DeviceNameLength'],
               'ClientProcessId': ['Event_UserData_Operation_ClientFailure_ClientProcessId'],
               'PossibleCause': ['Event_UserData_Operation_ClientFailure_PossibleCause',
                                 'Event_UserData_Operation_TemporaryEssStarted_PossibleCause'],
               'User': ['Event_UserData_Operation_ClientFailure_User',
                        'Event_UserData_Operation_TemporaryEssStarted_User', 'Event_EventData_User',
                        'Event_UserData_EventXML_User'],
               'ProviderName': ['Event_UserData_Operation_StartedOperational_ProviderName'],
               'Query': ['Event_UserData_Operation_TemporaryEssStarted_Query'],
               'value': ['Event_EventData_value', 'Event_EventData_Value'],
               'Action': ['Event_EventData_Action', 'Event_UserData_CertNotificationData_Action'],
               'ApplicationPath': ['Event_EventData_ApplicationPath'],
               'ModifyingApplication': ['Event_EventData_ModifyingApplication'], 'Origin': ['Event_EventData_Origin'],
               'Protocol': ['Event_EventData_Protocol', 'Event_EventData_protocol'],
               'RuleName': ['Event_EventData_RuleName'], 'SchemaVersion': ['Event_EventData_SchemaVersion'],
               'ServiceName': ['Event_EventData_ServiceName'],
               'Filename': ['Event_EventData_Filename', 'Event_UserData_EventData_FileName',
                            'Event_EventData_FileName'], 'PackagePath': ['Event_EventData_PackagePath'],
               'FileNameBuffer': ['Event_EventData_FileNameBuffer'],
               'UserName': ['Event_UserData_EventData_UserName', 'Event_EventData_UserName', 'Event_EventData_userName',
                            'Event_EventData_Username'],
               'ShareName': ['Event_UserData_EventData_ShareName', 'Event_EventData_ShareName'],
               'NewState': ['Event_EventData_NewState'],
               'Param3': ['Event_UserData_EventXML_Param3', 'Event_EventData_param3'],
               'EventSourceName': ['Event_System_Provider_#attributes_EventSourceName'],
               'NumberOfGroupPolicyObjects': ['Event_EventData_NumberOfGroupPolicyObjects'],
               'ProcessingMode': ['Event_EventData_ProcessingMode'],
               'ProcessingTimeInMilliseconds': ['Event_EventData_ProcessingTimeInMilliseconds'],
               'HostName': ['Event_EventData_HostName'],
               'Ipaddress': ['Event_EventData_Ipaddress', 'Event_EventData_IpAddress'],
               'NewTime': ['Event_EventData_NewTime'], 'OldTime': ['Event_EventData_OldTime'],
               'HiveName': ['Event_EventData_HiveName'], 'ErrorDescription': ['Event_EventData_ErrorDescription'],
               'Address': ['Event_EventData_Address', 'Event_UserData_EventXML_Address'],
               'AddressLength': ['Event_EventData_AddressLength'], 'QueryName': ['Event_EventData_QueryName'],
               'TSId': ['Event_EventData_TSId'],
               'UserSid': ['Event_EventData_UserSid', 'Event_UserData_EventXML_UserSid', 'Event_EventData_UserSID'],
               'DeviceTime': ['Event_EventData_DeviceTime'],
               'DeviceVersionMajor': ['Event_EventData_DeviceVersionMajor'],
               'DeviceVersionMinor': ['Event_EventData_DeviceVersionMinor'],
               'FinalStatus': ['Event_EventData_FinalStatus'], 'ImagePath': ['Event_EventData_ImagePath'],
               'ServiceType': ['Event_EventData_ServiceType'], 'StartType': ['Event_EventData_StartType'],
               'ExtensionId': ['Event_EventData_ExtensionId'], 'ExtensionName': ['Event_EventData_ExtensionName'],
               'ShutdownActionType': ['Event_EventData_ShutdownActionType'],
               'ShutdownEventCode': ['Event_EventData_ShutdownEventCode'],
               'ShutdownReason': ['Event_EventData_ShutdownReason'], 'Group': ['Event_EventData_Group'],
               'IdleStateCount': ['Event_EventData_IdleStateCount'],
               'Number': ['Event_EventData_Number', 'Event_EventData_number'], 'BootMode': ['Event_EventData_BootMode'],
               'BuildVersion': ['Event_EventData_BuildVersion'], 'MajorVersion': ['Event_EventData_MajorVersion'],
               'MinorVersion': ['Event_EventData_MinorVersion'], 'QfeVersion': ['Event_EventData_QfeVersion'],
               'ServiceVersion': ['Event_EventData_ServiceVersion'],
               'StartTime': ['Event_EventData_StartTime', 'Event_UserData_CompatibilityFixEvent_StartTime'],
               'StopTime': ['Event_EventData_StopTime'], 'TimeSource': ['Event_EventData_TimeSource'],
               'Targetname': ['Event_EventData_Targetname'], 'Caption': ['Event_EventData_Caption'],
               'ErrorMessage': ['Event_EventData_ErrorMessage'], 'RetryMinutes': ['Event_EventData_RetryMinutes'],
               'Description': ['Event_EventData_Description'], 'Type': ['Event_EventData_Type'],
               'OperationType': ['Event_EventData_OperationType'], 'CommandLine': ['Event_EventData_CommandLine'],
               'PackageName': ['Event_EventData_PackageName'],
               'Data': ['Event_EventData_Data', 'Event_EventData_Data_#text'], 'LogonId': ['Event_EventData_LogonId'],
               'ServerName': ['Event_EventData_ServerName', 'Event_EventData_serverName'],
               'ObjectName': ['Event_EventData_ObjectName'], 'AccessList': ['Event_EventData_AccessList'],
               'AccessMask': ['Event_EventData_AccessMask'], 'HandleId': ['Event_EventData_HandleId'],
               'ObjectServer': ['Event_EventData_ObjectServer'], 'ObjectType': ['Event_EventData_ObjectType'],
               'SubjectDomainName': ['Event_EventData_SubjectDomainName'],
               'SubjectLogonId': ['Event_EventData_SubjectLogonId'],
               'SubjectUserName': ['Event_EventData_SubjectUserName'],
               'SubjectUserSid': ['Event_EventData_SubjectUserSid'], 'NewProcessId': ['Event_EventData_NewProcessId'],
               'NewProcessName': ['Event_EventData_NewProcessName'],
               'ParentProcessName': ['Event_EventData_ParentProcessName'],
               'TargetDomainName': ['Event_EventData_TargetDomainName'],
               'TargetLogonId': ['Event_EventData_TargetLogonId'], 'TargetUserName': ['Event_EventData_TargetUserName'],
               'TargetUserSid': ['Event_EventData_TargetUserSid'],
               'TokenElevationType': ['Event_EventData_TokenElevationType'], 'NewValue': ['Event_EventData_NewValue'],
               'ObjectValueName': ['Event_EventData_ObjectValueName'], 'OldValue': ['Event_EventData_OldValue'],
               'Properties': ['Event_EventData_Properties'], 'PrivilegeList': ['Event_EventData_PrivilegeList'],
               'Service': ['Event_EventData_Service'],
               'AuthenticationPackageName': ['Event_EventData_AuthenticationPackageName'],
               'ImpersonationLevel': ['Event_EventData_ImpersonationLevel'], 'IpPort': ['Event_EventData_IpPort'],
               'KeyLength': ['Event_EventData_KeyLength'], 'LmPackageName': ['Event_EventData_LmPackageName'],
               'LogonGuid': ['Event_EventData_LogonGuid'], 'LogonProcessName': ['Event_EventData_LogonProcessName'],
               'TransmittedServices': ['Event_EventData_TransmittedServices'],
               'WorkstationName': ['Event_EventData_WorkstationName'],
               'CallerProcessName': ['Event_EventData_CallerProcessName'], 'TargetSid': ['Event_EventData_TargetSid'],
               'TaskContentNew': ['Event_EventData_TaskContentNew'],
               'AuditPolicyChanges': ['Event_EventData_AuditPolicyChanges'],
               'SourceProcessId': ['Event_EventData_SourceProcessId'],
               'TargetProcessId': ['Event_EventData_TargetProcessId'],
               'TransactionId': ['Event_EventData_TransactionId'], 'TargetInfo': ['Event_EventData_TargetInfo'],
               'TargetLogonGuid': ['Event_EventData_TargetLogonGuid'],
               'TargetServerName': ['Event_EventData_TargetServerName'], 'Details': ['Event_EventData_Details'],
               'PackageFullName': ['Event_EventData_PackageFullName'], 'processPath': ['Event_EventData_processPath'],
               'Provider_Name': ['Event_System_Provider_#attributes_Name'], 'Accesses': ['Event_EventData_Accesses'],
               'AccountDomain': ['Event_EventData_AccountDomain'], 'AccountExpires': ['Event_EventData_AccountExpires'],
               'AddonName': ['Event_EventData_AddonName'],
               'AllowedToDelegateTo': ['Event_EventData_AllowedToDelegateTo'],
               'Application': ['Event_EventData_Application'],
               'AttributeLDAPDisplayName': ['Event_EventData_AttributeLDAPDisplayName'],
               'AttributeValue': ['Event_EventData_AttributeValue'],
               'AuditSourceName': ['Event_EventData_AuditSourceName'],
               'CallingProcessName': ['Event_EventData_CallingProcessName'], 'CallTrace': ['Event_EventData_CallTrace'],
               'Company': ['Event_EventData_Company'], 'CreationUtcTime': ['Event_EventData_CreationUtcTime'],
               'CurrentDirectory': ['Event_EventData_CurrentDirectory'],
               'DestinationAddress': ['Event_EventData_DestinationAddress'],
               'DestinationHostname': ['Event_EventData_DestinationHostname'],
               'DestinationIp': ['Event_EventData_DestinationIp'],
               'DestinationIsIpv6': ['Event_EventData_DestinationIsIpv6'],
               'DestinationPort': ['Event_EventData_DestinationPort'],
               'DestinationPortName': ['Event_EventData_DestinationPortName'], 'DestPort': ['Event_EventData_DestPort'],
               'Detail': ['Event_EventData_Detail'], 'DetectionSource': ['Event_EventData_DetectionSource'],
               'DeviceClassName': ['Event_EventData_DeviceClassName'],
               'DeviceDescription': ['Event_EventData_DeviceDescription'],
               'DisplayName': ['Event_EventData_DisplayName'], 'EngineVersion': ['Event_EventData_EngineVersion'],
               'EventSourceId': ['Event_EventData_EventSourceId'], 'ExtraInfo': ['Event_EventData_ExtraInfo'],
               'FailureCode': ['Event_EventData_FailureCode'], 'FailureReason': ['Event_EventData_FailureReason'],
               'FileVersion': ['Event_EventData_FileVersion'],
               'FilterHostProcessID': ['Event_EventData_FilterHostProcessID'],
               'GrantedAccess': ['Event_EventData_GrantedAccess'], 'GroupDomain': ['Event_EventData_GroupDomain'],
               'GroupName': ['Event_EventData_GroupName'], 'GroupSid': ['Event_EventData_GroupSid'],
               'Hash': ['Event_EventData_Hash'], 'Hashes': ['Event_EventData_Hashes'],
               'HomeDirectory': ['Event_EventData_HomeDirectory'], 'HomePath': ['Event_EventData_HomePath'],
               'HostApplication': ['Event_EventData_HostApplication'], 'HostVersion': ['Event_EventData_HostVersion'],
               'Image': ['Event_EventData_Image'], 'ImageLoaded': ['Event_EventData_ImageLoaded'],
               'Initiated': ['Event_EventData_Initiated'], 'IntegrityLevel': ['Event_EventData_IntegrityLevel'],
               'LayerRTID': ['Event_EventData_LayerRTID'], 'LDAPDisplayName': ['Event_EventData_LDAPDisplayName'],
               'LogonHours': ['Event_EventData_LogonHours'], 'NewName': ['Event_EventData_NewName'],
               'NewThreadId': ['Event_EventData_NewThreadId'], 'NewUacValue': ['Event_EventData_NewUacValue'],
               'NotificationPackageName': ['Event_EventData_NotificationPackageName'],
               'ObjectClass': ['Event_EventData_ObjectClass'], 'OldUacValue': ['Event_EventData_OldUacValue'],
               'OriginalFileName': ['Event_EventData_OriginalFileName'],
               'ParentCommandLine': ['Event_EventData_ParentCommandLine'],
               'ParentImage': ['Event_EventData_ParentImage'],
               'ParentProcessGuid': ['Event_EventData_ParentProcessGuid'],
               'ParentProcessId': ['Event_EventData_ParentProcessId'],
               'PasswordLastSet': ['Event_EventData_PasswordLastSet'],
               'PerfStateCount': ['Event_EventData_PerfStateCount'], 'PipeName': ['Event_EventData_PipeName'],
               'PreviousTime': ['Event_EventData_PreviousTime'], 'PrimaryGroupId': ['Event_EventData_PrimaryGroupId'],
               'ProcessCommandLine': ['Event_EventData_ProcessCommandLine'],
               'ProcessGuid': ['Event_EventData_ProcessGuid'], 'Product': ['Event_EventData_Product'],
               'ProfilePath': ['Event_EventData_ProfilePath'],
               'ProtocolHostProcessID': ['Event_EventData_ProtocolHostProcessID'],
               'PuaCount': ['Event_EventData_PuaCount'], 'PuaPolicyId': ['Event_EventData_PuaPolicyId'],
               'Publisher': ['Event_EventData_Publisher'], 'QueryResults': ['Event_EventData_QueryResults'],
               'QueryStatus': ['Event_EventData_QueryStatus'],
               'RelativeTargetName': ['Event_EventData_RelativeTargetName'],
               'ResourceManager': ['Event_EventData_ResourceManager'],
               'SAMAccountName': ['Event_EventData_SamAccountName'], 'ScriptPath': ['Event_EventData_ScriptPath'],
               'SecurityPackageName': ['Event_EventData_SecurityPackageName'], 'ServerID': ['Event_EventData_ServerID'],
               'ServerURL': ['Event_EventData_ServerURL'],
               'ServicePrincipalNames': ['Event_EventData_ServicePrincipalNames'],
               'ShareLocalPath': ['Event_EventData_ShareLocalPath'], 'SidHistory': ['Event_EventData_SidHistory'],
               'Signature': ['Event_EventData_Signature'], 'SignatureStatus': ['Event_EventData_SignatureStatus'],
               'Signed': ['Event_EventData_Signed'], 'SourceAddress': ['Event_EventData_SourceAddress'],
               'SourceHostname': ['Event_EventData_SourceHostname'], 'SourceImage': ['Event_EventData_SourceImage'],
               'SourceIp': ['Event_EventData_SourceIp'],
               'SourceNetworkAddress': ['Event_EventData_SourceNetworkAddress'],
               'SourceIsIpv6': ['Event_EventData_SourceIsIpv6'], 'SourcePort': ['Event_EventData_SourcePort'],
               'SourcePortName': ['Event_EventData_SourcePortName'],
               'SourceProcessGuid': ['Event_EventData_SourceProcessGuid'],
               'StartAddress': ['Event_EventData_StartAddress'], 'StartFunction': ['Event_EventData_StartFunction'],
               'StartModule': ['Event_EventData_StartModule'], 'SubStatus': ['Event_EventData_SubStatus'],
               'TargetFileName': ['Event_EventData_TargetFilename'], 'TargetImage': ['Event_EventData_TargetImage'],
               'TargetProcessAddress': ['Event_EventData_TargetProcessAddress'],
               'TargetProcessGuid': ['Event_EventData_TargetProcessGuid'],
               'TaskContent': ['Event_EventData_TaskContent'],
               'TerminalSessionId': ['Event_EventData_TerminalSessionId'],
               'ThrottleStateCount': ['Event_EventData_ThrottleStateCount'],
               'TicketEncryptionType': ['Event_EventData_TicketEncryptionType'],
               'TicketOptions': ['Event_EventData_TicketOptions'],
               'UserAccountControl': ['Event_EventData_UserAccountControl'],
               'UserParameters': ['Event_EventData_UserParameters'],
               'UserPrincipalName': ['Event_EventData_UserPrincipalName'],
               'UserWorkstations': ['Event_EventData_UserWorkstations'], 'UtcTime': ['Event_EventData_UtcTime'],
               'Workstation': ['Event_EventData_Workstation'],
               'ParentIntegrityLevel': ['Event_EventData_ParentIntegrityLevel'],
               'ParentUser': ['Event_EventData_ParentUser']}

    parser = PyEvtxParser(str(file))
    for record in parser.records_json():

        data=flatten(json.loads(record["data"]))
        for key in mapping.keys():
            requiredfield = "None"
            for field in mapping[key]:
                if field in data:
                    requiredfield=field
                    break

            if requiredfield!="None":
                if isinstance(data[requiredfield], list):
                    Alldata[key].append(",".join(data[requiredfield]))
                else:
                    Alldata[key].append(str(data[requiredfield]))
            else:
                if field == "Original_Event_Log":
                    Alldata[key].append(record["data"])
                    #Alldata[key].append(None)
                else:

                    Alldata[key].append(None)

    #print("finished Parsing")
    #print(Alldata)
    l.acquire()
    #print("Inserting data into "+DB)
    insert_into_db_mp(Alldata, DB)
    l.release()
    print("Done Parsing : "+str(file))


def clean(DBName):
        # specify the path to the file to be removed
    file_path = DBName

    # check if the file exists
    if os.path.isfile(file_path):
        # remove the file
        os.remove(file_path)
        print(f"Temp Database has been removed.")
    else:
        print(f"Temp Database does not exist.")


def init(l):
    global lock
    lock = l


def Sigma_Analyze(Path, rules,output, DBName="Events.sqlite"):
    global l,DBconn,DB
    tic_start = time.time()
    DB=DBName
    Create_DB(DB)
    print("Analyzing logs using Sigma with below config : ")
    print(f"Logs Path : {Path}\nSigma Rules file : {rules}\nProfile : {output}")
    pool = multiprocessing.Pool(multiprocessing.cpu_count(), initializer=init, initargs=(l,))
    files = auto_detect(Path)
    results = pool.map(optimised_parse_mp, files)
    RulesToDB(rules, DB)
    DBconn = sqlite3.connect(DB)
    optimised_search(DB,output)
    clean(DBName)
    DBconn.close()
    toc_end = time.time()
    print("Analysis results availble as CSV file with Name "+output+'_'+'Detections.csv')
    print("Analysis results availble as Excel file with statistics as "+output+'_'+'Detections.xlsx')
