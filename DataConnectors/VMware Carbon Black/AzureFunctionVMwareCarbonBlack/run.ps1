<#
    Title:          VMware Carbon Black Cloud data connector
    Language:       PowerShell
    Version:        1.1
    Author:         Microsoft
    Last Modified:  5/25/2022
    Comment:        Release to include option for API Event Logs

    DESCRIPTION
    This Function App calls the VMware Carbon Black Cloud REST API (https://developer.carbonblack.com/reference/carbon-black-cloud/cb-defense/latest/rest-api/) to pull the Carbon Black
    Audit, Notification and Event logs. The response from the CarbonBlack API is received in JSON format. This function will build the signature and authorization header
    needed to post the data to the Log Analytics workspace via the HTTP Data Connector API. The Function App will post each log type to their individual tables in Log Analytics, for example,
    CarbonBlackAuditLogs_CL, CarbonBlackNotifications_CL and CarbonBlackEvents_CL.

    Carbon Black recommends using the Event Forwarder with S3 bucket instead of the the API to retrieve event information. 
#>
# Input bindings are passed in via param block.
[CmdletBinding()]
param (
    $Timer
)

# Get the current universal time in the default string format
$currentUTCtime = (Get-Date).ToUniversalTime()
$logAnalyticsUri = $env:logAnalyticsUri

# The 'IsPastDue' property is 'true' when the current function invocation is later than scheduled.
if ($Timer.IsPastDue) {
    Write-Host "PowerShell timer is running late!"
}

# function to map the event field details retrieved from the S3 Bucket
function New-EventsFieldsMapping {
    [CmdletBinding()]
    param (
        $events
    )
    Write-Host "Starting field mapping for event logs retrieved via S3 Bucket"

    $fieldMappings = @{
        'shortDescription'                 = 'event_description'
        'createTime'                       = 'backend_timestamp'
        'eventId'                          = 'event_id'
        'longDescription'                  = 'event_description'
        'eventTime'                        = 'device_timestamp'
        'securityEventCode'                = 'alert_id'
        'eventType'                        = 'type'
        'incidentId'                       = 'alert_id'
        'deviceDetails_deviceIpAddress'    = 'device_external_ip'
        'deviceDetails_deviceIpV4Address'  = 'device_external_ip'
        'deviceDetails_deviceId'           = 'device_id'
        'deviceDetails_deviceName'         = 'device_name'
        'deviceDetails_deviceType'         = 'device_os'
        'deviceDetails_msmGroupName'       = 'device_group'
        'netFlow_peerFqdn'                 = 'netconn_domain'
        'netFlow_peerIpAddress'            = 'remote_ip'
        'processDetails_name'              = 'process_name'
        'processDetails_commandLine'       = 'process_cmdline'
        'processDetails_fullUserName'      = 'process_username'
        'processDetails_processId'         = 'process_pid'
        'processDetails_parentCommandLine' = 'process_cmdline'
        'processDetails_parentName'        = 'parent_path'
        'processDetails_parentPid'         = 'parent_pid'
        'processDetails_targetCommandLine' = 'target_cmdline'
        
    }

    $fieldMappings.GetEnumerator() | ForEach-Object {
        if (!$events.ContainsKey($_.Name)) {
            $events[$_.Name] = $events[$_.Value]
        }
    }
}

# function to map the event field details retrieved from the API
function New-EventsAPIFieldsMapping {
    [CmdletBinding()]
    param (
        $events
    )
    Write-Host "Starting field mapping for event logs retrieved through API"

    $fieldMappings = @{
        #'severity'                         = 'severity'
        #'category'                         = 'category'
        #'workflow'                         = 'workflow'
        #'notes_present'                    = 'notes_present'
        #'tags'                             = 'tags'
        #'reason'                           = 'reason'
        #'count'                            = 'count'
        #'longDescription'                 = 'event_description'
        'shortDescription'                 = 'reason'
        'createTime'                       = 'create_time'
        'eventId'                          = 'created_by_event_id'
        'eventTime'                        = 'create_time'
        'securityEventCode'                = 'legacy_alert_id'
        'eventType'                        = 'type'
        'incidentId'                       = 'legacy_alert_id'
        'deviceDetails_deviceIpAddress'    = 'device_external_ip'
        'deviceDetails_deviceIpV4Address'  = 'device_external_ip'
        'deviceDetails_deviceId'           = 'device_id'
        'deviceDetails_deviceName'         = 'device_name'
        'deviceDetails_deviceType'         = 'device_os'
        'deviceDetails_msmGroupName'       = 'device_group'
        'netFlow_peerFqdn'                 = 'netconn_domain'
        'netFlow_peerIpAddress'            = 'remote_ip'
        'processDetails_name'              = 'process_name'
        'processDetails_commandLine'       = 'process_cmdline'
        'processDetails_fullUserName'      = 'process_username'
        'processDetails_processId'         = 'threat_cause_actor_process_pid'
        'processDetails_processGuid'       = 'threat_cause_process_guid'
        'processDetails_parentCommandLine' = 'process_cmdline'
        'processDetails_parentName'        = 'parent_path'
        'processDetails_parentPid'         = 'parent_pid'
        'processDetails_targetCommandLine' = 'target_cmdline'
        'deviceDetails_deviceVersion'      = 'device_os_version'
        'deviceInfo_deviceId'              = 'device_id'
        'threatIndicators'                 = 'threat_indicators'
        'orgKey'                           = 'org_key'
        'lastUpdateTime'                   = 'last_update_time'
        'firstEventTime'                   = 'first_event_time'
        'lastEventTime'                    = 'last_event_time'
        'threatId'                         = 'threat_id'
        'deviceDetails_username'           = 'device_username'
        'policyName'                       = 'policy_name'
        'deviceDetails_targetPriorityType' = 'target_value'
        'policyId'                         = 'policy_id'
        'reasonCode'                       = 'reason_code'
        'deviceDetails_deviceLocation'     = 'device_location'
        'threatActivity_dlp'               = 'threat_activity_dlp'
        'threatActivity_phish'             = 'threat_activity_phish'
        'threatActivity_c2'                = 'threat_activity_c2'
        'threatCause_actorSha256'          = 'threat_cause_actor_sha256'
        'threatCause_actorName'            = 'threat_cause_actor_name'
        'threatCause_parentGuid'           = 'threat_cause_parent_guid'
        'threatCause_reputation'           = 'threat_cause_reputation'
        'threatCause_threatCategory'       = 'threat_cause_threat_category'
        'threatCause_vector'               = 'threat_cause_vector'
        'threatCause_causeEventId'         = 'threat_cause_cause_event_id'
        'blocked_threatCategory'           = 'blocked_threat_category'
        'notBlocked_threatCategory'        = 'not_blocked_threat_category'
        'killChain_status'                 = 'kill_chain_status'
        'sensorAction'                     = 'sensor_action'
        'runState'                         = 'run_state'
        'policyApplied'                    = 'policy_applied'   

    }

    # validate the hashtable and add headers
    $fieldMappings = $fieldMappings.GetEnumerator() | Select-Object @{N = 'Name'; E = { $_.Value } }, @{N = 'NewName'; E = { $_.Key } } 
    $fieldMappings = ( $fieldMappings | Where-Object { $_.NewName.length -gt 0 } | Group-Object -Property NewName | ForEach-Object { $_.Group[0] } )

    $props = @('*')
    ForEach ($prop in $fieldMappings) {
        $props += @{N = "$($prop.NewName)"; E = ([Scriptblock]::Create("`$_.$($prop.Name)")) }
    }
    return  ($events | Select-Object -Property $props -ExcludeProperty $fieldMappings.Name )
}

# function maps alert fields before ingesting into Azure Monitor
function New-AlertsFieldsMapping {
    [CmdletBinding()]
    param (
        $alerts
    )
    Write-Host "Starting field mapping for alert logs"

    $fieldMappings = @{
        # "eventDescription": "[AzureSentinel] [Carbon Black has detected a threat against your company.] 
        #   [https://defense-prod05.conferdeploy.net/device/20602996/incident/NE2F3D55-013a6074-000013b0-00000000-1d634654ecf865f-GUWNtEmJQhKmuOTxoRV8hA-6e5ae551-1cbb-45b3-b7a1-1569c0458f6b] 
        #   [Process powershell.exe was detected by the report \"Execution - Powershell Execution With Unrestriced or Bypass Flags Detected\" in watchlist \"Carbon Black Endpoint Visibility\"] 
        #   [Incident id: NE2F3D55-013a6074-000013b0-00000000-1d634654ecf865f-GUWNtEmJQhKmuOTxoRV8hA-6e5ae551-1cbb-45b3-b7a1-1569c0458f6b] [Threat score: 6] [Group: Standard] 
        #   [Email: sanitized@sanitized.com] [Name: Endpoint2] [Type and OS: WINDOWS pscr-sensor] [Severity: 6]\n"
        # "type" =  "type"
        # "notifications" = "notifications"
        # "success" = "success"
        # "message" = "message"
        # "eventType" = "CarbonBlackNotifications"
        # "ResourceId" = "resource_id"
        # "threatInfo_time" =  "create_time"
        # "threatHunterInfo_orgId" = "org_key"
        # "deviceInfo_targetPriorityCode" = "target_priority"
        'threatHunterInfo_summary'                      = 'reason_code'
        'threatHunterInfo_time'                         = 'create_time'
        'threatHunterInfo_indicators'                   = 'threat_indicators'
        'threatHunterInfo_count'                        = 'count'
        'threatHunterInfo_dismissed'                    = 'workflow.state'
        'threatHunterInfo_firstActivityTime'            = 'first_event_time'
        'threatHunterInfo_policyId'                     = 'process_guid'
        'threatHunterInfo_processPath'                  = 'severity'
        'threatHunterInfo_reportName'                   = 'report_name'
        'threatHunterInfo_reportId'                     = 'report_id'
        'threatHunterInfo_reputation'                   = 'threat_cause_reputation'
        'threatHunterInfo_responseAlarmId'              = 'id'
        'threatHunterInfo_responseSeverity'             = 'Severity'
        'threatHunterInfo_runState'                     = 'run_state'
        "threatHunterInfo_sha256"                       = "threat_cause_actor_sha256"
        "threatHunterInfo_status"                       = "status"
        "threatHunterInfo_targetPriority"               = "target_value"
        "threatHunterInfo_threatCause_reputation"       = "threat_cause_reputation"
        "threatHunterInfo_threatCause_actor"            = "threat_cause_actor_sha256"
        "threatHunterInfo_threatCause_actorName"        = "threat_cause_actor_name"
        "threatHunterInfo_threatCause_reason"           = "reason_code"
        "threatHunterInfo_threatCause_threatCategory"   = "threat_cause_threat_category"
        "threatHunterInfo_threatCause_originSourceType" = "threat_cause_vector"
        "threatHunterInfo_threatId"                     = "threat_id"
        "threatHunterInfo_lastUpdatedTime"              = "last_update_time"
        "threatInfo_incidentId"                         = "legacy_alert_id"
        "threatInfo_score"                              = "severity"
        "threatInfo_summary"                            = "reason"
        "threatInfo_indicators"                         = "threat_indicators"
        "threatInfo_threatCause_reputation"             = "threat_cause_reputation"
        "threatInfo_threatCause_actor"                  = "threat_cause_actor_sha256"
        "threatInfo_threatCause_reason"                 = "reason_code"
        "threatInfo_threatCause_threatCategory"         = "threat_cause_threat_catego"
        "threatInfo_threatCause_actorProcessPPid"       = "threat_cause_actor_process_pid"
        "threatInfo_threatCause_causeEventId"           = "threat_cause_cause_event_id"
        "threatInfo_threatCause_originSourceType"       = "threat_cause_vector"
        "url"                                           = "alert_url"
        "eventTime"                                     = "create_time"
        "deviceInfo_deviceId"                           = "device_id"
        "deviceInfo_deviceName"                         = "device_name"
        "deviceInfo_groupName"                          = "policy_name"
        "deviceInfo_email"                              = "device_username"
        "deviceInfo_deviceType"                         = "device_os"
        "deviceInfo_deviceVersion"                      = "device_os_version"
        "deviceInfo_targetPriorityType"                 = "target_value"
        "deviceInfo_uemId"                              = "device_uem_id"
        "deviceInfo_internalIpAddress"                  = "device_internal_ip"
        "deviceInfo_externalIpAddress"                  = "device_external_ip"

    }

    $fieldMappings.GetEnumerator() | ForEach-Object {
        if (!$alerts.ContainsKey($_.Name)) {
            $alerts[$_.Name] = $alerts[$_.Value]
        }
    }
}

# function to expand the files retrieved from S3 bucket
function Expand-GZipFile {
    [CmdletBinding()]
    param (
        $InFile,
        $OutFile
    )
    Write-Host "Processing Expand-GZipFile for: InFile = $InFile, outfile = $OutFile"
    $inputFile = New-Object System.IO.FileStream $InFile, ([IO.FileMode]::Open), ([IO.FileAccess]::Read), ([IO.FileShare]::Read)
    $output = New-Object System.IO.FileStream $OutFile, ([IO.FileMode]::Create), ([IO.FileAccess]::Write), ([IO.FileShare]::None)
    $gZipStream = New-Object System.IO.Compression.GzipStream $inputFile, ([IO.Compression.CompressionMode]::Decompress)

    $buffer = New-Object byte[](1024)
    while ($true) {
        $read = $gZipStream.Read($buffer, 0, 1024)
        if ($read -le 0) { break }
        $output.Write($buffer, 0, $read)
    }

    $gZipStream.Close()
    $output.Close()
    $inputFile.Close()
}

# The function retrieves the Audit, Event, and Notifications Logs from the Carbon Black API and from the S3 bucket 
function Get-CarbonBlackApi {
    [CmdletBinding()]
    param (
        $workspaceId = $env:workspaceId,
        $workspaceSharedKey = $env:workspaceKey,
        $hostName = $env:uri,
        $apiSecretKey = $env:apiKey,
        $logType = $env:CarbonBlackLogTypes,
        $apiId = $env:apiId,
        $SIEMapiKey = $env:SIEMapiKey,
        $SIEMapiId = $env:SIEMapiId,
        $time = $env:timeInterval,
        $OrgKey = $env:CarbonBlackOrgKey,
        $s3BucketName = $env:s3BucketName,
        $EventprefixFolder = $env:EventPrefixFolderName,
        $AlertprefixFolder = $env:AlertPrefixFolderName,
        $AWSAccessKeyId = $env:AWSAccessKeyId,
        $AWSSecretAccessKey = $env:AWSSecretAccessKey,
        $eventsApiSecret = $env:EventsApiKey,
        $eventsApiId = $env:EventsApiId
    )

    # clean up any variables that my not have been set to make sure they work as expected.
    if ($s3BucketName -eq "<S3BucketName>") {
        $s3BucketName = $null
    }
    if ($AWSAccessKeyId -eq "<Folder Name in AWS S3>") {
        $AWSAccessKeyId = $null
    }
    if ($AwsSecretAccessKey -eq "<AWSAccessKeyId>") {
        $AwsSecretAccessKey = $null
    }


    # Static assignments
    $AuditLogTable = "CarbonBlackAuditLogs"
    $EventLogTable = "CarbonBlackEvents"
    $NotificationTable = "CarbonBlackNotifications"
    
    # If there is no value for time interval, set a default of 15 minutes
    if ([string]::IsNullOrWhitespace($time)) {
        $time = 15
    }
    
    # The following times are needed for retreiving Events using the API. 
    # More information about bulk alert export can be found here: https://developer.carbonblack.com/reference/carbon-black-cloud/guides/alert-bulk-export/
    $Global:startTime = [System.DateTime]::UtcNow.AddMinutes( - $($time))
    $Global:now = [System.DateTime]::UtcNow

    # Remove extra slashes or spaces in hostName
    $hostName = $hostName.Trim() -replace "[.*/]$", ""

    if ([string]::IsNullOrEmpty($logAnalyticsUri)) {
        $logAnalyticsUri = "https://" + $workspaceId + ".ods.opinsights.azure.com"
    }

    # Verify the Log Analytics Uri is formatted correctly.
    # URI format example: https://" + <workspaceId> + ".ods.opinsights.azure.com
    if ($logAnalyticsUri -notmatch 'https:\/\/([\w\-]+)\.ods\.opinsights\.azure.([a-zA-Z\.]+)$') {
        throw "VMware Carbon Black data connector: Invalid Log Analytics Uri."
    }

    # Create authorization headers based on the API Id and API Secret.
    function Get-ApiAuthHeaders {
        [CmdletBinding()]
        param (
            [string] $Secret,
            [string] $Id
        )

        return @{"X-Auth-Token" = "$($Secret)/$($Id)" }

    }   

    $logType =  @("event", "audit", "alertSIEMAPI")

    # Converting logType to array
    if ([string]::IsNullOrWhiteSpace($logType)) {
        if ($SIEMapiKey -eq '<Optional>' -or $SIEMapiId -eq '<Optional>' -or [string]::IsNullOrWhitespace($SIEMapiKey) -or [string]::IsNullOrWhitespace($SIEMapiId)) {
            $LogTypeArr = @("event", "audit")
        }
        else {
            $LogTypeArr = @("event", "audit", "alertSIEMAPI")
        }
    }
    else {
        if ($logType -like "``[*``]") {
            $logType = $logType.Substring(1, $logType.Length - 2)
        }
        $logType = $logType -replace """", ""
        $LogTypeArr = $logType -split ','
    }
    
    if (-not([string]::IsNullOrWhiteSpace($apiId)) -and -not([string]::IsNullOrWhiteSpace($apiSecretKey)) -and -not([string]::IsNullOrWhiteSpace($hostName))) {
        if ($LogTypeArr -contains "audit") {
            
            $authHeaders = Get-ApiAuthHeaders -Secret $apiSecretKey -Id $apiId
            $auditLogsResult = Invoke-RestMethod -Headers $authHeaders -Uri ([System.Uri]::new("$($hostName)/integrationServices/v3/auditlogs"))

            if ($auditLogsResult.success -eq $true) {
                $AuditLogsJSON = $auditLogsResult.notifications | ConvertTo-Json -Depth 5

                if (-not([string]::IsNullOrWhiteSpace($AuditLogsJSON))) {
                    $responseObj = (ConvertFrom-Json $AuditLogsJSON)
                    $status = Send-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceSharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($AuditLogsJSON)) -logType $AuditLogTable;
                    Write-Host("$($responseObj.count) new Carbon Black audit events at $([DateTime]::UtcNow) and sent to Microsoft Sentinel. Status code:$($status)")
                }
                else {
                    Write-Host "No new Carbon Black Audit Events at $([DateTime]::UtcNow)"
                }
            }
            else {
                Write-Host "Audit Logs Result API status failed, Please check."
            }
        }
        else {
            Write-Warning "'Audit' was not selected as a LogType, audit logs will not be ingested into the workspace."
        }
    }
    else {
        Write-Warning "API credentials were not defined, audit logs will not be ingested to workspace."
    }

    # Is the S3 bucket information set?
    if (-not([string]::IsNullOrWhiteSpace($s3BucketName)) -and -not([string]::IsNullOrWhiteSpace($AWSAccessKeyId)) -and -not([string]::IsNullOrWhiteSpace($AWSSecretAccessKey)) -and -not([string]::IsNullOrWhiteSpace($OrgKey))) {
        if ($LogTypeArr -contains "event") {
            Get-BucketDetails -s3BucketName $s3BucketName -prefixFolder $EventprefixFolder -tableName $EventLogTable -logtype "event"
        }
        else {
            Write-Warning "'Event' was not selected as a LogType, event logs will not be ingested to the workspace."
        }
    } # If S3 bucket details are not set, is there event data API information?
    elseif (-not([string]::IsNullOrWhiteSpace($eventsApiSecret) -and -not([string]::IsNullOrWhiteSpace($eventsApiId)))) {
       
        Write-Information "S3 Bucket credentials not defined and API credentials defined, event logs will be ingested via API."
        
        # Carbon Black requires the queried time range to be be specially formatted.  
        # Format the search query to get the events for the specified time range. 
        $reqText = '{"criteria": {"create_time": {"start": "' + $Global:startTime.ToString("yyyy-MM-ddTHH:mm:ss.fffK") + '", "end": "' + $Global:now.ToString("yyyy-MM-ddTHH:mm:ss.fffK") + '"}},"rows": 10000, "start": 0, "sort": [ {"field": "create_time", "order": "ASC"}]}'
        # $authHeaders = Get-ApiAuthHeaders -Secret $eventsApiSecret -Id $eventsApiId
        # Get event data from API
        $eventLogsResult = Invoke-RestMethod -Headers (Get-ApiAuthHeaders -Secret $eventsApiSecret -Id $eventsApiId) -Uri ([System.Uri]::new("$($hostName)/appservices/v6/orgs/$($OrgKey)/alerts/_search")) -Body ([System.Text.Encoding]::UTF8.GetBytes($reqText)) -Verbose -Method 'POST' -ContentType "application/json"
        
        if ( $eventLogsResult.results -ne "") {
            if ($eventLogsResult.num_available -ge 1) {
                # Debugging output format.
                $mappedObjectsJson = New-EventsAPIFieldsMapping $eventLogsResult.results | ConvertTo-Json -Depth 6
                
                $status = Send-LogAnalyticsData -CustomerId $workspaceId -SharedKey $workspaceSharedKey -Body ([System.Text.Encoding]::UTF8.GetBytes($mappedObjectsJson)) -logType $EventLogTable;
                if ($status -eq 200) {
                    Write-Host "$($eventLogsResult.num_found) new Carbon Black events at $([DateTime]::UtcNow), sent to Sentinel workspace. "
                }
                else {
                    Write-Warning "An error occurred sending $($eventLogsResult.num_found) Carbon Black events to Sentinel workspace. Response:$($status) "
                }
            }
            else {
                Write-Host "No new Carbon Black events at $([DateTime]::UtcNow)"
            }
        }
    }   
    else {
        
        Write-Information "Neither S3 Bucket credentials nor API credentials provided, events will not be ingested."

    }

    if ($LogTypeArr -contains "alertSIEMAPI" -or $LogTypeArr -contains "alertAWSS3") {
        if ($SIEMapiKey -eq '<Optional>' -or $SIEMapiId -eq '<Optional>' -or [string]::IsNullOrWhitespace($SIEMapiKey) -or [string]::IsNullOrWhitespace($SIEMapiId)) {
            if (-not([string]::IsNullOrWhiteSpace($s3BucketName)) -and -not([string]::IsNullOrWhiteSpace($AWSAccessKeyId)) -and -not([string]::IsNullOrWhiteSpace($AWSSecretAccessKey)) -and -not([string]::IsNullOrWhiteSpace($OrgKey))) {
                $alerts = Get-BucketDetails -s3BucketName $s3BucketName -prefixFolder $AlertprefixFolder -tableName $NotificationTable -logtype "alert"
                Write-Host "$($alerts.count) new Carbon Black alerts found in S3 bucket at $([DateTime]::UtcNow) and sent to Sentinel workspace."
            }
        }
        elseif (-not([string]::IsNullOrWhiteSpace($SIEMapiKey)) -and -not([string]::IsNullOrWhiteSpace($SIEMapiId))) {

            $authHeaders = Get-ApiAuthHeaders -Secret $SIEMapiKey -Id $SIEMapiId
            $notifications = Invoke-RestMethod -Headers $authHeaders -Uri ([System.Uri]::new("$($hostName)/integrationServices/v3/notification"))
            if ($notifications.success -eq $true) {
                $NotifLogJson = $notifications.notifications | ConvertTo-Json -Depth 5
                if (-not([string]::IsNullOrWhiteSpace($NotifLogJson))) {
                    $responseObj = ConvertFrom-Json $NotifLogJson
                    $status = Send-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceSharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($NotifLogJson)) -logType $NotificationTable;
                    Write-Host("$($responseObj.count) new Carbon Black notifications at $([DateTime]::UtcNow), sent to Sentinel workspace. Status code:$($status)")
                }
                else {
                    Write-Host "No new Carbon Black Notifications as of $([DateTime]::UtcNow)"
                }
            }
            else {
                Write-Host "Notifications API status failed , Please check."
            }
        }
        else {
            Write-Warning "No SIEM API ID and/or Key or S3 Bucket value was defined, therefore alert logs will not to ingested to workspace."
        }
    }
    else {
        Write-Warning "'Alert' was not selected as a LogType, therefore alert logs will not be ingested to the workspace."
    } 
}

# Create an authorization signature
function Build-Signature {
    [CmdletBinding()]
    param (
        [string]$CustomerId, 
        [string]$SharedKey, 
        $Date, 
        [string]$ContentLength, 
        [string]$Method, 
        [string]$ContentType, 
        [string]$Resource
    )

    $xHeaders = "x-ms-date:" + $date;
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource;
    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash);
    $keyBytes = [Convert]::FromBase64String($sharedKey);
    $sha256 = New-Object System.Security.Cryptography.HMACSHA256;
    $sha256.Key = $keyBytes;
    $calculatedHash = $sha256.ComputeHash($bytesToHash);
    $encodedHash = [Convert]::ToBase64String($calculatedHash);
    $authorization = 'SharedKey {0}:{1}' -f $customerId, $encodedHash;
    return $authorization;
}

# Creates and posts data to Azure Monitor
function Send-LogAnalyticsData {
    [CmdletBinding()]
    param (
        $CustomerId, 
        $SharedKey, 
        $Body, 
        $LogType
    )
    
    $TimeStampField = "eventTime"
    $method = "POST";
    $contentType = "application/json";
    $resource = "/api/logs";
    $rfc1123date = [DateTime]::UtcNow.ToString("r");
    $contentLength = $body.Length;
    $signature = Build-Signature -CustomerId $customerId -SharedKey $sharedKey -Date $rfc1123date -ContentLength $contentLength -Method $method -ContentType $contentType -Resource $resource;
    $logAnalyticsUri = $logAnalyticsUri + $resource + "?api-version=2016-04-01"
    $headers = @{
        "Authorization"        = $signature;
        "Log-Type"             = $logType;
        "x-ms-date"            = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    };
    $response = Invoke-WebRequest -Body $body -Uri $logAnalyticsUri -Method $method -ContentType $contentType -Headers $headers -UseBasicParsing
    return $response.StatusCode
}

# Get data from the AWS S3 Bucket
function Get-BucketDetails {
    [CmdletBinding()]
    param (
        $S3BucketName,
        $PrefixFolder,
        $TableName,
        $Logtype
    )

    if ($null -ne $S3BucketName) {
        Set-AWSCredentials -AccessKey $AWSAccessKeyId -SecretKey $AWSSecretAccessKey

        while ($Global:startTime -le $Global:now) {
            $keyPrefix = "$prefixFolder/org_key=$OrgKey/year=$($Global:startTime.Year)/month=$($Global:startTime.Month)/day=$($Global:startTime.Day)/hour=$($Global:startTime.Hour)/minute=$($Global:startTime.Minute)"
            Get-S3Object -BucketName $S3BucketName -keyPrefix $keyPrefix | Read-S3Object -Folder "C:\tmp"
            Write-Host "Files under $keyPrefix are downloaded."

            if (Test-Path -Path "/tmp/$keyPrefix") {
                Get-ChildItem -Path "/tmp" -Recurse -Include *.gz |
                    ForEach-Object {
                        $fileName = $_.FullName
                        $inFile = $_.FullName
                        $outFile = $_.FullName -replace ($_.Extension, '')
                        Expand-GZipFile $inFile.Trim() $outfile.Trim()
                        $null = Remove-Item -Path $inFile -Force -Recurse -ErrorAction Ignore
                        $fileName = $fileName -replace ($_.Extension, '')
                        $fileName = $fileName.Trim()
                        $AllEvents = [System.Collections.ArrayList]::new()

                        foreach ($logEvent in [System.IO.File]::ReadLines($fileName)) {
                            $logs = $logEvent | ConvertFrom-Json
                            $hash = @{}
                            $logs.PSObject.properties | ForEach-Object { $hash[$_.Name] = $_.Value }
                            $logevents = $hash

                            if ($logtype -eq "event") {
                                New-EventsFieldsMapping -events $logevents
                            }
                            if ($logtype -eq "alert") {
                                New-AlertsFieldsMapping -alerts $logevents
                            }
                            $AllEvents.Add($logevents)
                        }

                        $EventLogsJSON = $AllEvents | ConvertTo-Json -Depth 5

                        if (-not([string]::IsNullOrWhiteSpace($EventLogsJSON))) {
                            $responseObj = (ConvertFrom-Json $EventLogsJSON)
                            try {
                                $status = Send-LogAnalyticsData -customerId $workspaceId -sharedKey $workspaceSharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($EventLogsJSON)) -logType $tableName;
                                Write-Host "Pushed events to $($tableName)"
                            }
                            catch {
                                Write-Host $_
                            }
                            Write-Host("$($responseObj.count) new Carbon Black Events as of $([DateTime]::UtcNow). Pushed data to Microsoft Sentinel status code:$($status)")
                        }
                        $null = Remove-Variable -Name AllEvents
                    }

                Remove-Item -LiteralPath "/tmp/$keyPrefix" -Force -Recurse
            }

            $Global:startTime = $Global:startTime.AddMinutes(1)
        }
    }
}

# Execute the function to pull Carbon Black data and post to the Log Analytics Workspace
Get-CarbonBlackAPI

# Write an information log with the current time.
Write-Host "PowerShell timer trigger function ran at: $currentUTCtime"