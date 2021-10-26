function Enable-GuardDuty
{
    <#
    .SYNOPSIS 
        Enables GuardDuty based on specified configuration
    #>

    Write-Log -Message "Enabling GuardDuty" -LogFileName $LogFileName -LinePadding 1
    Set-RetryAction({
        Write-Log -Message "Executing: aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES 2>&1" -LogFileName $LogFileName -Severity Verbose
        $newGuarduty = aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES 2>&1
        
        $isGuardutyEnabled = $lastexitcode -ne 0
        if ($isGuardutyEnabled)
        {
            Write-Output `n
            Write-Log -Message 'A detector already exists for the current account.' -LogFileName $LogFileName
            Write-Log -Message 'List of existing detectors:' -LogFileName $LogFileName
            Write-Log -Message "Executing: aws guardduty list-detectors" -LogFileName $LogFileName -Severity Verbose
            aws guardduty list-detectors
            
            $script:detectorId = Read-ValidatedHost 'Please enter detector Id'
            Write-Log -Message "Detector Id: $detectorId" -LogFileName $LogFileName
        }
        else
        {
            $script:detectorId = ($newGuarduty | ConvertFrom-Json).DetectorId
        }
        
        Write-Log -Message "Executing: aws guardduty list-publishing-destinations --detector-id $detectorId 2>&1" -LogFileName $LogFileName -Severity Verbose
        $script:currentDestinations = aws guardduty list-publishing-destinations --detector-id $detectorId 2>&1
        Write-Log $currentDestinations -LogFileName $LogFileName -Severity Verbose
    })
}

function Set-GuardDutyPublishDestinationBucket
{
    <#
    .SYNOPSIS 
        Configures GuardDuty to publish logs to destination bucket
    #>

    $currentDestinationsObject = $currentDestinations | ConvertFrom-Json
    $currentS3Destinations = $currentDestinationsObject.Destinations | Where-Object DestinationType -eq S3
    if ($null -eq $currentS3Destinations)
    {
        Write-Log -Message "Executing: aws guardduty create-publishing-destination --detector-id $detectorId --destination-type S3 --destination-properties DestinationArn=arn:aws:s3:::$bucketName,KmsKeyArn=$kmsArn | Out-Null" -LogFileName $LogFileName -Severity Verbose
        aws guardduty create-publishing-destination --detector-id $detectorId --destination-type S3 --destination-properties DestinationArn=arn:aws:s3:::$bucketName,KmsKeyArn=$kmsArn | Out-Null
    }
    else
    {
        Write-Log "Executing: aws guardduty describe-publishing-destination --detector-id $detectorId --destination-id $currentS3Destinations.DestinationId | ConvertFrom-Json" -LogFileName $LogFileName -Severity Verbose
        $destinationDescriptionObject = aws guardduty describe-publishing-destination --detector-id $detectorId --destination-id $currentS3Destinations.DestinationId | ConvertFrom-Json
        $destinationArn = $destinationDescriptionObject.DestinationProperties.DestinationArn

        Write-Log -Message "GuardDuty is already configured for bucket arn '$destinationArn'" -LogFileName $LogFileName -LinePadding 2
        $guardDutyBucketConfirmation = Read-ValidatedHost -Prompt "Are you sure that you want to override the existing bucket destination? [y/n]"
        if ($guardDutyBucketConfirmation -eq 'y')
        {
            Write-Log -Message "Executing: aws guardduty update-publishing-destination --detector-id $detectorId --destination-id $currentS3Destinations.DestinationId --destination-properties DestinationArn=arn:aws:s3:::$bucketName,KmsKeyArn=$kmsArn | Out-Null" -LogFileName $LogFileName -Severity Verbose
            aws guardduty update-publishing-destination --detector-id $detectorId --destination-id $currentS3Destinations.DestinationId --destination-properties DestinationArn=arn:aws:s3:::$bucketName,KmsKeyArn=$kmsArn | Out-Null
        }
        else
        {
            Write-Log -Message 'GuardDuty setup was not completed. You must manually update the GuardDuty destination bucket' -LogFileName $LogFileName -Severity Error -LinePadding 2
        }
    } 
}

function New-GuardDutyDataConnector
{
	<#
	.SYNOPSIS
		Main function to create the GuardDuty data connector
	#>

    Write-Log -Message "Starting GuardDuty data connector configuration script" -LogFileName $LogFileName -Severity Verbose
    Write-Log -Message "This script creates an Assume Role with minimal permissions to grant Azure Sentinel access to your logs in a designated S3 bucket & SQS of your choice, enable GuardDuty Logs, S3 bucket, SQS Queue, and S3 notifications." -LogFileName $LogFileName -LinePadding 2

    # Connect using the AWS CLI
    Get-AwsConfig

    New-ArnRole
    Write-Log -Message "Executing: aws iam get-role --role-name $roleName" -LogFileName $LogFileName -Severity Verbose
    $roleArnObject = aws iam get-role --role-name $roleName
    $roleArn = ($roleArnObject | ConvertFrom-Json ).Role.Arn
    Write-Log -Message $roleArn -LogFileName $LogFileName -Severity Verbose

    # Create S3 bucket for storing logs
    New-S3Bucket -BucketName $BucketName -AwsRegion $AwsRegion

    Write-Log -Message "Executing: (aws sts get-caller-identity | ConvertFrom-Json).Account" -LogFileName $LogFileName -Severity Verbose
    $callerAccount = (aws sts get-caller-identity | ConvertFrom-Json).Account
    Write-Log -Message $callerAccount -LogFileName $LogFileName -Severity Verbose

    New-KMS
    $kmsArn = ($kmsKeyDescription | ConvertFrom-Json).KeyMetadata.Arn 
    $kmsKeyId = ($kmsKeyDescription | ConvertFrom-Json).KeyMetadata.KeyId
    Write-Log -Message "kmsArn: $kmsArn kmsKeyId: $kmsKeyId" -LogFileName $LogFileName -Severity Verbose

    New-SQSQueue
    Write-Log -Message "Executing: ((aws sqs get-queue-url --queue-name $sqsName) | ConvertFrom-Json).QueueUrl" -LogFileName $LogFileName -Severity Verbose
    $sqsUrl = ((aws sqs get-queue-url --queue-name $sqsName) | ConvertFrom-Json).QueueUrl
    Write-Log -Message "Executing: ((aws sqs get-queue-attributes --queue-url $sqsUrl --attribute-names QueueArn )| ConvertFrom-Json).Attributes.QueueArn" -LogFileName $LogFileName -Severity Verbose
    $sqsArn =  ((aws sqs get-queue-attributes --queue-url $sqsUrl --attribute-names QueueArn )| ConvertFrom-Json).Attributes.QueueArn
    Write-Log -Message "sqsUrl: $sqsUrl sqsArn: $sqsArn" -LogFileName $LogFileName -Severity Verbose

    $customMessage = "Changes GuardDuty: Kms GenerateDataKey to GuardDuty"
    $kmsRequiredPolicies = Get-GuardDutyAndRoleKmsPolicy -RoleArn $roleArn
    Update-KmsPolicy -RequiredPolicy $kmsRequiredPolicies -CustomMessage $customMessage

    Update-SQSPolicy

    $customMessage = "Changes S3: Get GuardDuty notifications"
    $s3RequiredPolicy = Get-RoleAndGuardDutyS3Policy -RoleArn $roleArn -BucketName $bucketName -KmsArn $kmsArn
    Update-S3Policy -RequiredPolicy $s3RequiredPolicy -CustomMessage $customMessage

    Enable-S3EventNotification -DefaultEventNotificationPrefix "AWSLogs/${callerAccount}/GuardDuty/"

    Enable-GuardDuty
    Set-GuardDutyPublishDestinationBucket
    
    # Output information needed to configure Sentinel data connector
    Write-RequiredConnectorDefinitionInfo
}