function Enable-GuardDuty
{
    <#
    .SYNOPSIS 
        Enables GuardDuty based on specified configuration
    #>

    Write-Log -Message "Enabling GuardDuty" -LogFileName $script:LogFileName -LinePadding 1
    Set-RetryAction({
        Write-Log -Message "Executing: aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES 2>&1" -LogFileName $script:LogFileName -Severity Verbose
        $newGuarduty = aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES 2>&1
        
        $isGuardutyEnabled = $lastexitcode -ne 0
        if ($isGuardutyEnabled)
        {
            Write-Output `n
            Write-Log -Message 'A detector already exists for the current account.' -LogFileName $script:LogFileName
            Write-Log -Message 'List of existing detectors:' -LogFileName $script:LogFileName
            Write-Log -Message "Executing: aws guardduty list-detectors" -LogFileName $script:LogFileName -Severity Verbose
            aws guardduty list-detectors
            
            $script:detectorId = Read-ValidatedHost 'Please enter detector Id'
            Write-Log -Message "Detector Id: $script:detectorId" -LogFileName $script:LogFileName
        }
        else
        {
            $script:detectorId = ($newGuarduty | ConvertFrom-Json).DetectorId
        }
        
        Write-Log -Message "Executing: aws guardduty list-publishing-destinations --detector-id $script:detectorId 2>&1" -LogFileName $script:LogFileName -Severity Verbose
        $script:currentDestinations = aws guardduty list-publishing-destinations --detector-id $script:detectorId 2>&1
        Write-Log $currentDestinations -LogFileName $script:LogFileName -Severity Verbose
    })
}

function Set-GuardDutyDestinationBucket
{
    <#
    .SYNOPSIS 
        Configures GuardDuty to publish logs to destination bucket
    #>

    $currentDestinationsObject = $script:currentDestinations | ConvertFrom-Json
    $currentS3Destinations = $currentDestinationsObject.Destinations | Where-Object DestinationType -eq S3
    if ($null -eq $currentS3Destinations)
    {
        Write-Log -Message "Executing: aws guardduty create-publishing-destination --detector-id $script:detectorId --destination-type S3 --destination-properties DestinationArn=arn:aws:s3:::$script:bucketName,KmsKeyArn=$kmsArn | Out-Null" -LogFileName $script:LogFileName -Severity Verbose
        aws guardduty create-publishing-destination --detector-id $script:detectorId --destination-type S3 --destination-properties DestinationArn=arn:aws:s3:::$script:bucketName,KmsKeyArn=$kmsArn | Out-Null
    }
    else
    {
        Write-Log "Executing: aws guardduty describe-publishing-destination --detector-id $script:detectorId --destination-id $currentS3Destinations.DestinationId | ConvertFrom-Json" -LogFileName $script:LogFileName -Severity Verbose
        $destinationDescriptionObject = aws guardduty describe-publishing-destination --detector-id $script:detectorId --destination-id $currentS3Destinations.DestinationId | ConvertFrom-Json
        $destinationArn = $destinationDescriptionObject.DestinationProperties.DestinationArn

        Write-Log -Message "GuardDuty is already configured for bucket arn '$destinationArn'" -LogFileName $script:LogFileName -LinePadding 2
        $guardDutyBucketConfirmation = Read-ValidatedHost -Prompt "Are you sure that you want to override the existing bucket destination? [y/n]"
        if ($guardDutyBucketConfirmation -eq 'y')
        {
            Write-Log -Message "Executing: aws guardduty update-publishing-destination --detector-id $script:detectorId --destination-id $currentS3Destinations.DestinationId --destination-properties DestinationArn=arn:aws:s3:::$script:bucketName,KmsKeyArn=$kmsArn | Out-Null" -LogFileName $script:LogFileName -Severity Verbose
            aws guardduty update-publishing-destination --detector-id $script:detectorId --destination-id $currentS3Destinations.DestinationId --destination-properties DestinationArn=arn:aws:s3:::$script:bucketName,KmsKeyArn=$kmsArn | Out-Null
        }
        else
        {
            Write-Log -Message 'GuardDuty setup was not completed. You must manually update the GuardDuty destination bucket' -LogFileName $script:LogFileName -Severity Error -LinePadding 2
        }
    } 
}

function New-GuardDutyDataConnector
{
	<#
	.SYNOPSIS
		Main function to setup AWS GuardDuty for use with the Azure Sentinel AWS S3 data connector
	#>

    Write-Log -Message "Starting GuardDuty data connector configuration script" -LogFileName $script:LogFileName -Severity Verbose
    Write-Log -Message "This script creates an Assume Role with minimal permissions to grant Azure Sentinel access to your logs in a designated S3 bucket & SQS of your choice, enable GuardDuty Logs, S3 bucket, SQS Queue, and S3 notifications." -LogFileName $script:LogFileName -LinePadding 2

    # Connect using the AWS CLI
    Get-AwsConfig

    # Create Role Arn
    New-ArnRole

    Write-Log -Message "Executing: aws iam get-role --role-name $roleName" -LogFileName $script:LogFileName -Severity Verbose
    $roleArnObject = aws iam get-role --role-name $roleName
    $script:roleArn = ($roleArnObject | ConvertFrom-Json ).Role.Arn
    Write-Log -Message $script:roleArn -LogFileName $script:LogFileName -Severity LogOnly

    # Create S3 bucket for storing logs
    New-S3Bucket -Name $script:bucketName -AwsRegion $script:AwsRegion

    # Get the Aws account info for the logged in user.
    Write-Log -Message "Executing: (aws sts get-caller-identity | ConvertFrom-Json).Account" -LogFileName $script:LogFileName -Severity Verbose
    $script:callerAccount = (aws sts get-caller-identity | ConvertFrom-Json).Account
    Write-Log -Message "`$script:callerAccount = $script:callerAccount" -LogFileName $script:LogFileName -Severity Verbose

    # Create a new KMS
    Write-Log -Message "Executing: `$script:kmsKeyDescription = New-KMS -Alias $kmsAliasName" -LogFileName $script:LogFileName -Severity Verbose
    $script:kmsKeyDescription = New-KMS -Alias $kmsAliasName
    Write-Log -Message "`$script:kmsKeyDescription = $script:kmsKeyDescription" -LogFileName $script:LogFileName -Severity Verbose

    $script:kmsArn = ($script:kmsKeyDescription | ConvertFrom-Json).KeyMetadata.Arn 
    $script:kmsKeyId = ($script:kmsKeyDescription | ConvertFrom-Json).KeyMetadata.KeyId
    Write-Log -Message "kmsArn: '$script:kmsArn' kmsKeyId: '$script:kmsKeyId'" -LogFileName $script:LogFileName -Severity Verbose

    # Create new SQS Queue
    Write-Log -Message "Executing: New-SQSQueue -Name $sqsName" -LogFileName $script:LogFileName -Severity Verbose
    $script:sqsName = New-SQSQueue -Name $sqsName

    Write-Log -Message "Executing: ((aws sqs get-queue-url --queue-name $sqsName) | ConvertFrom-Json).QueueUrl" -LogFileName $script:LogFileName -Severity Verbose
    $script:sqsUrl = ((aws sqs get-queue-url --queue-name $sqsName) | ConvertFrom-Json).QueueUrl
    
    Write-Log -Message "Executing: ((aws sqs get-queue-attributes --queue-url $sqsUrl --attribute-names QueueArn )| ConvertFrom-Json).Attributes.QueueArn" -LogFileName $script:LogFileName -Severity Verbose
    $script:sqsArn =  ((aws sqs get-queue-attributes --queue-url $sqsUrl --attribute-names QueueArn )| ConvertFrom-Json).Attributes.QueueArn
    Write-Log -Message "sqsUrl: $sqsUrl sqsArn: $sqsArn" -LogFileName $script:LogFileName -Severity Verbose

    $customMessage = "Changes GuardDuty: Kms GenerateDataKey to GuardDuty"
    Write-Log -Message "Executing: Get-GuardDutyAndRoleKmsPolicy -Arn $script:roleArn" -LogFileName $script:LogFileName -Severity Verbose
    $kmsRequiredPolicies = Get-GuardDutyAndRoleKmsPolicy -Arn $script:roleArn

    Write-Log -Message "Executing: Update-KmsPolicy -RequiredPolicy $kmsRequiredPolicies -CustomMessage $customMessage -KeyId $script:kmsKeyId -Role $roleArn" -LogFileName $script:LogFileName -Severity Verbose
    Update-KmsPolicy -RequiredPolicy $kmsRequiredPolicies -CustomMessage $customMessage -KeyId $script:kmsKeyId -Role $script:roleArn
    
    Write-Log -Message "Executing: Update-SQSPolicy -Role $script:roleName -Bucket $script:bucketName -Sqs $script:sqsName" -LogFileName $script:LogFileName -Severity Verbose
    Update-SQSPolicy -Role $script:roleName -Bucket $script:bucketName -Sqs $script:sqsName

    $customMessage = "Changes S3: Get GuardDuty notifications"
    Write-Log -Message "Executing: `$s3RequiredPolicy = Get-RoleAndGuardDutyS3Policy -RoleArn $script:roleArn -BucketName $script:bucketName -KmsArn $kmsArn" -LogFileName $script:LogFileName -Severity Verbose
    $s3RequiredPolicy = Get-RoleAndGuardDutyS3Policy -Role $script:roleArn -Bucket $script:bucketName -Kms $script:kmsArn

    Write-Log -Message "Executing: Update-S3Policy -RequiredPolicy $s3RequiredPolicy -CustomMessage $customMessage -Role $script:roleName -Bucket $script:bucketName" -LogFileName $script:LogFileName -Severity Verbose
    Update-S3Policy -RequiredPolicy $s3RequiredPolicy -CustomMessage $customMessage -Role $roleName -Bucket $script:bucketName

    Write-Log -Message "Executing: Enable-S3EventNotification -DefaultEventNotificationPrefix 'AWSLogs/$script:callerAccount/GuardDuty/'" -LogFileName $script:LogFileName -Severity Verbose
    Enable-S3EventNotification -DefaultEventNotificationPrefix "AWSLogs/$script:callerAccount/GuardDuty/"

    Write-Log -Message "Executing: Enable-GuardDuty" -LogFileName $script:LogFileName -Severity Verbose
    Enable-GuardDuty

    Write-Log -Message "Executing: Set-GuardDutyDestinationBucket" -LogFileName $script:LogFileName -Severity Verbose
    Set-GuardDutyDestinationBucket
    
    # Output information needed to configure Sentinel data connector
    Write-Log -Message "Executing: Write-RequiredConnectorDefinitionInfo" -LogFileName $script:LogFileName -Severity Verbose
    Write-RequiredConnectorDefinitionInfo

}
