function Get-EventNotificationPrefix
{
	<#
	.SYNOPSIS
		Returns the default event notification prefix depending on whether the entire AWS organization is to be configured or just a specific account/
	.PARAMETER OrganizationId
		Specifies the AWS Organization id for which to enable CloudTrail.
	.PARAMETER CreateOrganizationCloudTrail
		Specifies whether to configure CloudTrail for the entire AWS organization. Valid values are N or Y. If Y, an organization id is expected otherwise 
	.PARAMETER Account
		Specifies the specific account for which to configure CloudTrail.
	#>

	[CmdletBinding()]
	param (
		[Parameter()]
		[string]
		$OrganizationId,
		[Parameter()]
		[string]
		$Account,
		[Parameter()]
		[string]
		$CreateOrganizationCloudTrail = "N"
	)
	if ($CreateOrganizationCloudTrail -ne "N")
	{
		return "AWSLogs/$OrganizationId/"
	}
	else
	{
		return  "AWSLogs/$Account/CloudTrail/"
	}	
}

function Set-CloudTrailDataEventConfig
{
	<#
	.SYNOPSIS
		Sets the CloudTrail event configuration
	#>
	$DataEventsConfirmation = Read-ValidatedHost `n'Do you want to enable the CloudTrail data events? [y/n]' -ValidationType Confirm
	if ($DataEventsConfirmation -eq 'y')
	{
		Write-Log -Message "Executing: aws cloudtrail put-event-selectors --trail-name $cloudTrailName --event-selectors '[{'DataResources': [{'Type':'AWS::S3::Object', 'Values': ['arn:aws:s3:::']}]}]' | Out-Null" -LogFileName $LogFileName -Severity Verbose
		aws cloudtrail put-event-selectors --trail-name $cloudTrailName --event-selectors '[{\"DataResources\": [{\"Type\":\"AWS::S3::Object\", \"Values\": [\"arn:aws:s3:::\"]}]}]' | Out-Null
	}
}

function Set-MultiRegionTrailConfig
{
	<#
	.SYNOPSIS
		Configures multi-region trail capability
	#>	
	$regionConfirmation = Read-ValidatedHost 'Do you want the Trail to be multi-region? [y/n]' -ValidationType Confirm
	if ($regionConfirmation -eq 'y')
	{
		Write-Log -Message "Executing: aws cloudtrail update-trail --name $cloudTrailName --is-multi-region-trail | Out-Null" -LogFileName $LogFileName -Severity Verbose
		aws cloudtrail update-trail --name $cloudTrailName --is-multi-region-trail | Out-Null 
	}
	else
	{
		Write-Log -Message "Executing: aws cloudtrail update-trail --name $cloudTrailName --no-is-multi-region-trail | Out-Null" -LogFileName $LogFileName -Severity Verbose
		aws cloudtrail update-trail --name $cloudTrailName --no-is-multi-region-trail | Out-Null 
	}
}

function Set-OrganizationTrailConfig
{
	<#
	.SYNOPSIS
		Configures trail logging for the entire organization
	#>	
	if ($organizationCloudTrailConfirmation -ne 'n')
	{	
		Write-Log -Message "Executing: aws cloudtrail update-trail --name $cloudTrailName --is-organization-trail | Out-Null" -LogFileName $LogFileName -Severity Verbose
		aws cloudtrail update-trail --name $cloudTrailName --is-organization-trail | Out-Null
	}
	else
	{
		Write-Log -Message "Executing: aws cloudtrail update-trail --name $cloudTrailName --no-is-organization-trail | Out-Null" -LogFileName $LogFileName -Severity Verbose
		aws cloudtrail update-trail --name $cloudTrailName --no-is-organization-trail | Out-Null
	}
}

function New-CloudTrailDataConnector
{
	<#
	.SYNOPSIS
		Main function to create the CloudTrail data connector
	#>

	Write-Log -Message "Starting CloudTrail data connector configuration script" -LogFileName $LogFileName -Severity Verbose
	Write-Log -Message "This script creates an Assume Role with minimal permissions to grant Azure Sentinel access to your logs in a designated S3 bucket & SQS of your choice, enable CloudTrail Logs, S3 bucket, SQS Queue, and S3 notifications." -LogFileName $LogFileName -Severity Information -LinePadding 2

	# Connect using the AWS CLI
	Get-AwsConfig

	New-ArnRole

	Write-Log -Message "Executing: aws iam get-role --role-name $roleName" -LogFileName $LogFileName -Severity Verbose
	$roleArnObject = aws iam get-role --role-name $roleName
	$roleArn = ($roleArnObject | ConvertFrom-Json ).Role.Arn
	Write-Log -Message $roleArn -LogFileName $LogFileName -Severity Verbose

	New-S3Bucket -BucketName $BucketName -AwsRegion $AwsRegion

	Write-Log -Message "Executing: (aws sts get-caller-identity | ConvertFrom-Json).Account" -LogFileName $LogFileName -Severity Verbose
	$callerAccount = (aws sts get-caller-identity | ConvertFrom-Json).Account
	Write-Log -Message "$callerAccount" -LogFileName $LogFileName -Severity Verbose

	New-SQSQueue

	Write-Log -Message "Executing: ((aws sqs get-queue-url --queue-name $sqsName) | ConvertFrom-Json).QueueUrl" -LogFileName $LogFileName -Severity Verbose
	$sqsUrl = ((aws sqs get-queue-url --queue-name $sqsName) | ConvertFrom-Json).QueueUrl
	Write-Log -Message $sqsUrl -LogFileName $LogFileName -Severity Verbose
	Write-Log -Message "Executing: (aws sts get-caller-identity | ConvertFrom-Json).Account" -LogFileName $LogFileName -Severity Verbose
	$sqsArn =  ((aws sqs get-queue-attributes --queue-url $sqsUrl --attribute-names QueueArn )| ConvertFrom-Json).Attributes.QueueArn
	Write-Log -Message $sqsArn -LogFileName $LogFileName -Severity Verbose

	$kmsConfirmation = Read-ValidatedHost -Prompt 'Do you want to enable KMS for CloudTrail? [y/n]' -ValidationType Confirm
	if ($kmsConfirmation -eq 'y')
	{
		$kmsKeyDescription = New-KMS -KmsAlias $kmsAliasName
		$kmsArn = ($kmsKeyDescription | ConvertFrom-Json).KeyMetadata.Arn 
		$kmsKeyId = ($kmsKeyDescription | ConvertFrom-Json).KeyMetadata.KeyId
		
		$customMessage = "Changes CloudTrail: Kms GenerateDataKey to CloudTrail"
		$kmsRequiredPolicies = Get-CloudTrailKmsPolicy -RoleArn $roleArn
		Update-KmsPolicy -RequiredPolicy $kmsRequiredPolicies -CustomMessage $customMessage
	}

	Update-SQSPolicy

	$organizationCloudTrailConfirmation = Read-ValidatedHost -Prompt 'Do you want to enable the Trail and CloudTrail S3 Policy for ALL accounts in your organization? [y/n]' -ValidationType Confirm
	if ($organizationCloudTrailConfirmation -eq "y")
	{
		# Retreive the organization information
		Write-Log -Message "Executing: ((aws organizations describe-account --account-id $callerAccount ) | ConvertFrom-Json -ErrorAction SilentlyContinue).Account.Arn.Split('/')[1]" -LogFileName $LogFileName -Severity Verbose
		try
		{
			$organizationId = ((aws organizations describe-account --account-id $callerAccount) | ConvertFrom-Json -ErrorAction SilentlyContinue).Account.Arn.Split('/')[1]
		}
		catch {
			Write-Log -Message "Unable to access AWS organization information. This could be a permissions or policy issue." -LogFileName $LogFileName -Severity Information -Indent 2 
			$organizationCloudTrailConfirmation = "n"
		}

	}

	$s3RequiredPolicy = New-CloudTrailS3Policy
	$customMessage = "Changes S3: Get CloudTrail notifications"
	Update-S3Policy -RequiredPolicy $s3RequiredPolicy -CustomMessage $customMessage

	$eventNotificationPrefix = Get-EventNotificationPrefix -OrganizationId $organizationId -Account $callerAccount -CreateOrganizationCloudTrail $organizationCloudTrailConfirmation
	Enable-S3EventNotification -DefaultEventNotificationPrefix $eventNotificationPrefix

	Write-Log -Message 'CloudTrail definition' -LogFileName $LogFileName -LinePadding 2

	Set-RetryAction({
		
		$script:cloudTrailName = Read-ValidatedHost 'Please enter CloudTrail name'
		Write-Log -Message "Using CloudTrail name: $cloudTrailName" -LogFileName $LogFileName -Indent 2

		Write-Log -Message "Executing: aws cloudtrail get-trail --name $cloudTrailName 2>&1| Out-Null" -LogFileName $LogFileName -Severity Verbose
		aws cloudtrail get-trail --name $cloudTrailName 2>&1| Out-Null
		
		$isCloudTrailNotExist = $lastexitcode -ne 0
		if ($isCloudTrailNotExist)
		{
			if ($kmsConfirmation -eq 'y')
			{
				Write-Log -Message "Executing: aws cloudtrail create-trail --name $cloudTrailName --s3-bucket-name $bucketName --kms-key-id $kmsKeyId 2>&1" -LogFileName $LogFileName -Severity Verbose
				$tempForOutput = aws cloudtrail create-trail --name $cloudTrailName --s3-bucket-name $bucketName --kms-key-id $kmsKeyId 2>&1
				Write-Log -Message $tempForOutput -LogFileName $LogFileName -Severity Verbose
			}
			else
			{
				Write-Log -Message "Executing: aws cloudtrail create-trail --name $cloudTrailName --s3-bucket-name $bucketName 2>&1" -LogFileName $LogFileName -Severity Verbose
				$tempForOutput = aws cloudtrail create-trail --name $cloudTrailName --s3-bucket-name $bucketName 2>&1
				Write-Log -Message $tempForOutput -LogFileName $LogFileName -Severity Verbose
			}
			if($lastexitcode -eq 0)
			{
				Write-Log -Message "${cloudTrailName} trail created successfully" -LogFileName $LogFileName -Indent 2
			}
		}
		else
		{
			$cloudTrailBucketConfirmation = Read-ValidatedHost "Trail '${cloudTrailName}' is already configured. Do you want to override the bucket destination? [y/n]"
			
			if ($cloudTrailBucketConfirmation -eq 'y')
			{
				if ($kmsConfirmation -eq 'y')
				{
					Write-Log -Message "Executing: aws cloudtrail update-trail --name $cloudTrailName --s3-bucket-name $bucketName -kms-key-id $kmsKeyId | Out-Null" -LogFileName $LogFileName -Severity Verbose
					aws cloudtrail update-trail --name $cloudTrailName --s3-bucket-name $bucketName -kms-key-id $kmsKeyId | Out-Null
				}
				else
				{
					Write-Log -Message "Executing: aws cloudtrail update-trail --name $cloudTrailName --s3-bucket-name $bucketName | Out-Null" -LogFileName $LogFileName -Severity Verbose
					aws cloudtrail update-trail --name $cloudTrailName --s3-bucket-name $bucketName | Out-Null
				}
			}
			else
			{
				Write-Log -Message "CloudTrail setup was not completed. You must manually updated the CloudTrail destination bucket" -LogFileName $LogFileName -LinePadding 1
			}
		}
	})

	Set-CloudTrailDataEventConfig
	Set-MultiRegionTrailConfig
	Set-OrganizationTrailConfig

	# Enable CloudTrail logging
	Write-Log -Message "Executing: aws cloudtrail start-logging  --name $cloudTrailName" -LogFileName $LogFileName -Severity Verbose
	aws cloudtrail start-logging  --name $cloudTrailName

	# Output information needed to configure Sentinel data connector
	Write-RequiredConnectorDefinitionInfo
}