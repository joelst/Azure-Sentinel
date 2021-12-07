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
	.PARAMETER
		Specifies whether to enable multi-region cloud. If not set, the user will be prompted to answer. 
	#>
[CmdletBinding()]
param (
	[Parameter()]
	[string]
	$DataEventsConfirmation = ""
)

	
	
}

function Set-MultiRegionTrailConfig
{
	<#
	.SYNOPSIS
		Configures multi-region trail capability
	#>



}

function Set-OrganizationTrailConfig
{
	<#
	.SYNOPSIS
		Configures trail logging for the entire organization
	#>	
	if ($organizationCloudTrailConfirmation -ne 'n')
	{	
		Write-Log -Message "Executing: aws cloudtrail update-trail --name $script:cloudTrailName --is-organization-trail | Out-Null" -LogFileName $script:LogFileName -Severity Verbose
		aws cloudtrail update-trail --name $script:cloudTrailName --is-organization-trail | Out-Null
	}
	else
	{
		Write-Log -Message "Executing: aws cloudtrail update-trail --name $script:cloudTrailName --no-is-organization-trail | Out-Null" -LogFileName $script:LogFileName -Severity Verbose
		aws cloudtrail update-trail --name $script:cloudTrailName --no-is-organization-trail | Out-Null
	}
}

function New-CloudTrailDataConnector
{
	<#
	.SYNOPSIS
		Main function to setup AWS CloudTrail for use with the Azure Sentinel AWS S3 data connector
	#>
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]
		$ArnName,
		[Parameter()]
		[string]
		$AwsRegion

	)

	Write-Log -Message "Starting CloudTrail data connector configuration script" -LogFileName $script:LogFileName -Severity Verbose
	Write-Log -Message "This script creates an Assume Role with minimal permissions to grant Azure Sentinel access to your logs in a designated S3 bucket & SQS of your choice, enable CloudTrail Logs, S3 bucket, SQS Queue, and S3 notifications." -LogFileName $script:LogFileName -Severity Information -LinePadding 2

	# Connect using the AWS CLI
	Get-AwsConfig

	Write-Log -Message "Executing: New-ArnRole -Name $ArnName -WorkspaceId $workspaceId" -LogFileName $script:LogFileName -Severity Verbose
	New-ArnRole -Name $ArnName -WorkspaceId $workspaceId

	Write-Log -Message "Executing: aws iam get-role --role-name $roleName" -LogFileName $script:LogFileName -Severity Verbose
	$roleArnObject = aws iam get-role --role-name $roleName
	$roleArn = ($roleArnObject | ConvertFrom-Json ).Role.Arn
	Write-Log -Message $roleArn -LogFileName $script:LogFileName -Severity Verbose

	Write-Log -Message "Executing: New-S3Bucket -Name $script:BucketName -AwsRegion $script:AwsRegion" -LogFileName $script:LogFileName -Severity Verbose
	New-S3Bucket -Name $script:BucketName -AwsRegion $script:AwsRegion

	Write-Log -Message "Executing: (aws sts get-caller-identity | ConvertFrom-Json).Account" -LogFileName $script:LogFileName -Severity Verbose
	$script:callerAccount = (aws sts get-caller-identity | ConvertFrom-Json).Account
	Write-Log -Message "`$script:calleraccount = $script:callerAccount" -LogFileName $script:LogFileName -Severity Verbose

	Write-Log -Message "Executing: New-SQSQueue -Name $sqsName" -LogFileName $script:LogFileName -Severity Verbose
	$script:sqsName = New-SQSQueue -Name $sqsName

	Write-Log -Message "Executing: ((aws sqs get-queue-url --queue-name $sqsName) | ConvertFrom-Json).QueueUrl" -LogFileName $script:LogFileName -Severity Verbose
	$script:sqsUrl = ((aws sqs get-queue-url --queue-name $sqsName) | ConvertFrom-Json).QueueUrl
	Write-Log -Message $sqsUrl -LogFileName $script:LogFileName -Severity Verbose
	
	Write-Log -Message "Executing: ((aws sqs get-queue-attributes --queue-url $sqsUrl --attribute-names QueueArn )| ConvertFrom-Json).Attributes.QueueArn" -LogFileName $script:LogFileName -Severity Verbose
	$script:sqsArn =  ((aws sqs get-queue-attributes --queue-url $sqsUrl --attribute-names QueueArn )| ConvertFrom-Json).Attributes.QueueArn
	Write-Log -Message "`$script:sqsArn = $script:sqsArn" -LogFileName $script:LogFileName -Severity Verbose

	$kmsConfirmation = Read-ValidatedHost -Prompt 'Do you want to enable KMS for CloudTrail? [y/n]' -ValidationType Confirm
	if ($kmsConfirmation -eq 'y')
	{
		$script:kmsKeyDescription = New-KMS -Alias $kmsAliasName
		$script:kmsArn = ($kmsKeyDescription | ConvertFrom-Json).KeyMetadata.Arn 
		$script:kmsKeyId = ($kmsKeyDescription | ConvertFrom-Json).KeyMetadata.KeyId
		
		$customMessage = "Changes CloudTrail: Kms GenerateDataKey to CloudTrail"
		$kmsRequiredPolicies = Get-CloudTrailKmsPolicy -Role $roleArn
		Write-Log -Message "Executing: Update-KmsPolicy -RequiredPolicy $kmsRequiredPolicies -CustomMessage $customMessage" -LogFileName $script:LogFileName -Severity Verbose
		Update-KmsPolicy -RequiredPolicy $kmsRequiredPolicies -CustomMessage $customMessage
	}

	Update-SQSPolicy -Role $script:roleName -Bucket $script:bucketName -Sqs $script:sqsName

	$organizationCloudTrailConfirmation = Read-ValidatedHost -Prompt 'Do you want to enable the Trail and CloudTrail S3 Policy for ALL accounts in your organization? [y/n]' -ValidationType Confirm
	if ($organizationCloudTrailConfirmation -eq "y")
	{
		# Retreive the organization information
		Write-Log -Message "Executing: ((aws organizations describe-account --account-id $script:callerAccount ) | ConvertFrom-Json -ErrorAction SilentlyContinue).Account.Arn.Split('/')[1]" -LogFileName $script:LogFileName -Severity Verbose
		try
		{
			$script:organizationId = ((aws organizations describe-account --account-id $script:callerAccount) | ConvertFrom-Json -ErrorAction SilentlyContinue).Account.Arn.Split('/')[1]
		}
		catch {
			Write-Log -Message "Unable to access AWS organization information. This could be a permissions or policy issue." -LogFileName $script:LogFileName -Severity Information -Indent 2 
			$script:organizationCloudTrailConfirmation = "n"
		}

	}

	Write-Log -Message "Executing: `$s3RequiredPolicy = New-CloudTrailS3Policy" -LogFileName $script:LogFileName -Severity Verbose
	$s3RequiredPolicy = New-CloudTrailS3Policy
	
	$customMessage = "Changes S3: Get CloudTrail notifications"
	Update-S3Policy -RequiredPolicy $s3RequiredPolicy -CustomMessage $customMessage -Role $script:roleName -Bucket $script:bucketName

	$eventNotificationPrefix = Get-EventNotificationPrefix -OrganizationId $script:organizationId -Account $script:callerAccount -CreateOrganizationCloudTrail $script:organizationCloudTrailConfirmation
	Enable-S3EventNotification -DefaultEventNotificationPrefix $eventNotificationPrefix

	Write-Log -Message 'CloudTrail definition' -LogFileName $script:LogFileName -LinePadding 2

	Set-RetryAction({
		
		$script:cloudTrailName = Read-ValidatedHost 'Please enter CloudTrail name'
		Write-Log -Message "Using CloudTrail name: $script:cloudTrailName" -LogFileName $script:LogFileName -Indent 2

		Write-Log -Message "Executing: aws cloudtrail get-trail --name $script:cloudTrailName 2>&1| Out-Null" -LogFileName $script:LogFileName -Severity Verbose
		aws cloudtrail get-trail --name $script:cloudTrailName 2>&1| Out-Null
		
		$isCloudTrailNotExist = $lastexitcode -ne 0
		if ($isCloudTrailNotExist)
		{
			if ($kmsConfirmation -eq 'y')
			{
				Write-Log -Message "Executing: aws cloudtrail create-trail --name $script:cloudTrailName --s3-bucket-name $bucketName --kms-key-id $kmsKeyId 2>&1" -LogFileName $script:LogFileName -Severity Verbose
				$tempForOutput = aws cloudtrail create-trail --name $script:cloudTrailName --s3-bucket-name $bucketName --kms-key-id $kmsKeyId 2>&1
				Write-Log -Message $tempForOutput -LogFileName $script:LogFileName -Severity Verbose
			}
			else
			{
				Write-Log -Message "Executing: aws cloudtrail create-trail --name $script:cloudTrailName --s3-bucket-name $bucketName 2>&1" -LogFileName $script:LogFileName -Severity Verbose
				$tempForOutput = aws cloudtrail create-trail --name $script:cloudTrailName --s3-bucket-name $bucketName 2>&1
				Write-Log -Message $tempForOutput -LogFileName $script:LogFileName -Severity Verbose
			}
			if ($lastexitcode -eq 0)
			{
				Write-Log -Message "$script:cloudTrailName trail created successfully" -LogFileName $script:LogFileName -Indent 2
			}
		}
		else
		{
			$cloudTrailBucketConfirmation = Read-ValidatedHost "Trail '${cloudTrailName}' is already configured. Do you want to override the bucket destination? [y/n]"
			
			if ($cloudTrailBucketConfirmation -eq 'y')
			{
				if ($kmsConfirmation -eq 'y')
				{
					Write-Log -Message "Executing: aws cloudtrail update-trail --name $script:cloudTrailName --s3-bucket-name $bucketName -kms-key-id $kmsKeyId | Out-Null" -LogFileName $script:LogFileName -Severity Verbose
					aws cloudtrail update-trail --name $script:cloudTrailName --s3-bucket-name $bucketName -kms-key-id $kmsKeyId | Out-Null
				}
				else
				{
					Write-Log -Message "Executing: aws cloudtrail update-trail --name $script:cloudTrailName --s3-bucket-name $bucketName | Out-Null" -LogFileName $script:LogFileName -Severity Verbose
					aws cloudtrail update-trail --name $script:cloudTrailName --s3-bucket-name $bucketName | Out-Null
				}
			}
			else
			{
				Write-Log -Message "CloudTrail setup was not completed. You must manually set the CloudTrail destination bucket" -LogFileName $script:LogFileName -LinePadding 1
			}
		}
	})

	# Set-CloudTrailDataEventConfig - Moving function to main since it is only used once
	$dataEventsConfirmation = Read-ValidatedHost `n'Do you want to enable the CloudTrail data events? [y/n]' -ValidationType Confirm

	if ($dataEventsConfirmation -eq 'y')
	{
		Write-Log -Message "Executing: aws cloudtrail put-event-selectors --trail-name $script:cloudTrailName --event-selectors '[{'DataResources': [{'Type':'AWS::S3::Object', 'Values': ['arn:aws:s3:::']}]}]' | Out-Null" -LogFileName $script:LogFileName -Severity Verbose
		aws cloudtrail put-event-selectors --trail-name $script:cloudTrailName --event-selectors '[{\"DataResources\": [{\"Type\":\"AWS::S3::Object\", \"Values\": [\"arn:aws:s3:::\"]}]}]' | Out-Null
	}

	# Set-MultiRegionTrailConfig - Moving to main function since this is only called once.
	$regionConfirmation = Read-ValidatedHost 'Do you want the Trail to be multi-region? [y/n]' -ValidationType Confirm
	
	if ($regionConfirmation -eq 'y')
	{
		Write-Log -Message "Executing: aws cloudtrail update-trail --name $script:cloudTrailName --is-multi-region-trail | Out-Null" -LogFileName $script:LogFileName -Severity Verbose
		aws cloudtrail update-trail --name $script:cloudTrailName --is-multi-region-trail | Out-Null 
	}
	else
	{
		Write-Log -Message "Executing: aws cloudtrail update-trail --name $script:cloudTrailName --no-is-multi-region-trail | Out-Null" -LogFileName $script:LogFileName -Severity Verbose
		aws cloudtrail update-trail --name $script:cloudTrailName --no-is-multi-region-trail | Out-Null 
	}

	Set-OrganizationTrailConfig

	# Enable CloudTrail logging
	Write-Log -Message "Executing: aws cloudtrail start-logging  --name $script:cloudTrailName" -LogFileName $script:LogFileName -Severity Verbose
	aws cloudtrail start-logging  --name $script:cloudTrailName

	# Output information needed to configure Sentinel data connector
	Write-RequiredConnectorDefinitionInfo
}
