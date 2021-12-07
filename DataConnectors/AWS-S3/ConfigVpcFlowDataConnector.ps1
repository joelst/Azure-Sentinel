function New-VpcFlowDataConnector {
	<#
	.SYNOPSIS
		Main function to setup AWS VPC Flow for use with the Azure Sentinel AWS S3 data connector
	#>
	
	Write-Log -Message "Starting Vpc flow data connector configuration script" -LogFileName $script:LogFileName -Severity Verbose
	Write-Log -Message "This script creates an Assume Role with minimal permissions to grant Azure Sentinel access to your logs in a designated S3 bucket & SQS of your choice, enable VPCFlow Logs, S3 bucket, SQS Queue, and S3 notifications." -LogFileName $script:LogFileName

	# Connect using the AWS CLI
	Get-AwsConfig

	# Create new Arn Role
	New-ArnRole -Name $roleName -WorkspaceId $workspaceId
	Write-Log -Message "Executing: aws iam get-role --role-name $roleName" -LogFileName $script:LogFileName -Severity Verbose
	$roleArnObject = aws iam get-role --role-name $roleName
	$roleArn = ($roleArnObject | ConvertFrom-Json ).Role.Arn
	Write-Log -Message $roleArn -LogFileName $script:LogFileName -Severity Verbose

	# Create S3 bucket for storing logs
	New-S3BucketNew-S3Bucket -BucketName $BucketName -AwsRegion $AwsRegion
	
	Write-Log -Message "Executing: (aws sts get-caller-identity | ConvertFrom-Json).Account" -LogFileName $script:LogFileName -Severity Verbose
	$script:callerAccount = (aws sts get-caller-identity | ConvertFrom-Json).Account
	Write-Log -Message $script:callerAccount -LogFileName $script:LogFileName -Severity Verbose

	Write-Log -Message "Listing your available VPCs" -LogFileName $script:LogFileName -Severity Information -LinePadding 1
	Write-Log -Message "Executing: aws ec2 --output text --query 'Vpcs[*].{VpcId:VpcId}' describe-vpcs" -LogFileName $script:LogFileName -Severity Verbose
	aws ec2 --output text --query 'Vpcs[*].{VpcId:VpcId}' describe-vpcs

	Write-Log 'Enabling VPC flow Logs (default format)' -LogFileName $script:LogFileName -Severity Information -LinePadding 1

	Set-RetryAction({
		
		$vpcResourceIds = Read-ValidatedHost 'Please enter Vpc Resource Id[s] (space separated)'
		Write-Log -Message "Using Vpc Resource Ids: $vpcResourceIds" -LogFileName $script:LogFileName -Severity Information -Indent 2
		
		do
		{
			try
			{
				[ValidateSet("ALL","ACCEPT","REJECT")]$vpcTrafficType = Read-Host 'Please enter traffic type (ALL, ACCEPT, REJECT)'
			}
			catch {}

		} until ($?)

		$vpcName = Read-ValidatedHost 'Please enter Vpc name'
		Write-Log "Using Vpc name: $vpcName" -LogFileName $script:LogFileName -Indent 2

		$vpcTagSpecifications = "ResourceType=vpc-flow-log,Tags=[{Key=Name,Value=$vpcName}]"
		Write-Log -Message "Vpc tag specification: $vpcTagSpecifications" -LogFileName $script:LogFileName

		Write-Log -Message "Executing: aws ec2 create-flow-logs --resource-type VPC --resource-ids $vpcResourceIds.Split(' ') --traffic-type $vpcTrafficType --log-destination-type s3 --log-destination arn:aws:s3:::$bucketName --tag-specifications $vpcTagSpecifications 2>&1" -LogFileName $script:LogFileName -Severity Verbose
		$tempForOutput = aws ec2 create-flow-logs --resource-type VPC --resource-ids $vpcResourceIds.Split(' ') --traffic-type $vpcTrafficType --log-destination-type s3 --log-destination arn:aws:s3:::$bucketName --tag-specifications $vpcTagSpecifications 2>&1
		Write-Log $tempForOutput -LogFileName $script:LogFileName -Severity Verbose

	})

	Write-Log "Executing: New-SQSQueue -Name $sqsName" -LogFileName $script:LogFileName -Severity Verbose
	$script:sqsName = New-SQSQueue -Name $sqsName

	Write-Log "Executing: ((aws sqs get-queue-url --queue-name $sqsName) | ConvertFrom-Json).QueueUrl" -LogFileName $script:LogFileName -Severity Verbose
	$script:sqsUrl = ((aws sqs get-queue-url --queue-name $sqsName) | ConvertFrom-Json).QueueUrl
	if ($null -ne $script:sqsUrl)
	{
		Write-Log "`$script:sqsUrl = $script:sqsUrl" -LogFileName $script:LogFileName -Severity Verbose
	}
	
	Write-Log "Executing: ((aws sqs get-queue-attributes --queue-url $sqsUrl --attribute-names QueueArn )| ConvertFrom-Json).Attributes.QueueArn" -LogFileName $script:LogFileName -Severity Verbose
	$script:sqsArn =  ((aws sqs get-queue-attributes --queue-url $sqsUrl --attribute-names QueueArn )| ConvertFrom-Json).Attributes.QueueArn
	Write-Log "`$script:sqsArn = $($script:sqsArn.ToString())" -LogFileName $script:LogFileName -Severity Verbose

	Update-SQSPolicy -Role $script:roleName -Bucket $script:bucketName -Sqs $script:sqsName

	Write-Log -Message "Attaching S3 read policy to Sentinel role." -LogFileName $script:LogFileName -LinePadding 1
	Write-Log -Message "Changes Role ARN: S3 Get and List permissions to '$script:roleName' rule" -LogFileName $script:LogFileName

	$s3RequiredPolicy = Get-RoleS3Policy -Role $script:roleArn -Bucket script:$bucketName
	Update-S3Policy -RequiredPolicy $s3RequiredPolicy -Role $script:roleName -Bucket $script:bucketName

	Enable-S3EventNotification -DefaultEventNotificationPrefix "AWSLogs/$script:callerAccount/vpcflowlogs/"

	# Output information needed to configure Sentinel data connector
	Write-RequiredConnectorDefinitionInfo
}