function Get-RoleArnPolicy
{
   <#
	.SYNOPSIS
		Returns a customized Arn policy using the Sentinel Workspace Id
	.PARAMETER WorkspaceId
		Specifies the Azure Sentinel workspace id 
   #>
[OutputType([string])]
[CmdletBinding()]
param (
	[Parameter(position=0)]
	[ValidateNotNullOrEmpty()]
	[string]
	$WorkspaceId
)  
   $arnRolePolicy = "{
            'Version': '2012-10-17',
            'Statement': [
                {
                    'Effect': 'Allow',
                    'Principal': {
                        'AWS': 'arn:aws:iam::197857026523:root'
                    },
                    'Action': 'sts:AssumeRole',
                    'Condition': {
                        'StringEquals': {
                            'sts:ExternalId': '$WorkspaceId'
                        }
                    }
                }
            ]
        }"
	return $arnRolePolicy.Replace("'",'\"')
}

function Get-S3AndRuleSQSPolicies
{
   	<#
	.SYNOPSIS
		Returns a customized Sqs rule policy using the specified S3 bucket name, the Sqs ARN, and role ARN.
	.PARAMETER EventNotificationName
		Specifies the event notification name
	.PARAMETER EventNotificationPrefix
		Specifies the event notification prefix
	.PARAMETER SqsArn
		Specifies the Sqs ARN
   #>
   [OutputType([string])]
   [CmdletBinding()]
   param (
	   [ValidateNotNullOrEmpty()][string]
	   $RoleArn,
	   [ValidateNotNullOrEmpty()][string]
	   $BucketName,
	   [ValidateNotNullOrEmpty()][string]
	   $SqsArn
   )  

	$sqsPolicyForS3 = "
    {
	  'Version': '2008-10-17',
	  'Id':'__default_policy_ID',
      'Statement': [
		  {
			  'Sid': 'allow s3 to send notification messages to SQS queue',
			  'Effect': 'Allow',
			  'Principal': {
				'Service': 's3.amazonaws.com'
			  },
			  'Action': 'SQS:SendMessage',
			  'Resource': '$SqsArn',
			  'Condition': {
				'ArnLike': {
				  'aws:SourceArn': 'arn:aws:s3:*:*:$BucketName'
				}
			  }
		  },
		  {
		  'Sid': 'allow specific role to read/delete/change visibility of SQS messages and get queue url',
		  'Effect': 'Allow',
		  'Principal': {
			'AWS': '$RoleArn'
		  },
		  'Action': [
			'SQS:ChangeMessageVisibility',
			'SQS:DeleteMessage',
			'SQS:ReceiveMessage',
            'SQS:GetQueueUrl'
		  ],
		  'Resource': '$SqsArn'
		}
	  ]
	}"

	return $sqsPolicyForS3.Replace("'",'"')
}

function Get-SqsEventNotificationConfig
{ 
   	<#
	.SYNOPSIS
		Returns a customized Sqs event notification config policy using the specified event notification name, the Sqs ARN, and notification prefix.
	.PARAMETER EventNotificationName
		Specifies the event notification name
	.PARAMETER EventNotificationPrefix
		Specifies the event notification prefix
	.PARAMETER SqsArn
		Specifies the Sqs ARN
   #>
[OutputType([string])]
[CmdletBinding()]
param (
	[Parameter(position=0)]
	[ValidateNotNullOrEmpty()]
	[string]
	$EventNotificationName,
	[Parameter(position=1)]
	[ValidateNotNullOrEmpty()]
	[string]
	$EventNotificationPrefix,
	[Parameter(position=2)]
	[ValidateNotNullOrEmpty()]
	[string]
	$SqsArn
)  

	$sqsEventConfig = "
   {
	   'QueueConfigurations': [
			{
			  'Id':'$EventNotificationName',
			  'QueueArn': '$SqsArn',
			  'Events': ['s3:ObjectCreated:*'],
			  'Filter': {
				'Key': {
				  'FilterRules': [
					{
					  'Name': 'prefix',
					  'Value': '$EventNotificationPrefix'
					},
					{
					  'Name': 'suffix',
					  'Value': '.gz'
					}
				  ]
				}
			  }
			}
		]
	}"

	return $sqsEventConfig.Replace("'",'"')
}

function Get-RoleS3Policy
{
	<#
	.SYNOPSIS
		Returns a customized Arn policy using the specified role ARN and bucket name
	.PARAMETER RoleArn
		Specifies the Role ARN
	.PARAMETER BucketName
		Specifies the S3 Bucket
   #>
[OutputType([string])]
[CmdletBinding()]
param (
	[Parameter(position=0)]
	[ValidateNotNullOrEmpty()][string]
	$RoleArn,
	[Parameter(position=1)]
	[ValidateNotNullOrEmpty()][string]
	$BucketName
)  
	
	$s3PolicyForArn = "{
	 'Statement': [{
            'Sid': 'Allow Arn read access S3 bucket',
            'Effect': 'Allow',
            'Principal': {
                'AWS': '$RoleArn'
            },
            'Action': ['s3:Get*','s3:List*'],
            'Resource': 'arn:aws:s3:::$BucketName/*'
        }]}"
			
	return $s3PolicyForArn.Replace("'",'"')
}

#region CloudTrail_policies
function Get-CloudTrailKmsPolicy
{
	<#
	.SYNOPSIS
		Returns a customized Kms policy for CloudTrail using the supplied Role Arn principal
	.PARAMETER RoleArn
		Specifies the ARN to use in the customized KMS policy
	#>
[CmdletBinding()]
param (
	[Parameter()]
	[string]
	$RoleArn
)
	$kmsPolicy = "{
		'Statement': [
		{
			  'Sid': 'Allow CloudTrail to encrypt logs',
			  'Effect': 'Allow',
			  'Principal': {
				'Service': 'cloudtrail.amazonaws.com'
			  },
			  'Action': 'kms:GenerateDataKey*',
			  'Resource': '*'
		},
        {
            'Sid': 'Allow use of the key',
            'Effect': 'Allow',
            'Principal': {
                'AWS': ['$RoleArn']
            },
            'Action': [
                'kms:Encrypt',
                'kms:Decrypt',
                'kms:ReEncrypt*',
                'kms:GenerateDataKey*',
                'kms:DescribeKey'
            ],
            'Resource': '*'
        }
    ]}"
	
	return $kmsPolicy.Replace("'",'"')
}

function Get-OrganizationCloudTrailS3Policy
{	
	<#
	.SYNOPSIS
		Returns a customized S3 Policy for specified organization and S3 bucket
	.PARAMETER BucketName
		Specifies the name of the bucket name
	.PARAMETER OrganizationId
		Specifies the Aws organization id
	#>
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]
		$BucketName,
		[Parameter()]
		[string]
		$OrganizationId
	)

	$s3PolicyForRoleOrganizationCloudTrail = "{
        'Sid': 'AWSCloudTrailWrite20150319',
        'Effect': 'Allow',
        'Principal': {
            'Service': [
                    'cloudtrail.amazonaws.com'
                ]
            },
        'Action': 's3:PutObject',
        'Resource': 'arn:aws:s3:::$BucketName/AWSLogs/$OrganizationId/*',
        'Condition': {
            'StringEquals': {
                's3:x-amz-acl': 'bucket-owner-full-control'
            }
        }
    }"

	return $s3PolicyForRoleOrganizationCloudTrail.Replace("'",'"')
}

function Get-KmsS3Policy
{	
	<#
	.SYNOPSIS
		Returns customized S3 policy for Kms Arn to access S3 bucket	
	.PARAMETER BucketName
		Specifies the bucket name 
	.PARAMETER KmsArn
		Specifies the KMS ARN
	
	#>
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]
		$BucketName,
		[Parameter()]
		[string]
		$KmsArn
	)

	$s3PolicyForKms = "
	[	
		{
            'Sid': 'Deny unencrypted object uploads. This is optional',
            'Effect': 'Deny',
            'Principal': {
                'Service': 'cloudtrail.amazonaws.com'
            },
            'Action': 's3:PutObject',
            'Resource': 'arn:aws:s3:::$BucketName/*',
            'Condition': {
                'StringNotEquals': {
                    's3:x-amz-server-side-encryption': 'aws:kms'
                }
            }
        },
        {
            'Sid': 'Deny incorrect encryption header. This is optional',
            'Effect': 'Deny',
            'Principal': {
                'Service': 'cloudtrail.amazonaws.com'
            },
            'Action': 's3:PutObject',
            'Resource': 'arn:aws:s3:::$BucketName/*',
            'Condition': {
                'StringNotEquals': {
                    's3:x-amz-server-side-encryption-aws-kms-key-id': '$KmsArn'
                }
            }
		}
    ]"

	return $s3PolicyForKms.Replace("'",'"')
}

function Get-RoleAndCloudTrailS3Policy
{
	<#
	.SYNOPSIS
		Returns customized S3 Policy to allown specified Role Arn to write CloudTrail logs to specified S3 bucket
	.PARAMETER BucketName
		Specifies the bucket name
	
	#>
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]
		$BucketName,
		[Parameter()]
		[string]
		$RoleArn,
		[Parameter()]
		[string]
		$CallerAccount
	)
	 $s3PolicyForRoleAndCloudTrail = "{
	 'Statement': [
		{
            'Sid': 'Allow Arn read access S3 bucket',
            'Effect': 'Allow',
            'Principal': {
                'AWS': '$RoleArn'
            },
            'Action': ['s3:Get*','s3:List*'],
            'Resource': 'arn:aws:s3:::$BucketName/*'
        },
		{
            'Sid': 'AWSCloudTrailAclCheck20150319',
            'Effect': 'Allow',
            'Principal': {
                'Service': 'cloudtrail.amazonaws.com'
            },
            'Action': 's3:GetBucketAcl',
            'Resource': 'arn:aws:s3:::$BucketName'
        },
        {
            'Sid': 'AWSCloudTrailWrite20150319',
            'Effect': 'Allow',
            'Principal': {
                'Service': 'cloudtrail.amazonaws.com'
            },
            'Action': 's3:PutObject',
            'Resource': 'arn:aws:s3:::$BucketName/AWSLogs/$CallerAccount/*',
            'Condition': {
                'StringEquals': {
                    's3:x-amz-acl': 'bucket-owner-full-control'
                }
            }
        }]}"	
	return $s3PolicyForRoleAndCloudTrail.Replace("'",'"')
}

function New-CloudTrailS3Policy
{
	<#
	.SYNOPSIS
		Returns customized S3 Policy for CloudTrail logs
	#>
	$s3RequiredPolicy = Get-RoleAndCloudTrailS3Policy -BucketName $bucketName -RoleArn $roleArn -CallerAccount $callerAccount
	$s3RequiredPolicyObject = $s3RequiredPolicy | ConvertFrom-Json 
	if ($organizationCloudTrailConfirmation -ne 'n')
	{
		$s3RequiredPolicyObject.Statement += (Get-OrganizationCloudTrailS3Policy -BucketName $bucketName -OrganizationId $organizationId | ConvertFrom-Json)
	}
	if ($kmsConfirmation -eq 'y')
	{
		$s3RequiredPolicyObject.Statement += (Get-KmsS3Policy -BucketName $bucketName -KmsArn $kmsArn | ConvertFrom-Json)
	}

	return $s3RequiredPolicyObject | ConvertTo-Json -Depth 5
}

#endregion

#region guardduty_policies

function Get-RoleAndGuardDutyS3Policy
{
	<#
    .SYNOPSIS 
        Creates a S3 Policy for GuardDuty based on specified bucket name, role ARN, and Kms ARN

    .PARAMETER RoleArn
		Specifies the Role ARN
	.PARAMETER BucketName
		Specifies the S3 Bucket
    .PARAMETER KmsArn
        Specifies the KMS ARN
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param (
        [Parameter(position=0)]
        [ValidateNotNullOrEmpty()][string]
        $RoleArn,
        [Parameter(position=1)]
        [ValidateNotNullOrEmpty()][string]
        $BucketName,
        [Parameter(position=2)]
        [ValidateNotNullOrEmpty()][string]
        $KmsArn
    )  
    $s3PolicyForRoleAndGuardDuty = "{
	 'Statement': [
		{
            'Sid': 'Allow Arn read access S3 bucket',
            'Effect': 'Allow',
            'Principal': {
                'AWS': '$RoleArn'
            },
            'Action': ['s3:Get*','s3:List*'],
            'Resource': 'arn:aws:s3:::$BucketName/*'
        },
		{
            'Sid': 'Allow GuardDuty to use the getBucketLocation operation',
            'Effect': 'Allow',
            'Principal': {
                'Service': 'guardduty.amazonaws.com'
            },
            'Action': 's3:GetBucketLocation',
            'Resource': 'arn:aws:s3:::$BucketName'
        },
        {
            'Sid': 'Allow GuardDuty to upload objects to the bucket',
            'Effect': 'Allow',
            'Principal': {
                'Service': 'guardduty.amazonaws.com'
            },
            'Action': 's3:PutObject',
            'Resource': 'arn:aws:s3:::$BucketName/*'
        },
        {
            'Sid': 'Deny unencrypted object uploads. This is optional',
            'Effect': 'Deny',
            'Principal': {
                'Service': 'guardduty.amazonaws.com'
            },
            'Action': 's3:PutObject',
            'Resource': 'arn:aws:s3:::$BucketName/*',
            'Condition': {
                'StringNotEquals': {
                    's3:x-amz-server-side-encryption': 'aws:kms'
                }
            }
        },
        {
            'Sid': 'Deny incorrect encryption header. This is optional',
            'Effect': 'Deny',
            'Principal': {
                'Service': 'guardduty.amazonaws.com'
            },
            'Action': 's3:PutObject',
            'Resource': 'arn:aws:s3:::$BucketName/*',
            'Condition': {
                'StringNotEquals': {
                    's3:x-amz-server-side-encryption-aws-kms-key-id': '$KmsArn'
                }
            }
        },
        {
            'Sid': 'Deny non-HTTPS access',
            'Effect': 'Deny',
            'Principal': '*',
            'Action': 's3:*',
            'Resource': 'arn:aws:s3:::$BucketName/*',
            'Condition': {
                'Bool': {
                    'aws:SecureTransport': 'false'
                }
            }
	 }]}"	
	return $s3PolicyForRoleAndGuardDuty.Replace("'",'"')
}

function Get-GuardDutyAndRoleKmsPolicy
{
	<#
    .SYNOPSIS 
        Creates a customized KMS Policy for GuardDuty based on specified role ARN
    .PARAMETER RoleArn
		Specifies the Role ARN
    #>
    [OutputType([string])]
    [CmdletBinding()]
    param (
        [Parameter(position=0)]
        [ValidateNotNullOrEmpty()][string]
        $RoleArn
    )

    $kmsPolicy = "{
		'Statement': [
        {
            'Sid': 'Allow GuardDuty to use the key',
            'Effect': 'Allow',
            'Principal': {
                'Service': 'guardduty.amazonaws.com'
            },
            'Action': 'kms:GenerateDataKey',
            'Resource': '*'
        },
        {
            'Sid': 'Allow use of the key',
            'Effect': 'Allow',
            'Principal': {
                'AWS': ['$RoleArn']
            },
            'Action': [
                'kms:Encrypt',
                'kms:Decrypt',
                'kms:ReEncrypt*',
                'kms:GenerateDataKey*',
                'kms:DescribeKey'
            ],
            'Resource': '*'
        }
    ]}"
	
	return $kmsPolicy.Replace("'",'"')
}

#endregion