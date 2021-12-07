function New-ArnRole
{
   <#
   .SYNOPSIS
        Creates a new ARN role based on specified RoleName and WorkspaceId. This will allow the Azure Sentinel data connector to access data in S3.
    .PARAMETER Name
        Specifies the name for the new ARN
    .PARAMETER WorkspaceId
        Specifies the Azure Sentinel Workspace Id that will need access to the AWS resources.
    
   #>
   [CmdletBinding()]
   param (
       [Parameter()]
       [string]
       $Name,
       [Parameter()]
       [string]
       $WorkspaceId
   )
   Write-Log -Message "Assume role definition" -LogFileName $script:LogFileName -Severity Information -LinePadding 2
   Write-Log -Message "Executing Set-RetryAction" -LogFileName $script:LogFileName -Severity Verbose
    
   Set-RetryAction({

        # If the RoleName was not passed to the function, it needs to be requested from the user.
        if ($Name -eq "")
        {
            $Name = $script:RoleName = Read-ValidatedHost -Prompt 'Please enter role name. (If you have already configured an assume role for Azure Sentinel, use the same role name)'
        }
        else
        {
            $script:RoleName = $Name
        }
        
        Write-Log -Message "Using role name: $Name" -LogFileName $script:LogFileName -Severity Information -Indent 2
        
        # Determine if this role exists before continuing
        Write-Log "Executing: aws iam get-role --role-name $Name 2>&1| Out-Null" -LogFileName $script:LogFileName -Severity Verbose
        aws iam get-role --role-name $Name 2>&1| Out-Null

        # If there was an error the role does not already exist, so it must be created.
        $isRuleNotExist = $lastexitcode -ne 0
        if ($isRuleNotExist)
        {
            if ($WorkspaceId -eq "")
            {
                Write-Log "You must specify the the Azure Sentinel Workspace ID. This is found in the Azure Sentinel portal." -LogFileName $script:LogFileName -Severity Information -LinePadding 1
                $WorkspaceId = $script:workspaceId = Read-ValidatedHost -Prompt "Please enter your Azure Sentinel Workspace ID (External Id)"
            }
            else
            {
                $script:workspaceId = $WorkspaceId    
            }

            Write-Log "Using Azure Sentinel Workspace ID: $WorkspaceId" -LogFileName $script:LogFileName -Severity Information -Indent 2

            $rolePolicy = Get-RoleArnPolicy -WorkspaceId $script:WorkspaceId
            
            Write-Log "Executing: aws iam create-role --role-name $Name --assume-role-policy-document $rolePolicy 2>&1" -LogFileName $script:LogFileName -Severity Verbose
            $tempForOutput = aws iam create-role --role-name $Name --assume-role-policy-document $rolePolicy 2>&1
            Write-Log -Message $tempForOutput -LogFileName $script:LogFileName -Severity Verbose
            
            # If the role was retrieved then the role was created successfully
            if ($lastexitcode -eq 0)
            {
                Write-Log -Message "$Name role created successfully" -LogFileName $script:LogFileName -Severity Information -Indent 2
            }
        }
    })
}

function New-S3Bucket
{
    <#
   .SYNOPSIS
        Creates a new S3 Bucket based on the specified, bucket name and region.
   .PARAMETER Name
        Specifies the name for the bucket to create
    .PARAMETER AwsRegion
        Specifies the AWS region to create the bucket
        #>
   [CmdletBinding()]
   param (
       [Parameter()]
       [string]$Name,
       [Parameter()]
       [ValidateSet("us-east-2","us-east-1","us-west-1","us-west-2","af-south-1","ap-east-1","ap-south-1","ap-northeast-3","ap-northeast-2","ap-southeast-1",
       "ap-southeast-2","ap-northeast-1","ca-central-1","eu-central-1","eu-west-1","eu-west-2","eu-south-1","eu-west-3","eu-north-1","me-south-1","sa-east-1",
       "us-gov-east-1","us-gov-west-1","")]
       [string]$AwsRegion
   )
    Write-Log -Message "S3 bucket definition." -LogFileName $script:LogFileName -LinePadding 1
    Set-RetryAction({
        
        # Get s3 bucket name from user and clean up based on naming rules see https://docs.aws.amazon.com/awscloudtrail/latest/userguide/cloudtrail-s3-bucket-naming-requirements.html
        if ($Name -eq "")
        {
            $Name = $script:bucketName = (Read-ValidatedHost -Prompt "Please enter S3 bucket name" -MaxLength 64 -MinLength 3)
        }
        else
        {
            # TODO: Validate input information
            $script:bucketName = $Name
        }
        Write-Log -Message "Using S3 bucket name: $Name" -LogFileName $script:LogFileName -Indent 2
            
        Write-Log -Message "Executing: aws s3api head-bucket --bucket $Name 2>&1" -LogFileName $script:LogFileName -Severity Verbose
        $headBucketOutput = aws s3api head-bucket --bucket $Name 2>&1
            
        if ($null -ne $headBucketOutput)
        {
            # If AwsBucketRegion was not specified, prompt user for information
            if ($AwsRegion -eq "")
            {
                $AwsRegion = Read-ValidatedHost -Prompt "Please enter the AWS region in which to create S3 bucket"
            }

            Write-Log -Message "Using S3 bucket region: $AwsRegion" -LogFileName $script:LogFileName -Indent 2
            
            if ($AwsRegion -eq "us-east-1") # see aws doc https://docs.aws.amazon.com/cli/latest/reference/s3api/create-bucket.html
            {
                Write-Log -Message "Executing: aws s3api create-bucket --bucket $Name 2>&1" -LogFileName $script:LogFileName -Severity Verbose
                $tempForOutput = aws s3api create-bucket --bucket $Name 2>&1
                Write-Log -Message $tempForOutput -LogFileName $script:LogFileName -Severity Verbose
            }
            else
            {
                Write-Log "Executing: aws s3api create-bucket --bucket $Name --create-bucket-configuration LocationConstraint=$AwsRegion 2>&1" -LogFileName $script:LogFileName -Severity Verbose
                $tempForOutput = aws s3api create-bucket --bucket $Name --create-bucket-configuration LocationConstraint=$AwsRegion 2>&1
                Write-Log -Message $tempForOutput -LogFileName $script:LogFileName -Severity Verbose
            }
                
            if ($lastexitcode -eq 0)
            {
                Write-Log "S3 Bucket $Name created successfully" -LogFileName $script:LogFileName -Indent 2
            }
        }
    })
    
    # This seems redundant to steps that occur after this.
    # Write-Log -Message "Executing: (aws sts get-caller-identity | ConvertFrom-Json).Account" -LogFileName $script:LogFileName -Severity Verbose
    # $script:callerAccount = (aws sts get-caller-identity | ConvertFrom-Json).Account
    # Write-Log -Message $script:callerAccount -LogFileName $script:LogFileName -Severity Verbose

}

function New-SQSQueue
{
   <#
    .SYNOPSIS
        Creates a SQS Queue
    .PARAMETER Name
        Specifies the name for the SQS to create
   #>
   [OutputType([string])]
   [CmdletBinding()]
   param (
       [Parameter()]
       [string]
       $Name
   )
    Write-Log -Message "Creating SQS queue:" -LogFileName $script:LogFileName -LinePadding 1
    Set-RetryAction({

        if ($Name -eq "")
        {
            $script:sqsName = $Name = Read-ValidatedHost -Prompt "Please enter Sqs name"
        }

        Write-Log -Message "Using Sqs name: $Name" -LogFileName $script:LogFileName -Indent 2
        Write-Log -Message "Executing: aws sqs create-queue --queue-name $Name 2>&1" -LogFileName $script:LogFileName -Severity Verbose
        $tempForOutput = aws sqs create-queue --queue-name $Name 2>&1
        Write-Log -Message $tempForOutput -LogFileName $script:LogFileName -Severity Verbose
    })

    return $script:sqsName
}

function Enable-S3EventNotification 
{
    <#
   .SYNOPSIS
        Enables S3 event notifications. User may override the default prefix

    .PARAMETER DefaultEventNotificationPrefix
        Specifies the default prefix. The user may override this prefix and specify a new one
   #>
    param(
        [Parameter(Mandatory=$true)][string]$DefaultEventNotificationPrefix
        )
        Write-Log -Message "Enabling S3 event notifications (for *.gz files)" -LogFileName $script:LogFileName -LinePadding 2
    
    Set-RetryAction({

        $script:eventNotificationName = Read-ValidatedHost -Prompt 'Please enter the event notifications name'
        Write-Log -Message "Using event notification name: $script:eventNotificationName" -LogFileName $script:LogFileName -Indent 2

        $eventNotificationPrefix = $DefaultEventNotificationPrefix
      
        $prefixOverrideConfirm = Read-ValidatedHost -Prompt "The default prefix is '$eventNotificationPrefix'. `n   Do you want to override the event notification prefix? [y/n]" -ValidationType Confirm
        if ($prefixOverrideConfirm -eq 'y')
        {
            $eventNotificationPrefix = Read-ValidatedHost 'Please enter the event notifications prefix'
            Write-Log -Message "Using event notification prefix: $eventNotificationPrefix" -LogFileName $script:LogFileName -Indent 2
        }

        $newEventConfig = Get-SqsEventNotificationConfig -EventNotificationName $script:eventNotificationName -EventNotificationPrefix $eventNotificationPrefix -Sqs $script:sqsArn

        Write-Log -Message "Executing: aws s3api get-bucket-notification-configuration --bucket $BucketName" -LogFileName $script:LogFileName -Severity Verbose
        $existingEventConfig = aws s3api get-bucket-notification-configuration --bucket $BucketName

        if ($null -ne $existingEventConfig)
        {
            $newEventConfigObject = $newEventConfig | ConvertFrom-Json
            $existingEventConfigObject = $existingEventConfig | ConvertFrom-Json 
            
            $newEventConfigObject.QueueConfigurations += $existingEventConfigObject.QueueConfigurations
            $updatedEventConfigs = ($newEventConfigObject | ConvertTo-Json -Depth 6 ).Replace('"','\"')
        }
        else
        {
            $updatedEventConfigs = $newEventConfig.Replace('"','\"')
        }
        Write-Log -Message "Executing: aws s3api put-bucket-notification-configuration --bucket $BucketName --notification-configuration $updatedEventConfigs 2>&1" -LogFileName $script:LogFileName -Severity Verbose
        $tempForOutput = aws s3api put-bucket-notification-configuration --bucket $BucketName --notification-configuration $updatedEventConfigs 2>&1
        if ($null -ne $tempForOutput)
        {
            Write-Log -Message $tempForOutput -LogFileName $script:LogFileName -Severity Verbose
        }
        
    })
}

function New-KMS
{
    <#
    .SYNOPSIS
        Creates a new Kms with specified alias

    .PARAMETER Alias
        Specifies the alias for the created KMS

    #>
    [OutputType([string])]
    [CmdletBinding()]
    param (
    [Parameter()]
    [string]
    $Alias
    )

    Write-Log -Message "Kms definition." -LogFileName $script:LogFileName -LinePadding 1
    Set-RetryAction({
        
        # If alias is not provided as parameter, ask the user for the value.
        if ($Alias -eq "")
        {
            $Alias = $script:kmsAlias = Read-ValidatedHost -Prompt "Please enter the KMS alias name"
        }
        else
        {
            $script:kmsAlias = $Alias
        }

        Write-Log -Message "Using Kms alias name: $Alias" -LogFileName $script:LogFileName -Indent 2
        Write-Log -Message "Executing: aws kms describe-key --key-id alias/$Alias 2>&1" -LogFileName $script:LogFileName -Severity Verbose
        $script:kmsKeyDescription = aws kms describe-key --key-id alias/$Alias 2>&1

        # If there weren't any errors continue
        if ($lastexitcode -ne 0)
        {
            Write-Log -Message $script:kmsKeyDescription -LogFileName $script:LogFileName -Severity Verbose  
            Write-Log -Message "Executing: aws kms create-key" -LogFileName $script:LogFileName -Severity Verbose
            $script:kmsKeyDescription = aws kms create-key
            
            Write-Log -Message "`$script:kmsKeyDescription = $script:kmsKeyDescription" -LogFileName $script:LogFileName -Severity Verbose
            $script:kmsKeyId = ($script:kmsKeyDescription | ConvertFrom-Json).KeyMetadata.KeyId
            
            Write-Log -Message "Executing: aws kms create-alias --alias-name alias/$Alias --target-key-id $script:kmsKeyId 2>&1" -LogFileName $script:LogFileName -Severity Verbose
            $tempForOutput = aws kms create-alias --alias-name alias/$Alias --target-key-id $script:kmsKeyId 2>&1
            
            if ($null -ne $tempForOutput)
            {
                Write-Log -Message "$($tempForOutput.ToString()) " -LogFileName $script:LogFileName -Indent 2 -Severity Verbose
            }

            if ($lastexitcode -eq 0)
            {
                Write-Log -Message "$Alias created successfully" -LogFileName $script:LogFileName -Indent 2
            }
            else
            {
                Write-Log -Message "Error occurred executing: aws kms create-alias --alias-name alias/$Alias --target-key-id $script:kmsKeyId 2>&1" -LogFileName $script:LogFileName -Severity Verbose
                Write-Log -Message "$Error[0]" -LogFileName $script:LogFileName -Severity Verbose
            }
        }
    })

    return $script:kmsKeyDescription
}