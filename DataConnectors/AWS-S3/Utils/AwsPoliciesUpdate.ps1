function Update-SQSPolicy
{
    <#
    .SYNOPSIS 
       Update the SQS policy
    .PARAMETER Role
        Specifies the role name to assign in the customized policy
    .PARAMETER Bucket
        Specifies the bucket name for the customized policy to be assigned.
    .PARAMETER Sqs
        Specifies the Sqs name for the customized policy
    #>

    param
    (
         [Parameter(Mandatory=$true)][string]$Role,
         [Parameter(Mandatory=$true)][string]$Bucket,
         [Parameter(Mandatory=$true)][string]$Sqs
    )
    Write-Log -Message "Updating the SQS policy to allow S3 notifications, and ARN to read/delete/change visibility of SQS messages and get queue url" -LogFileName $script:LogFileName -LinePadding 1
    Write-Log -Message "Changes S3: SQS SendMessage permission to '$Bucket'" -LogFileName $script:LogFileName -Indent 2
    Write-Log -Message "Changes Role ARN: SQS ChangeMessageVisibility, DeleteMessage, ReceiveMessage and GetQueueUrl permissions to '$Role'" -LogFileName $script:LogFileName -Indent 2

    Write-Log -Message "Executing: `$sqsRequiredPolicies = Get-S3AndRuleSQSPolicies -Role $Role -Sqs $Sqs -Bucket $Bucket" -LogFileName $script:LogFileName -Severity Verbose
    $sqsRequiredPolicies = Get-S3AndRuleSQSPolicies -Role $Role -Sqs $Sqs -Bucket $Bucket
    Write-Log -Message "`$sqsRequiredPolicies = $sqsRequiredPolicies" -LogFileName $script:LogFileName -Severity Verbose

    Write-Log -Message "Executing: `$currentSqsPolicy = aws sqs get-queue-attributes --queue-url $script:sqsUrl --attribute-names Policy" -LogFileName $script:LogFileName -Severity Verbose
    $currentSqsPolicy = aws sqs get-queue-attributes --queue-url $script:sqsUrl --attribute-names Policy

    if ($null -ne $currentSqsPolicy)
    {
        Write-Log -Message "`$currentSqsPolicy = $currentSqsPolicy" -LogFileName $script:LogFileName -Severity Verbose
        $sqsRequiredPoliciesObject = $sqsRequiredPolicies | ConvertFrom-Json 
        $currentSqsPolicyObject = $currentSqsPolicy | ConvertFrom-Json 	
        $currentSqsPolicies = ($currentSqsPolicyObject.Attributes.Policy) | ConvertFrom-Json 
        
        $sqsRequiredPoliciesMissingInCurrentPolicy = $sqsRequiredPoliciesObject.Statement | Where-Object { ($_ | ConvertTo-Json -Depth 5) -notin ($currentSqsPolicies.Statement | ForEach-Object { $_ | ConvertTo-Json -Depth 5}  )}
        
        if ($null -ne $sqsRequiredPoliciesMissingInCurrentPolicy)
        {
            $currentSqsPolicies.Statement += $sqsRequiredPoliciesMissingInCurrentPolicy
            $UpdatedPolicyValue = ($currentSqsPolicies | ConvertTo-Json -Depth 16  -Compress).Replace('"','\\\"')
            $UpdatedSqsPolicy = ("{'Policy':'$UpdatedPolicyValue'}").Replace("'",'\"')

            Write-Log -Message "Executing: aws sqs set-queue-attributes --queue-url $script:sqsUrl  --attributes $UpdatedSqsPolicy | Out-Null" -LogFileName $script:LogFileName -Severity Verbose
            aws sqs set-queue-attributes --queue-url $script:sqsUrl  --attributes $UpdatedSqsPolicy | Out-Null
        }
    }
    else
    {
        # If no sqs queue attributes exist, need to set new attributes.
        Write-Log -Message "No results returned from: aws sqs get-queue-attributes --queue-url $script:sqsUrl --attribute-names Policy " -LogFileName $script:LogFileName -Severity Verbose
        $newSqsPolicyValue = ($sqsRequiredPolicies | ConvertFrom-Json |  ConvertTo-Json -Depth 16  -Compress).Replace('"','\\\"')
        $newSqsPolicyObject = ("{'Policy':'${newSqsPolicyValue}'}").Replace("'",'\"')
        
        Write-Log -Message "Executing: aws sqs set-queue-attributes --queue-url $script:sqsUrl --attributes $newSqsPolicyObject | Out-Null" -LogFileName $script:LogFileName -Severity Verbose
        aws sqs set-queue-attributes --queue-url $script:sqsUrl --attributes $newSqsPolicyObject | Out-Null
    }
}

function Update-S3Policy
{
    <#
    .SYNOPSIS
        Updates S3 policy to allow Sentinel access to read data.
    
    .PARAMETER RequiredPolicy
        Specifies the policy to customize
    .PARAMETER CustomMessage
        Specifies the message to include in customized policy
    .PARAMETER Role
        Specifies the role name to assign in the customized policy
    .PARAMETER Bucket
        Specifies the bucket name for the customized policy to be assigned.
    #>
    
    param
    (
         [Parameter(Mandatory=$true)][string]$RequiredPolicy,
         [Parameter(Mandatory=$false)][string]$CustomMessage,
         [Parameter(Mandatory=$false)][string]$Role,
         [Parameter()][string]$Bucket
    )

    Write-Log -Message "Updating S3 policy to allow Sentinel read access." -LogFileName $script:LogFileName -LinePadding 1
    Write-Log -Message "Changes S3: Add Get and List permissions to '$Role'" -LogFileName $script:LogFileName -Indent 2

    if ($CustomMessage -ne $null)
    {
        Write-Output $CustomMessage
    }
    
    Write-Log -Message "Executing: aws s3api get-bucket-policy --bucket $Bucket 2>&1" -LogFileName $script:LogFileName -Severity Verbose
    $currentBucketPolicy = aws s3api get-bucket-policy --bucket $Bucket 2>&1
    $isBucketPolicyExist = $lastexitcode -eq 0
    if ($isBucketPolicyExist)
    {	
        $s3RequiredPolicyObject = $s3RequiredPolicy | ConvertFrom-Json 
        $currentBucketPolicyObject = $currentBucketPolicy | ConvertFrom-Json 	
        $currentBucketPolicies = ($currentBucketPolicyObject.Policy) | ConvertFrom-Json 
        
        $s3RequiredPolicyMissingInCurrentPolicy = $s3RequiredPolicyObject.Statement | Where-Object { ($_ | ConvertTo-Json -Depth 5) -notin ($currentBucketPolicies.Statement | ForEach-Object { $_ | ConvertTo-Json  -Depth 5}  )}
        if ($null -ne $s3RequiredPolicyMissingInCurrentPolicy)
        {
            $currentBucketPolicies.Statement += $s3RequiredPolicyMissingInCurrentPolicy
            $UpdatedS3Policy = (@{Statement = $currentBucketPolicies.Statement} | ConvertTo-Json -Depth 16).Replace('"','\"')
            Write-Log -Message "Executing: aws s3api put-bucket-policy --bucket $Bucket --policy $UpdatedS3Policy | Out-Null" -LogFileName $script:LogFileName -Severity Verbose
            aws s3api put-bucket-policy --bucket $Bucket --policy $UpdatedS3Policy | Out-Null
        }
    }
    else
    {
        # $s3RequiredPolicyObject - remove one step
        $newS3Policy = ($s3RequiredPolicy | ConvertFrom-Json | ConvertTo-Json -Depth 16).Replace('"','\"')
        Write-Log -Message "Executing: aws s3api put-bucket-policy --bucket $Bucket --policy $newS3Policy | Out-Null" -LogFileName $script:LogFileName -Severity Verbose
        aws s3api put-bucket-policy --bucket $Bucket --policy $newS3Policy | Out-Null
    }
}

function Update-KmsPolicy
{
    <#
    .SYNOPSIS
        Updates Kms policy to allow Sentinel access to read data.

    .PARAMETER RequiredPolicy
        Specifies the policy to customize

    .PARAMETER CustomMessage
        Specifies the message to include in customized policy

    .PARAMETER KeyId
        Specifies the KMS key id

    .PARAMETER Role
        Specifies the role

    #>
    param
    (
         [Parameter(Mandatory=$true)][string]$RequiredPolicy,
         [Parameter(Mandatory=$false)][string]$CustomMessage,
         [Parameter()][string]$KeyId,
         [Parameter()][string]$Role
    )

    Write-Log -Message "Updating KMS policy to allow Sentinel read the data." -LogFileName $script:LogFileName -LinePadding 1
    Write-Log -Message "Changes Role: Kms Encrypt, Decrypt, ReEncrypt*, GenerateDataKey* and DescribeKey permissions to '$Role' rule" -LogFileName $script:LogFileName -Indent 2
    
    if ($CustomMessage -ne $null)
    {
        Write-Log -Message $CustomMessage -LogFileName $script:LogFileName -LinePadding 1
    }

    Write-Log -Message "Executing: aws kms get-key-policy --policy-name default --key-id $KeyId" -LogFileName $script:LogFileName -Severity Verbose
    $currentKmsPolicy = aws kms get-key-policy --policy-name default --key-id $KeyId
    
    if ($null -ne $currentKmsPolicy)
    {
        $kmsRequiredPoliciesObject = $RequiredPolicy | ConvertFrom-Json 
        $currentKmsPolicyObject = $currentKmsPolicy | ConvertFrom-Json 	
        $currentKmsPolicies = ($currentKmsPolicyObject.Policy) | ConvertFrom-Json
        
        $kmsRequiredPoliciesMissingInCurrentPolicy =  $kmsRequiredPoliciesObject.Statement | Where-Object { ($_ | ConvertTo-Json -Depth 5) -notin ($currentKmsPolicies.Statement | ForEach-Object { $_ | ConvertTo-Json -Depth 5}  )}
        if ($null -ne $kmsRequiredPoliciesMissingInCurrentPolicy)
        {
            $currentKmsPolicies.Statement += $kmsRequiredPoliciesMissingInCurrentPolicy

            $UpdatedKmsPolicyObject = ($currentKmsPolicies | ConvertTo-Json -Depth 16).Replace('"','\"')
            Write-Log -Message "Executing: aws kms put-key-policy --policy-name default --key-id $KeyId --policy $UpdatedKmsPolicyObject | Out-Null" -LogFileName $script:LogFileName -Severity Verbose
            aws kms put-key-policy --policy-name default --key-id $KeyId --policy $UpdatedKmsPolicyObject | Out-Null
        }
    }
    else
    {
        $newKmsPolicyObject = ($RequiredPolicy | ConvertFrom-Json |  ConvertTo-Json -Depth 16).Replace('"','\"')
        Write-Log -Message "Executing: aws kms put-key-policy --policy-name default --key-id $KeyId --policy $newKmsPolicyObject | Out-Null" -LogFileName $script:LogFileName -Severity Verbose
        aws kms put-key-policy --policy-name default --key-id $KeyId --policy $newKmsPolicyObject | Out-Null
    }
}