param(
    [Parameter(Mandatory=$true)]
    [string]$TargetComputer,
    [Parameter(Mandatory=$false)]
    [int]$MinutesBack = 15,
    [Parameter(Mandatory=$false)]
    [string]$PrincipalUser = "Administrator",
    [Parameter(Mandatory=$false)]
    [string]$ServiceFilter = "cifs",
    [Parameter(Mandatory=$false)]
    [string]$SharePattern = "*$"
)

<#
.SYNOPSIS
    Validates EDR detection capabilities for Shadow Credentials attacks
.DESCRIPTION
    Checks for presence of critical security events (5136, 4768, 4769, 5145)
    that indicate Shadow Credentials attack activity. Uses robust XML-based
    event parsing instead of fragile Message field string splitting.
.PARAMETER TargetComputer
    Name of the target computer object (without $ suffix)
.PARAMETER MinutesBack
    How many minutes back to search for events (default: 15)
.EXAMPLE
    .\Validate-ShadowCredentialsEDR.ps1 -TargetComputer "EC2AMAZ-V903HM1"
.NOTES
    Author: Shadow Credentials EDR Verification Framework
    Version: 2.0
    Requires: Run on Domain Controller with appropriate permissions
#>

$ErrorActionPreference = "SilentlyContinue"
$startTime = (Get-Date).AddMinutes(-$MinutesBack)

Write-Output ""
Write-Output "====================================================="
Write-Output "  Shadow Credentials EDR Detection Validation Report"
Write-Output "====================================================="
Write-Output "Target: $TargetComputer"
Write-Output "Period: $startTime to $(Get-Date)"
Write-Output ""

# Validation results
$detectionResults = [ordered]@{
    "Event 5136 (Shadow Credentials Implant)" = $false
    "Event 4768 (PKINIT TGT Request)" = $false
    "Event 4769 (Service Ticket Request)" = $false
    "Event 5145 (File Share Access)" = $false
}

# Function to parse event data using XML (robust, language-independent)
function Get-EventDataValue {
    param(
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$Event,
        [string]$FieldName
    )

    try {
        $xml = [xml]$Event.ToXml()
        $value = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq $FieldName}).'#text'
        return $value
    } catch {
        return $null
    }
}

function Get-EventDataFallback {
    param(
        [System.Diagnostics.Eventing.Reader.EventLogRecord]$Event,
        [string]$PrimaryField,
        [string]$FallbackField
    )
    $v = Get-EventDataValue -Event $Event -FieldName $PrimaryField
    if ([string]::IsNullOrEmpty($v)) {
        $v = Get-EventDataValue -Event $Event -FieldName $FallbackField
    }
    return $v
}

# Check Event 5136: Directory Service Changes
Write-Output "[1/4] Checking Event 5136: Directory Service Modification..."
$evt5136 = Get-WinEvent -FilterHashtable @{LogName='Security';ID=5136;StartTime=$startTime} |
Where-Object {
    $objectDN = Get-EventDataValue -Event $_ -FieldName 'ObjectDN'
    $attributeName = Get-EventDataValue -Event $_ -FieldName 'AttributeLDAPDisplayName'

    $objectDN -like "*$TargetComputer*" -and $attributeName -eq 'msDS-KeyCredentialLink'
}

if ($evt5136) {
    Write-Output "  PASS Event 5136 detected ($($evt5136.Count) event(s))"
    $detectionResults["Event 5136 (Shadow Credentials Implant)"] = $true

    foreach ($evt in $evt5136) {
        $timeCreated = $evt.TimeCreated
        $subjectUser = Get-EventDataValue -Event $evt -FieldName 'SubjectUserName'
        $operationType = Get-EventDataValue -Event $evt -FieldName 'OperationType'

        Write-Output "    $timeCreated - Subject: $subjectUser - Operation: $operationType"
    }
} else {
    Write-Output "  FAIL Event 5136 NOT detected"
    Write-Output "       ACTION: Verify audit policy and SACL configuration"
}

# Check Event 4768: Kerberos TGT Request
Write-Output ""
Write-Output "[2/4] Checking Event 4768: Kerberos TGT Request..."
$evt4768 = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4768;StartTime=$startTime} |
Where-Object {
    $accountName = Get-EventDataFallback -Event $_ -PrimaryField 'AccountName' -FallbackField 'TargetUserName'
    $accountName -like "$TargetComputer*"
}

if ($evt4768) {
    Write-Output "  PASS Event 4768 detected ($($evt4768.Count) event(s))"
    $detectionResults["Event 4768 (PKINIT TGT Request)"] = $true

    $evt4768 | Select-Object -First 3 | ForEach-Object {
        $timeCreated = $_.TimeCreated
        $account = Get-EventDataFallback -Event $_ -PrimaryField 'AccountName' -FallbackField 'TargetUserName'
        $preAuthType = Get-EventDataValue -Event $_ -FieldName 'PreAuthType'

        Write-Output "    $timeCreated - Account: $account - PreAuthType: $preAuthType"
    }
} else {
    Write-Output "  WARN Event 4768 NOT detected or filtered"
}

# Check Event 4769: Service Ticket Request
Write-Output ""
Write-Output "[3/4] Checking Event 4769: Service Ticket Request..."
$evt4769 = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4769;StartTime=$startTime} |
Where-Object {
    $serviceName = Get-EventDataValue -Event $_ -FieldName 'ServiceName'
    $targetUserName = Get-EventDataValue -Event $_ -FieldName 'TargetUserName'

    $serviceName -like "$ServiceFilter*" -or $targetUserName -eq $PrincipalUser
}

if ($evt4769) {
    Write-Output "  PASS Event 4769 detected ($($evt4769.Count) event(s))"
    $detectionResults["Event 4769 (Service Ticket Request)"] = $true

    $evt4769 | Select-Object -First 3 | ForEach-Object {
        $timeCreated = $_.TimeCreated
        $service = Get-EventDataValue -Event $_ -FieldName 'ServiceName'
        $ticketOptions = Get-EventDataValue -Event $_ -FieldName 'TicketOptions'

        Write-Output "    $timeCreated - Service: $service - Options: $ticketOptions"
    }
} else {
    Write-Output "  WARN Event 4769 NOT detected or filtered"
}

# Check Event 5145: Network Share Access
Write-Output ""
Write-Output "[4/4] Checking Event 5145: Network Share Access..."
$evt5145 = Get-WinEvent -FilterHashtable @{LogName='Security';ID=5145;StartTime=$startTime} |
Where-Object {
    $subjectUserName = Get-EventDataValue -Event $_ -FieldName 'SubjectUserName'
    $shareName = Get-EventDataValue -Event $_ -FieldName 'ShareName'

    $subjectUserName -eq $PrincipalUser -and $shareName -like $SharePattern
}

if ($evt5145) {
    Write-Output "  PASS Event 5145 detected ($($evt5145.Count) event(s))"
    $detectionResults["Event 5145 (File Share Access)"] = $true

    $evt5145 | Select-Object -First 3 | ForEach-Object {
        $timeCreated = $_.TimeCreated
        $share = Get-EventDataValue -Event $_ -FieldName 'ShareName'
        $relativePath = Get-EventDataValue -Event $_ -FieldName 'RelativeTargetName'

        Write-Output "    $timeCreated - Share: $share - Path: $relativePath"
    }
} else {
    Write-Output "  WARN Event 5145 NOT detected or filtered"
}

# Calculate score
$passCount = ($detectionResults.Values | Where-Object {$_ -eq $true}).Count
$totalChecks = $detectionResults.Count
$score = [math]::Round(($passCount / $totalChecks) * 100, 0)

# Final Summary
Write-Output ""
Write-Output "====================================================="
Write-Output "  EDR Detection Summary"
Write-Output "====================================================="

foreach ($check in $detectionResults.GetEnumerator()) {
    $status = if ($check.Value) { "PASS" } else { "FAIL" }
    Write-Output "$status $($check.Key)"
}

Write-Output ""
Write-Output "Detection Score: $passCount/$totalChecks ($score%)"

# Interpretation
if ($score -eq 100) {
    Write-Output "Assessment: Excellent coverage - all attack phases detected"
} elseif ($score -ge 75) {
    Write-Output "Assessment: Good coverage - minor gaps present"
} elseif ($score -ge 50) {
    Write-Output "Assessment: Moderate coverage - significant gaps present"
} else {
    Write-Output "Assessment: Poor coverage - major blind spots present"
}

# Recommendations
if ($score -lt 100) {
    Write-Output ""
    Write-Output "RECOMMENDATIONS:"

    if (-not $detectionResults["Event 5136 (Shadow Credentials Implant)"]) {
        Write-Output "  - Enable Directory Service Changes audit policy:"
        Write-Output "    auditpol /set /subcategory:`"Directory Service Changes`" /success:enable"
        Write-Output "  - Configure SACL on sensitive computer objects (see Step 2 in procedure)"
    }

    if (-not $detectionResults["Event 4768 (PKINIT TGT Request)"]) {
        Write-Output "  - Review Kerberos authentication audit settings"
        Write-Output "  - Enable PKINIT-specific logging if available"
    }

    if (-not $detectionResults["Event 4769 (Service Ticket Request)"]) {
        Write-Output "  - Enable Kerberos Service Ticket Operations auditing"
    }

    if (-not $detectionResults["Event 5145 (File Share Access)"]) {
        Write-Output "  - Enable detailed file share auditing:"
        Write-Output "    auditpol /set /subcategory:`"File Share`" /success:enable"
    }
}

# Return structured results for automation
Write-Output ""
return @{
    Score = $score
    PassCount = $passCount
    TotalChecks = $totalChecks
    Results = $detectionResults
    TargetComputer = $TargetComputer
    TimeRange = @{
        Start = $startTime
        End = (Get-Date)
    }
}
