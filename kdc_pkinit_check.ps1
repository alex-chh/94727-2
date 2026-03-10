param(
    [Parameter(Mandatory = $false)]
    [string]$DomainDn = "",

    [Parameter(Mandatory = $false)]
    [string]$DomainFqdn = "",

    [Parameter(Mandatory = $false)]
    [string]$DcComputerName = $env:COMPUTERNAME,

    [Parameter(Mandatory = $false)]
    [string]$TargetComputerName = ""
)

$ErrorActionPreference = "Continue"

$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$outDir = Join-Path -Path $PSScriptRoot -ChildPath "output"
if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
$transcriptPath = Join-Path -Path $outDir -ChildPath ("kdc_pkinit_check_{0}.txt" -f $ts)
Start-Transcript -Path $transcriptPath -Force | Out-Null

function Write-Section([string]$title) {
    Write-Output ""
    Write-Output ("=" * 60)
    Write-Output $title
    Write-Output ("=" * 60)
}

function Write-Skip([string]$reason) {
    Write-Output ("[SKIP] {0}" -f $reason)
}

function Write-Fail([string]$msg) {
    Write-Output ("[FAIL] {0}" -f $msg)
}

function Write-Ok([string]$msg) {
    Write-Output ("[OK] {0}" -f $msg)
}

function Write-Warn([string]$msg) {
    Write-Output ("[WARN] {0}" -f $msg)
}

Write-Section "0. Environment Info"
Write-Output ("Computer : {0}" -f $env:COMPUTERNAME)
Write-Output ("User     : {0}" -f $env:USERNAME)
Write-Output ("Time     : {0}" -f (Get-Date))

$adAvailable = $false
try {
    Import-Module ActiveDirectory -ErrorAction Stop
    $adAvailable = $true
} catch {
    Write-Warn ("ActiveDirectory module not available: {0}" -f $_.Exception.Message)
}

if ($adAvailable -and ([string]::IsNullOrWhiteSpace($DomainFqdn) -or [string]::IsNullOrWhiteSpace($DomainDn))) {
    try {
        $d0 = Get-ADDomain -ErrorAction Stop
        if ([string]::IsNullOrWhiteSpace($DomainFqdn)) { $DomainFqdn = $d0.DNSRoot }
        if ([string]::IsNullOrWhiteSpace($DomainDn)) { $DomainDn = $d0.DistinguishedName }
    } catch {
        Write-Warn ("Could not auto-detect domain info: {0}" -f $_.Exception.Message)
    }
}

if (-not [string]::IsNullOrWhiteSpace($DomainFqdn)) {
    Write-Output ("Domain   : {0}" -f $DomainFqdn)
}
if (-not [string]::IsNullOrWhiteSpace($DomainDn)) {
    Write-Output ("DomainDN : {0}" -f $DomainDn)
}

Write-Section "1. AD Functional Levels"
if (-not $adAvailable) {
    Write-Skip "ActiveDirectory module not available"
} elseif ([string]::IsNullOrWhiteSpace($DomainFqdn) -or [string]::IsNullOrWhiteSpace($DomainDn)) {
    Write-Skip "DomainFqdn/DomainDn not available"
} else {
    try {
        $d = Get-ADDomain -Identity $DomainFqdn -ErrorAction Stop
        $f = Get-ADForest -Identity $DomainFqdn -ErrorAction Stop
        Write-Output ("Domain Mode : {0}" -f $d.DomainMode)
        Write-Output ("Forest Mode : {0}" -f $f.ForestMode)

        $domainEntry = [ADSI]("LDAP://{0}" -f $DomainDn)
        $forestEntry = [ADSI]("LDAP://CN=Partitions,CN=Configuration,{0}" -f $DomainDn)
        $dBv = $domainEntry.Properties["msDS-Behavior-Version"].Value
        $fBv = $forestEntry.Properties["msDS-Behavior-Version"].Value
        Write-Output ("Domain Behavior Version (ADSI): {0} {1}" -f $dBv, $(if ($dBv -ge 7) { "[OK] (>= 2016)" } else { "[FAIL] Too Low (need >= 7)" }))
        Write-Output ("Forest Behavior Version (ADSI): {0} {1}" -f $fBv, $(if ($fBv -ge 7) { "[OK] (>= 2016)" } else { "[FAIL] Too Low (need >= 7)" }))
    } catch {
        Write-Fail ("Error checking functional levels: {0}" -f $_.Exception.Message)
    }
}

Write-Section "2. Encryption Types (KDC Registry)"
try {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\KDC"
    $regVal = Get-ItemProperty -Path $regPath -Name "SupportedEncryptionTypes" -ErrorAction SilentlyContinue
    if ($regVal) {
        $val = [int]$regVal.SupportedEncryptionTypes
        Write-Output ("Registry SupportedEncryptionTypes: {0} (0x{1})" -f $val, $val.ToString("X"))

        $hasAes128 = ($val -band 0x8) -eq 0x8
        $hasAes256 = ($val -band 0x10) -eq 0x10
        $hasRC4 = ($val -band 0x4) -eq 0x4

        Write-Output ("  RC4    : {0}" -f $(if ($hasRC4) { "[OK] Enabled" } else { "Disabled" }))
        Write-Output ("  AES128 : {0}" -f $(if ($hasAes128) { "[OK] Enabled" } else { "[FAIL] Disabled" }))
        Write-Output ("  AES256 : {0}" -f $(if ($hasAes256) { "[OK] Enabled" } else { "[FAIL] Disabled" }))

        if ($hasAes128 -and $hasAes256) {
            Write-Ok "AES128 + AES256 both supported (PKINIT requirement met)"
        } else {
            Write-Fail "AES128 and/or AES256 missing - PKINIT may fail"
        }
    } else {
        Write-Warn "Registry value 'SupportedEncryptionTypes' not found (system default applies)"
        Write-Output "Default usually includes RC4+AES, but explicit setting is recommended."
    }
} catch {
    Write-Fail ("Error checking registry: {0}" -f $_.Exception.Message)
}

Write-Section "3. Computer Objects (msDS-SupportedEncryptionTypes)"
if (-not $adAvailable) {
    Write-Skip "ActiveDirectory module not available"
} else {
    $targets = @()
    if (-not [string]::IsNullOrWhiteSpace($DcComputerName)) { $targets += $DcComputerName }
    if (-not [string]::IsNullOrWhiteSpace($TargetComputerName)) { $targets += $TargetComputerName }
    $targets = $targets | Select-Object -Unique

    foreach ($t in $targets) {
        try {
            $comp = Get-ADComputer -Identity $t -Properties msDS-SupportedEncryptionTypes, KerberosEncryptionType, DNSHostName, Enabled -ErrorAction Stop
            Write-Output ""
            Write-Output ("Host    : {0}" -f $comp.Name)
            Write-Output ("DNS     : {0}" -f $comp.DNSHostName)
            Write-Output ("Enabled : {0}" -f $comp.Enabled)

            $msDS = $comp."msDS-SupportedEncryptionTypes"
            if ($null -eq $msDS) { $msDS = 0 }
            Write-Output ("msDS-SupportedEncryptionTypes : {0} (0x{1})" -f $msDS, ([int]$msDS).ToString("X"))
            Write-Output ("KerberosEncryptionType        : {0}" -f (($comp.KerberosEncryptionType) -join ", "))

            $aesOk = (([int]$msDS -band 0x18) -eq 0x18)
            if ($aesOk) {
                Write-Ok "AES128 + AES256 bits set on computer object"
            } else {
                Write-Fail "AES bits not fully set - run: Set-ADComputer -KerberosEncryptionType @('AES128','AES256')"
            }
        } catch {
            Write-Fail ("Failed to get computer object for '{0}': {1}" -f $t, $_.Exception.Message)
        }
    }
}

Write-Section "4. KDC Certificate (LocalMachine\\My)"
$kdcOid = "1.3.6.1.5.2.3.5"
$serverAuthOid = "1.3.6.1.5.5.7.3.1"
$kdcCerts = @()

try {
    $allCerts = Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop
    $kdcCerts = @($allCerts | Where-Object { $_.EnhancedKeyUsageList.ObjectId -contains $kdcOid })

    if ($kdcCerts.Count -gt 0) {
        Write-Ok ("Found {0} certificate(s) with KDC Authentication EKU" -f $kdcCerts.Count)
        foreach ($c in $kdcCerts) {
            $daysLeft = ($c.NotAfter - (Get-Date)).Days
            $expiryTag = if ($daysLeft -lt 0) { "[FAIL] EXPIRED" } elseif ($daysLeft -le 30) { "[WARN] Expiring in {0} days" -f $daysLeft } else { "[OK] Valid for {0} days" -f $daysLeft }

            Write-Output ""
            Write-Output ("  Thumbprint : {0}" -f $c.Thumbprint)
            Write-Output ("  Subject    : {0}" -f $c.Subject)
            Write-Output ("  Issuer     : {0}" -f $c.Issuer)
            Write-Output ("  EKUs       : {0}" -f ($c.EnhancedKeyUsageList.FriendlyName -join ", "))
            Write-Output ("  HasPrivKey : {0}" -f $c.HasPrivateKey)
            Write-Output ("  Expiry     : {0} - {1}" -f $c.NotAfter, $expiryTag)

            $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
            $chainValid = $chain.Build($c)
            if ($chainValid) {
                Write-Output "  Chain      : [OK] Valid"
            } else {
                $chainErrors = $chain.ChainStatus | ForEach-Object { $_.StatusInformation.Trim() }
                Write-Output ("  Chain      : [FAIL] Invalid - {0}" -f ($chainErrors -join "; "))
            }
        }
    } else {
        Write-Fail ("No certificate with KDC Authentication EKU (OID {0}) found in LocalMachine\\My" -f $kdcOid)
        Write-Output "PKINIT will not work without a valid KDC certificate."
    }

    $serverOnlyCerts = @($allCerts | Where-Object { ($_.EnhancedKeyUsageList.ObjectId -contains $serverAuthOid) -and ($_.EnhancedKeyUsageList.ObjectId -notcontains $kdcOid) })
    if ($serverOnlyCerts.Count -gt 0) {
        Write-Output ""
        Write-Output ("[INFO] Found {0} cert(s) with Server Auth EKU only (not suitable for PKINIT):" -f $serverOnlyCerts.Count)
        foreach ($c in $serverOnlyCerts) {
            Write-Output ("  - {0} | {1}" -f $c.Thumbprint, $c.Subject)
        }
    }
} catch {
    Write-Fail ("Error reading certificate store: {0}" -f $_.Exception.Message)
}

Write-Section "5. NTAuth Store Check (ADSI)"
if (-not $adAvailable) {
    Write-Skip "ActiveDirectory module not available"
} else {
    try {
        $configContext = (Get-ADRootDSE -ErrorAction Stop).ConfigurationNamingContext
        $ntAuthDn = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,{0}" -f $configContext

        if ([ADSI]::Exists(("LDAP://{0}" -f $ntAuthDn))) {
            $ntAuthEntry = [ADSI]("LDAP://{0}" -f $ntAuthDn)
            $rawCerts = $ntAuthEntry.Properties["cACertificate"]
            Write-Output ("NTAuth DN    : {0}" -f $ntAuthDn)
            Write-Output ("NTAuth Certs : {0} certificate(s) found" -f $rawCerts.Count)

            if ($kdcCerts.Count -gt 0) {
                $ntAuthThumbs = foreach ($raw in $rawCerts) {
                    try {
                        (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, $raw)).Thumbprint
                    } catch {
                        Write-Warn ("Could not parse one NTAuth cert entry: {0}" -f $_.Exception.Message)
                    }
                }

                Write-Output ""
                foreach ($kdcCert in $kdcCerts) {
                    if ($ntAuthThumbs -contains $kdcCert.Thumbprint) {
                        Write-Ok "MATCH - KDC cert found in NTAuth store"
                        Write-Output ("  Thumbprint : {0}" -f $kdcCert.Thumbprint)
                    } else {
                        Write-Fail "NOT IN NTAuth - KDC cert missing from AD NTAuth store"
                        Write-Output ("  Thumbprint : {0}" -f $kdcCert.Thumbprint)
                        Write-Output "  Fix        : certutil -dspublish -f <cert.cer> NTAuthCA"
                    }
                }
            } else {
                Write-Output "[INFO] Skipping thumbprint match - no local KDC certs found in Section 4."
            }
        } else {
            Write-Fail ("NTAuthCertificates container not found at: {0}" -f $ntAuthDn)
            Write-Output "This is required for PKINIT smart card / certificate logon."
        }
    } catch {
        Write-Fail ("Error checking NTAuth store: {0}" -f $_.Exception.Message)
    }
}

Write-Section "6. KDC Service Status"
try {
    $svc = Get-Service -Name KDC -ErrorAction Stop
    $statusTag = if ($svc.Status -eq "Running") { "[OK]" } else { "[FAIL]" }
    $startTag = if ($svc.StartType -eq "Automatic") { "[OK]" } else { "[WARN]" }
    Write-Output ("Status     : {0} {1}" -f $statusTag, $svc.Status)
    Write-Output ("StartType  : {0} {1}" -f $startTag, $svc.StartType)
    Write-Output ("DisplayName: {0}" -f $svc.DisplayName)
} catch {
    Write-Warn ("KDC service not found or not accessible: {0}" -f $_.Exception.Message)
}

Write-Section "7. KDC Event Log Errors (Last 10)"
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName      = "System"
        ProviderName = "Microsoft-Windows-Kerberos-Key-Distribution-Center"
        Level        = 2
    } -MaxEvents 10 -ErrorAction SilentlyContinue

    if ($events) {
        Write-Warn ("Found {0} recent KDC error(s):" -f $events.Count)
        $events | Select-Object TimeCreated, Id, Message | Format-List
    } else {
        Write-Ok "No recent KDC errors found in System log."
    }
} catch {
    Write-Warn ("Could not read KDC provider events: {0}" -f $_.Exception.Message)
}

Stop-Transcript | Out-Null
Write-Output ""
Write-Ok ("Check completed. Output saved to: {0}" -f $transcriptPath)
