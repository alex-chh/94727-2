param(
    [Parameter(Mandatory = $false)]
    [string]$DomainDn = (Get-ADDomain).DistinguishedName,
    [Parameter(Mandatory = $false)]
    [string]$DomainFqdn = (Get-ADDomain).DNSRoot,
    [Parameter(Mandatory = $false)]
    [string]$DcComputerName = $env:COMPUTERNAME,
    [Parameter(Mandatory = $false)]
    [string]$TargetComputerName = ""
)

# 頂層保持 Continue，避免意外中斷 transcript
$ErrorActionPreference = "Continue"

$ts = Get-Date -Format "yyyyMMdd_HHmmss"
$outDir = Join-Path -Path $PSScriptRoot -ChildPath "output"
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }
$transcriptPath = Join-Path -Path $outDir -ChildPath ("kdc_pkinit_check_{0}.txt" -f $ts)
Start-Transcript -Path $transcriptPath -Force | Out-Null

function Write-Section([string]$title) {
    Write-Output "`n$('=' * 60)"
    Write-Output $title
    Write-Output "$('=' * 60)"
}

# ---------------------------------------------------------
Write-Section "0. Environment Info"
Write-Output "Computer : $env:COMPUTERNAME"
Write-Output "User     : $env:USERNAME"
Write-Output "Domain   : $DomainFqdn ($DomainDn)"
Write-Output "Time     : $(Get-Date)"

# ---------------------------------------------------------
Write-Section "1. AD Functional Levels"
try {
    $d = Get-ADDomain -Identity $DomainFqdn -ErrorAction Stop
    $f = Get-ADForest -Identity $DomainFqdn -ErrorAction Stop
    Write-Output "Domain Mode : $($d.DomainMode)"
    Write-Output "Forest Mode : $($f.ForestMode)"

    $domainEntry = [ADSI]"LDAP://$DomainDn"
    $forestEntry = [ADSI]"LDAP://CN=Partitions,CN=Configuration,$DomainDn"
    $dBv = $domainEntry.Properties["msDS-Behavior-Version"].Value
    $fBv = $forestEntry.Properties["msDS-Behavior-Version"].Value

    Write-Output "Domain Behavior Version (ADSI): $dBv $(if ($dBv -ge 7) { '✅ OK (>= 2016)' } else { '❌ Too Low (need >= 7)' })"
    Write-Output "Forest Behavior Version (ADSI): $fBv $(if ($fBv -ge 7) { '✅ OK (>= 2016)' } else { '❌ Too Low (need >= 7)' })"
} catch {
    Write-Output "❌ Error checking functional levels: $_"
}

# ---------------------------------------------------------
Write-Section "2. Encryption Types (KDC Registry)"
try {
    $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\KDC"
    $regVal = Get-ItemProperty -Path $regPath -Name "SupportedEncryptionTypes" -ErrorAction SilentlyContinue

    if ($regVal) {
        $val = $regVal.SupportedEncryptionTypes
        Write-Output "Registry SupportedEncryptionTypes: $val (0x$($val.ToString('X')))"

        # 正確 bitmask：AES128 = 0x8, AES256 = 0x10，兩者合計 0x18
        $hasAes128 = ($val -band 0x8)  -eq 0x8
        $hasAes256 = ($val -band 0x10) -eq 0x10
        $hasRC4    = ($val -band 0x4)  -eq 0x4

        Write-Output "  RC4    : $(if ($hasRC4)    { '✅ Enabled' } else { 'Disabled' })"
        Write-Output "  AES128 : $(if ($hasAes128) { '✅ Enabled' } else { '❌ Disabled' })"
        Write-Output "  AES256 : $(if ($hasAes256) { '✅ Enabled' } else { '❌ Disabled' })"

        if ($hasAes128 -and $hasAes256) {
            Write-Output "✅ AES128 + AES256 both supported (PKINIT requirement met)"
        } else {
            Write-Output "❌ AES128 and/or AES256 missing — PKINIT may fail"
        }
    } else {
        Write-Output "⚠️ Registry value 'SupportedEncryptionTypes' NOT FOUND (system default applies)"
        Write-Output "   Default usually includes RC4+AES, but explicit setting is recommended."
    }
} catch {
    Write-Output "❌ Error checking registry: $_"
}

# ---------------------------------------------------------
Write-Section "3. Computer Objects (msDS-SupportedEncryptionTypes)"
$targets = @($DcComputerName)
if ($TargetComputerName -ne "") { $targets += $TargetComputerName }

foreach ($t in $targets) {
    try {
        $comp = Get-ADComputer -Identity $t `
            -Properties msDS-SupportedEncryptionTypes, KerberosEncryptionType, DNSHostName, Enabled `
            -ErrorAction Stop

        Write-Output "`nHost    : $($comp.Name)"
        Write-Output "DNS     : $($comp.DNSHostName)"
        Write-Output "Enabled : $($comp.Enabled)"

        $msDS = $comp."msDS-SupportedEncryptionTypes"
        if ($null -eq $msDS) { $msDS = 0 }
        Write-Output "msDS-SupportedEncryptionTypes : $msDS (0x$($msDS.ToString('X')))"
        Write-Output "KerberosEncryptionType        : $($comp.KerberosEncryptionType -join ', ')"

        # AES128 = 0x8, AES256 = 0x10，兩者合計 0x18
        $aesOk = ($msDS -band 0x18) -eq 0x18
        if ($aesOk) {
            Write-Output "✅ AES128 + AES256 bits set on computer object"
        } else {
            Write-Output "❌ AES bits NOT fully set — run Set-ADComputer -KerberosEncryptionType @('AES128','AES256')"
        }
    } catch {
        Write-Output "❌ Failed to get computer object for '$t': $_"
    }
}

# ---------------------------------------------------------
Write-Section "4. KDC Certificate (LocalMachine\My)"
$kdcOid        = "1.3.6.1.5.2.3.5"   # KDC Authentication
$serverAuthOid = "1.3.6.1.5.5.7.3.1" # Server Authentication (TLS only, NOT for PKINIT)
$kdcCerts      = @()

try {
    $allCerts = Get-ChildItem Cert:\LocalMachine\My -ErrorAction Stop

    # 只取真正具備 KDC Authentication EKU 的憑證
    $kdcCerts = @($allCerts | Where-Object {
        $_.EnhancedKeyUsageList.ObjectId -contains $kdcOid
    })

    if ($kdcCerts.Count -gt 0) {
        Write-Output "✅ Found $($kdcCerts.Count) certificate(s) with KDC Authentication EKU:`n"
        foreach ($c in $kdcCerts) {
            $daysLeft = ($c.NotAfter - (Get-Date)).Days
            $expiryTag = if ($daysLeft -lt 0) { "❌ EXPIRED" }
                         elseif ($daysLeft -le 30) { "⚠️ Expiring in $daysLeft days" }
                         else { "✅ Valid for $daysLeft days" }

            Write-Output "  Thumbprint : $($c.Thumbprint)"
            Write-Output "  Subject    : $($c.Subject)"
            Write-Output "  Issuer     : $($c.Issuer)"
            Write-Output "  EKUs       : $($c.EnhancedKeyUsageList.FriendlyName -join ', ')"
            Write-Output "  HasPrivKey : $($c.HasPrivateKey)"
            Write-Output "  Expiry     : $($c.NotAfter) — $expiryTag"

            # 憑證鏈驗證
            $chain = New-Object System.Security.Cryptography.X509Certificates.X509Chain
            $chainValid = $chain.Build($c)
            if ($chainValid) {
                Write-Output "  Chain      : ✅ Valid"
            } else {
                $chainErrors = $chain.ChainStatus | ForEach-Object { $_.StatusInformation.Trim() }
                Write-Output "  Chain      : ❌ Invalid — $($chainErrors -join '; ')"
            }
            Write-Output ""
        }
    } else {
        Write-Output "❌ No certificate with KDC Authentication EKU (OID $kdcOid) found in LocalMachine\My"
        Write-Output "   PKINIT will NOT work without a valid KDC certificate."
    }

    # 僅供參考：有 Server Auth 但無 KDC Auth 的憑證（不適用於 PKINIT）
    $serverOnlyCerts = @($allCerts | Where-Object {
        ($_.EnhancedKeyUsageList.ObjectId -contains $serverAuthOid) -and
        ($_.EnhancedKeyUsageList.ObjectId -notcontains $kdcOid)
    })
    if ($serverOnlyCerts.Count -gt 0) {
        Write-Output "ℹ️ Found $($serverOnlyCerts.Count) cert(s) with Server Auth EKU only (NOT suitable for PKINIT, listed for reference):"
        foreach ($c in $serverOnlyCerts) {
            Write-Output "   - $($c.Thumbprint) | $($c.Subject)"
        }
    }
} catch {
    Write-Output "❌ Error reading certificate store: $_"
}

# ---------------------------------------------------------
Write-Section "5. NTAuth Store Check (ADSI)"
try {
    $configContext = (Get-ADRootDSE -ErrorAction Stop).ConfigurationNamingContext
    $ntAuthDn = "CN=NTAuthCertificates,CN=Public Key Services,CN=Services,$configContext"

    if ([ADSI]::Exists("LDAP://$ntAuthDn")) {
        $ntAuthEntry = [ADSI]"LDAP://$ntAuthDn"
        $rawCerts    = $ntAuthEntry.Properties["cACertificate"]

        Write-Output "NTAuth DN    : $ntAuthDn"
        Write-Output "NTAuth Certs : $($rawCerts.Count) certificate(s) found"

        if ($kdcCerts.Count -gt 0) {
            # 一次性將 NTAuth 內所有憑證轉為 thumbprint 清單，避免重複迴圈
            $ntAuthThumbs = foreach ($raw in $rawCerts) {
                try {
                    (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(, $raw)).Thumbprint
                } catch {
                    Write-Output "  ⚠️ Could not parse one NTAuth cert entry: $_"
                }
            }

            Write-Output ""
            foreach ($kdcCert in $kdcCerts) {
                if ($ntAuthThumbs -contains $kdcCert.Thumbprint) {
                    Write-Output "✅ MATCH — KDC cert found in NTAuth Store"
                    Write-Output "   Thumbprint : $($kdcCert.Thumbprint)"
                } else {
                    Write-Output "❌ NOT IN NTAuth — KDC cert missing from AD NTAuth Store"
                    Write-Output "   Thumbprint : $($kdcCert.Thumbprint)"
                    Write-Output "   Fix        : certutil -dspublish -f <cert.cer> NTAuthCA"
                }
            }
        } else {
            Write-Output "ℹ️ Skipping thumbprint match — no local KDC certs found in Section 4."
        }
    } else {
        Write-Output "❌ NTAuthCertificates container NOT FOUND at: $ntAuthDn"
        Write-Output "   This is required for PKINIT smart card / certificate logon."
    }
} catch {
    Write-Output "❌ Error checking NTAuth store: $_"
}

# ---------------------------------------------------------
Write-Section "6. KDC Service Status"
try {
    $svc = Get-Service -Name KDC -ErrorAction Stop
    $statusTag = if ($svc.Status -eq 'Running') { '✅' } else { '❌' }
    $startTag  = if ($svc.StartType -eq 'Automatic') { '✅' } else { '⚠️' }
    Write-Output "Status    : $statusTag $($svc.Status)"
    Write-Output "StartType : $startTag $($svc.StartType)"
    Write-Output "DisplayName: $($svc.DisplayName)"
} catch {
    Write-Output "❌ Error checking KDC service: $_"
}

# ---------------------------------------------------------
Write-Section "7. KDC Event Log Errors (Last 10)"
try {
    $events = Get-WinEvent -FilterHashtable @{
        LogName      = 'System'
        ProviderName = 'Microsoft-Windows-Kerberos-Key-Distribution-Center'
        Level        = 2  # Error only
    } -MaxEvents 10 -ErrorAction SilentlyContinue

    if ($events) {
        Write-Output "⚠️ Found $($events.Count) recent KDC error(s):`n"
        $events | Select-Object TimeCreated, Id, Message | Format-List
    } else {
        Write-Output "✅ No recent KDC errors found in System log."
    }
} catch {
    Write-Output "ℹ️ No KDC errors found or log unreadable."
}

# ---------------------------------------------------------
Stop-Transcript | Out-Null
Write-Output "`n✅ Check completed. Output saved to: $transcriptPath"
