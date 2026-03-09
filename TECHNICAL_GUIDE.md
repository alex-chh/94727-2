# Technical Guide: Shadow Credentials

## The "Why"
Why do we care about `msDS-KeyCredentialLink`? Because it was designed for Windows Hello for Business (WHfB), but like many "convenience" features, it introduces a massive attack surface when misunderstood.

It allows a user (or machine) to authenticate using a public/private key pair. The public key is stored in the `msDS-KeyCredentialLink` attribute of the user/computer object in AD.

## Data Structure
The `msDS-KeyCredentialLink` attribute stores a `DN-Binary` value. The binary part is a `KEY_CREDENTIAL_LINK_BLOB` structure.

```cpp
struct KEY_CREDENTIAL_LINK_BLOB {
    ULONG Version;
    ULONG Length;
    KEY_CREDENTIAL_ENTRY Entries[];
};
```

This blob contains the raw public key material. When an attacker has write access to this attribute, they can append their own key.

## The Attack Flow

1.  **Write**: Attacker writes a new `KEY_CREDENTIAL_ENTRY` to the target's attribute.
2.  **Request**: Attacker sends an AS-REQ with Pre-Auth Data type 16 (PA-PK-AS-REQ).
3.  **Validate**: KDC looks up the user, parses `msDS-KeyCredentialLink`, finds the matching key.
4.  **Issue**: KDC issues a TGT encrypted with the user's long-term key (or a session key encrypted with the public key? Actually, the reply is encrypted with the session key, which is encrypted with the client's public key in the response, or via Diffie-Hellman).
5.  **Decrypt**: Attacker decrypts the AS-REP using their private key to get the session key and the PAC.
6.  **Profit**: The PAC contains the NTHash (in the PAC_CREDENTIAL_INFO buffer) if the KDC is configured to supply it (which it often is for compatibility).

## EDR Blind Spots
-   **LDAP Traffic**: Most EDRs do not inspect encrypted LDAP traffic (port 636) or even cleartext LDAP (port 389) deeply enough to parse the `msDS-KeyCredentialLink` structure.
-   **Legitimate Feature**: This is a built-in Windows feature. Blocking it breaks WHfB.
-   **Volume**: 5136 events can be noisy.

## Mitigation
-   **SACL**: Audit modification of `msDS-KeyCredentialLink`.
-   **ACL**: Restrict who can write to this attribute.
-   **Monitor**: Watch for 4768 events with PKINIT from unexpected sources (e.g., a workstation authenticating as another workstation).

## Reference
-   [SpecterOps: Shadow Credentials](https://posts.specterops.io/shadow-credentials-abusing-key-trust-account-mapping-for-takeover-8ee1a5351c96)
-   [Whisker](https://github.com/eladshamir/Whisker)
