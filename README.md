**RoadMap for Understanding LAK and LDEVID Certification Process**

This README provides a step-by-step guide to understanding the link between the LAK (Local Attestation Key) and LDEVID (Local Device ID), and how the certification process works.

### 1. Create the LAK
- Open a connection with the Platform Crypto Provider (PCP).
- Create a temporary handle for the LAK, setting the dwFlag to NCRYPT_OVERWRITE_KEY_FLAG.
- Define a policy set:
  - Use NCryptSetProperty with NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY to set the policy to NCRYPT_PCP_IDENTITY_KEY.
- Finalize the key creation process.

### 2. Register as a Machine Key
- Open a connection with the Platform Crypto Provider (PCP).
- Open the LAK and obtain its handle.
- Export the LAK to a BCRYPT_OPAQUE_KEY_BLOB structure.
- Register as a trust point generation for performing quotes and other attestation procedures:
  - Open a connection with the Windows Registry using HKEY_LOCAL_MACHINE under the TPM_STATIC_CONFIG_QUOTE_KEYS property.
  - Use the handle obtained above to set the exported LAK blob.
- Register as a key attestation generation:
  - Open a connection with the Windows Registry using HKEY_LOCAL_MACHINE under the TPM_STATIC_CONFIG_KEYATTEST_KEYS property.
  - Use the handle obtained above to set the exported LAK blob.
- Free all handles and buffers used in the process.

### 3. Create the LDEVID
- Open a connection with the Platform Crypto Provider (PCP).
- Create a temporary handle for the LDEVID, setting the dwFlags to NCRYPT_OVERWRITE_KEY_FLAG.
- Set a keyUsage property to restrict the LDEVID to sign operations only.
- Finalize the key creation process and free all handles and buffers used.

This roadmap provides a clear path to understanding how to create and register LAK and LDEVID keys, as well as their significance in the certification process.