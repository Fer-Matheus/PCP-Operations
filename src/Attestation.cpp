#include "/workspace/HP/PCP-Operations/include/Attestation.h"
#include "/workspace/HP/PCP-Operations/include/InlineFn.h"

// Global hash handles are kept open for performance reasons
BCRYPT_ALG_HANDLE g_hSHA1HashAlg = NULL;
BCRYPT_ALG_HANDLE g_hSHA1HmacAlg = NULL;
BCRYPT_ALG_HANDLE g_hSHA256HashAlg = NULL;
BCRYPT_ALG_HANDLE g_hSHA256HmacAlg = NULL;

HRESULT
TpmAttiGetTpmVersion(
    _Out_ PUINT32 pTpmVersion
)
{
    HRESULT hr = S_OK;
    TPM_DEVICE_INFO info = { 0 };

    if (pTpmVersion == NULL)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    if (FAILED(hr = Tbsi_GetDeviceInfo(sizeof(info), (PVOID)&info)))
    {
        goto Cleanup;
    }

    *pTpmVersion = info.tpmVersion;

Cleanup:
    return hr;
}

HRESULT
TpmAttGenerateKeyAttestation(
    NCRYPT_KEY_HANDLE hAik,
    NCRYPT_KEY_HANDLE hKey,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Deref_out_range_(0, cbOutput) PUINT32 pcbResult
)
{
    HRESULT hr = S_OK;
    NCRYPT_PROV_HANDLE hProv = NULL;
    NCRYPT_PROV_HANDLE hProvKey = NULL;
    UINT32 tpmVersion = 0;
    TBS_HCONTEXT hPlatformTbsHandle = 0;

    UINT32 hPlatformAikHandle = 0;
    BYTE tAikUsageAuthRequired = 0;
    BYTE aikUsageAuth[SHA1_DIGEST_SIZE] = { 0 };

    UINT32 hPlatformKeyHandle = 0;
    BYTE tUsageAuthRequired = 0;
    BYTE usageAuth[SHA1_DIGEST_SIZE] = { 0 };

    UINT32 cbRequired = 0;
    UINT32 cbCertify = 0;
    UINT32 cbSignature = 0;
    UINT32 cbKeyblob = 0;
    PPCP_KEY_ATTESTATION_BLOB pAttestationBlob = (PPCP_KEY_ATTESTATION_BLOB)pbOutput;
    UINT32 cursor = 0;

    // Check the parameters
    if ((pcbResult == NULL) ||
        (hAik == NULL) ||
        (hKey == NULL))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }
    *pcbResult = 0;

    // Get TPM version to select implementation
    if (FAILED(hr = TpmAttiGetTpmVersion(&tpmVersion)))
    {
        goto Cleanup;
    }

    // Obtain the provider handle from the AIK so we can get to the TBS handle
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
        hAik,
        NCRYPT_PROVIDER_HANDLE_PROPERTY,
        (PUCHAR)&hProv,
        sizeof(hProv),
        (PULONG)&cbRequired,
        0))))
    {
        goto Cleanup;
    }

    // Obtain the provider handle from the key and check that both share the same provider handle
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
        hKey,
        NCRYPT_PROVIDER_HANDLE_PROPERTY,
        (PUCHAR)&hProvKey,
        sizeof(hProvKey),
        (PULONG)&cbRequired,
        0))))
    {
        goto Cleanup;
    }

    if (hProv != hProvKey)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Obtain the TBS handle that has been used to load the AIK and the key
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
        hProv,
        NCRYPT_PCP_PLATFORMHANDLE_PROPERTY,
        (PUCHAR)&hPlatformTbsHandle,
        sizeof(hPlatformTbsHandle),
        (PULONG)&cbRequired,
        0))))
    {
        goto Cleanup;
    }

    // Obtain the virtualized AIK TPM key handle that is used by the provider
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
        hAik,
        NCRYPT_PCP_PLATFORMHANDLE_PROPERTY,
        (PUCHAR)&hPlatformAikHandle,
        sizeof(hPlatformAikHandle),
        (PULONG)&cbRequired,
        0))))
    {
        goto Cleanup;
    }

    // Obtain the virtualized TPM key handle that is used by the provider
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
        hKey,
        NCRYPT_PCP_PLATFORMHANDLE_PROPERTY,
        (PUCHAR)&hPlatformKeyHandle,
        sizeof(hPlatformKeyHandle),
        (PULONG)&cbRequired,
        0))))
    {
        goto Cleanup;
    }

    // Obtain the size of the signature from this key
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
        hAik,
        BCRYPT_SIGNATURE_LENGTH,
        (PUCHAR)&cbSignature,
        sizeof(cbSignature),
        (PULONG)&cbRequired,
        0))))
    {
        goto Cleanup;
    }

    // Does the AIK need authorization?
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
        hAik,
        NCRYPT_PCP_PASSWORD_REQUIRED_PROPERTY,
        (PUCHAR)&tAikUsageAuthRequired,
        sizeof(tAikUsageAuthRequired),
        (PULONG)&cbRequired,
        0))))
    {
        goto Cleanup;
    }

    if (tAikUsageAuthRequired != FALSE)
    {
        // Get the usageAuth from the provider
        if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
            hAik,
            NCRYPT_PCP_USAGEAUTH_PROPERTY,
            aikUsageAuth,
            sizeof(aikUsageAuth),
            (PULONG)&cbRequired,
            0))))
        {
            goto Cleanup;
        }
    }

    // Does the key need authorization?
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
        hKey,
        NCRYPT_PCP_PASSWORD_REQUIRED_PROPERTY,
        (PUCHAR)&tUsageAuthRequired,
        sizeof(tUsageAuthRequired),
        (PULONG)&cbRequired,
        0))))
    {
        goto Cleanup;
    }

    if (tUsageAuthRequired != FALSE)
    {
        // Get the usageAuth from the provider
        if (FAILED(hr = HRESULT_FROM_WIN32(NCryptGetProperty(
            hKey,
            NCRYPT_PCP_USAGEAUTH_PROPERTY,
            usageAuth,
            sizeof(usageAuth),
            (PULONG)&cbRequired,
            0))))
        {
            goto Cleanup;
        }
    }

    // Get the size of the key blob
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(
        hKey,
        NULL,
        BCRYPT_OPAQUE_KEY_BLOB,
        NULL,
        NULL,
        0,
        (PULONG)&cbKeyblob,
        0))))
    {
        goto Cleanup;
    }

    if (tpmVersion == TPM_VERSION_20)
    {
        if (FAILED(hr = CertifyKey20(
            hPlatformTbsHandle,
            hPlatformAikHandle,
            (tAikUsageAuthRequired) ? aikUsageAuth : NULL,
            (tAikUsageAuthRequired) ? sizeof(aikUsageAuth) : 0,
            hPlatformKeyHandle,
            (tUsageAuthRequired) ? usageAuth : NULL,
            (tUsageAuthRequired) ? sizeof(usageAuth) : 0,
            pbNonce,
            cbNonce,
            NULL,
            0,
            &cbCertify)))
        {
            goto Cleanup;
        }
    }
    else
    {
        hr = E_FAIL;
        goto Cleanup;
    }

    // Calculate output buffer
    cbRequired = sizeof(PCP_KEY_ATTESTATION_BLOB) +
        cbCertify - cbSignature +
        cbSignature +
        cbKeyblob;

    if ((pbOutput == NULL) || (cbOutput == 0))
    {
        *pcbResult = cbRequired;
        goto Cleanup;
    }

    if (cbOutput < cbRequired)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        *pcbResult = cbRequired;
        goto Cleanup;
    }

    // Create the output structure
    pAttestationBlob->Magic = PCP_KEY_ATTESTATION_MAGIC;
    pAttestationBlob->Platform = tpmVersion;
    pAttestationBlob->HeaderSize = sizeof(PCP_KEY_ATTESTATION_BLOB);
    pAttestationBlob->cbKeyAttest = cbCertify - cbSignature;
    pAttestationBlob->cbSignature = cbSignature;
    pAttestationBlob->cbKeyBlob = cbKeyblob;
    cursor = pAttestationBlob->HeaderSize;

    // Perform key attestation and obtain the certification
    if (tpmVersion == TPM_VERSION_20)
    {
        if (FAILED(hr = CertifyKey20(
            hPlatformTbsHandle,
            hPlatformAikHandle,
            (tAikUsageAuthRequired) ? aikUsageAuth : NULL,
            (tAikUsageAuthRequired) ? sizeof(aikUsageAuth) : 0,
            hPlatformKeyHandle,
            (tUsageAuthRequired) ? usageAuth : NULL,
            (tUsageAuthRequired) ? sizeof(usageAuth) : 0,
            pbNonce,
            cbNonce,
            &pbOutput[cursor],
            pAttestationBlob->cbKeyAttest + pAttestationBlob->cbSignature,
            &cbRequired)))
        {
            goto Cleanup;
        }
        cursor += cbRequired;
    }
    else
    {
        hr = E_FAIL;
        goto Cleanup;
    }

    // Make OACR happy
    if ((cursor + pAttestationBlob->cbKeyBlob) > cbOutput)
    {
        hr = E_FAIL;
        goto Cleanup;
    }

    // Get the key blob
    if (FAILED(hr = HRESULT_FROM_WIN32(NCryptExportKey(
        hKey,
        NULL,
        BCRYPT_OPAQUE_KEY_BLOB,
        NULL,
        &pbOutput[cursor],
        pAttestationBlob->cbKeyBlob,
        (PDWORD)&cbRequired,
        0))))
    {
        goto Cleanup;
    }
    cursor += cbRequired;

    // Return the final size
    *pcbResult = cursor;

Cleanup:
    return hr;
}

HRESULT
CertifyKey20(
    TBS_HCONTEXT hPlatformTbsHandle,
    UINT32 hPlatformAikHandle,
    _In_reads_opt_(cbAikUsageAuth) PBYTE pbAikUsageAuth,
    UINT32 cbAikUsageAuth,
    UINT32 hPlatformKeyHandle,
    _In_reads_opt_(cbKeyUsageAuth) PBYTE pbKeyUsageAuth,
    UINT32 cbKeyUsageAuth,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
)
{
    HRESULT hr = S_OK;
    UINT32 cbRequired = 0;
    BYTE cmd[0x200] = { 0 };
    BYTE rsp[0x200] = { 0 };
    UINT32 cursorCmd = 0;
    UINT32 cursorRsp = 0;
    UINT32 cbRsp = sizeof(rsp);
    UINT32 responseSize = 0;
    UINT32 returnCode = 0;
    PBYTE pbCertify = NULL;
    UINT16 cbCertify = 0;
    UINT16 sigAlg = 0;
    UINT16 sigHashAlg = 0;
    PBYTE pbSignature = NULL;
    UINT16 cbSignature = 0;

    // Check the parameters
    if (pcbResult == NULL)
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Build Certify command buffer
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT16)0x8002))) //TPM_ST_SESSIONS
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT32)0x00000000))) //paramSize
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT32)0x00000148))) //TPM_CC_Certify
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, hPlatformKeyHandle))) //keyHandle
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, hPlatformAikHandle))) //aikHandle
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT32)(2 * sizeof(UINT32) + // authHandle
        2 * sizeof(UINT16) + // nonceNULL
        2 * sizeof(BYTE) +   // sessionAttributes
        2 * sizeof(UINT16) + // passwordSize
        cbKeyUsageAuth +     // authorizationSize
        cbAikUsageAuth))))   // authorizationSize
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT32)0x40000009))) //TPM_RS_PW
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT16)0x0000))) //nonceNULL
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (BYTE)0x00))) //sessionAttributes
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT16)cbKeyUsageAuth))) //passwordSize
    {
        goto Cleanup;
    }
    if (cbKeyUsageAuth != 0)
    {
        if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, pbKeyUsageAuth, cbKeyUsageAuth))) //password
        {
            goto Cleanup;
        }
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT32)0x40000009))) //TPM_RS_PW
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT16)0x0000))) //nonceNULL
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (BYTE)0x00))) //sessionAttributes
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT16)cbAikUsageAuth))) //passwordSize
    {
        goto Cleanup;
    }
    if (cbAikUsageAuth != 0)
    {
        if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, pbAikUsageAuth, cbAikUsageAuth))) //password
        {
            goto Cleanup;
        }
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT16)cbNonce))) //qualifyingDataSize
    {
        goto Cleanup;
    }
    if (cbNonce != 0)
    {
        if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, pbNonce, cbNonce))) //qualifyingData
        {
            goto Cleanup;
        }
    }
    if (FAILED(hr = WriteBigEndian(cmd, sizeof(cmd), &cursorCmd, (UINT16)0x0010))) //TPM_ALG_NULL
    {
        goto Cleanup;
    }

    // Set the command size
    ENDIANSWAP_UINT32TOARRAY(cursorCmd, cmd, 0x0002); // Location of paramSize

    // Send the command to the TPM
    if (FAILED(hr = Tbsip_Submit_Command(hPlatformTbsHandle,
        TBS_COMMAND_LOCALITY_ZERO,
        TBS_COMMAND_PRIORITY_NORMAL,
        cmd,
        cursorCmd,
        rsp,
        &cbRsp)))
    {
        goto Cleanup;
    }

    // Parse the response
    if (FAILED(hr = SkipBigEndian(rsp, cbRsp, &cursorRsp, sizeof(UINT16)))) // skip tag
    {
        goto Cleanup;
    }
    if (FAILED(hr = ReadBigEndian(rsp, cbRsp, &cursorRsp, &responseSize))) // responseSize
    {
        goto Cleanup;
    }
    if (responseSize != cbRsp)
    {
        hr = E_FAIL;
        goto Cleanup;
    }
    if (FAILED(hr = ReadBigEndian(rsp, cbRsp, &cursorRsp, &returnCode))) // ReturnCode
    {
        goto Cleanup;
    }
    if (returnCode != 0)
    {
        hr = E_FAIL;
        goto Cleanup;
    }
    if (FAILED(hr = SkipBigEndian(rsp, cbRsp, &cursorRsp, sizeof(UINT32)))) // paramSize
    {
        goto Cleanup;
    }
    if (FAILED(hr = ReadBigEndian(rsp, cbRsp, &cursorRsp, &cbCertify))) // certifyInfoSize
    {
        goto Cleanup;
    }
    if (FAILED(hr = ReadBigEndian(rsp, cbRsp, &cursorRsp, &pbCertify, cbCertify))) // certifyInfo
    {
        goto Cleanup;
    }
    if (FAILED(hr = ReadBigEndian(rsp, cbRsp, &cursorRsp, &sigAlg))) // sigAlg
    {
        goto Cleanup;
    }
    if (sigAlg != 0x0014) //TPM_ALG_RSASSA_PKCS1v1_5
    {
        hr = E_FAIL;
        goto Cleanup;
    }
    if (FAILED(hr = ReadBigEndian(rsp, cbRsp, &cursorRsp, &sigHashAlg))) // hash == TPM_ALG_SHA
    {
        goto Cleanup;
    }
    if (sigHashAlg != TPM_API_ALG_ID_SHA1) //TPM_ALG_SHA
    {
        hr = E_FAIL;
        goto Cleanup;
    }
    if (FAILED(hr = ReadBigEndian(rsp, cbRsp, &cursorRsp, &cbSignature))) // signatureSize
    {
        goto Cleanup;
    }
    if (FAILED(hr = ReadBigEndian(rsp, cbRsp, &cursorRsp, &pbSignature, cbSignature))) // signatureSize
    {
        goto Cleanup;
    }
    // We ignore the trailing session information in the response - It does not hold any information

    // Calculate Quote output buffer
    cbRequired = cbCertify +      // Certify
        cbSignature;     // Signature
    if ((pbOutput == NULL) || (cbOutput == 0))
    {
        *pcbResult = cbRequired;
        goto Cleanup;
    }
    if (cbOutput < cbRequired)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        *pcbResult = cbRequired;
        goto Cleanup;
    }

    // Generate Quote output
    *pcbResult = 0;
    if (FAILED(hr = WriteBigEndian(pbOutput, cbOutput, pcbResult, pbCertify, cbCertify))) // Certify
    {
        goto Cleanup;
    }
    if (FAILED(hr = WriteBigEndian(pbOutput, cbOutput, pcbResult, pbSignature, cbSignature))) // Signature
    {
        goto Cleanup;
    }
    if (cbOutput < *pcbResult)
    {
        hr = E_FAIL;
        goto Cleanup;
    }

Cleanup:
    return hr;
}

HRESULT
TpmAttValidateKeyAttestation(
    BCRYPT_KEY_HANDLE hAik,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _In_reads_(cbAttestation) PBYTE pbAttestation,
    UINT32 cbAttestation,
    UINT32 pcrMask,
    UINT16 pcrAlgId,
    _In_reads_opt_(cbPcrTable) PBYTE pcrTable,
    UINT32 cbPcrTable
)
{
    HRESULT hr = S_OK;
    PPCP_KEY_ATTESTATION_BLOB pAttestation = (PPCP_KEY_ATTESTATION_BLOB)pbAttestation;
    UINT32 cursor = 0;
    PBYTE pbKeyAttest = NULL;
    UINT32 cbKeyAttest = 0;
    PBYTE pbSignature = NULL;
    UINT32 cbSignature = 0;
    PBYTE pbKeyBlob = NULL;
    UINT32 cbKeyBlob = 0;
    BYTE attestDigest[SHA1_DIGEST_SIZE] = { 0 };
    UINT32 cbAttestDigest = 0;
    BCRYPT_PKCS1_PADDING_INFO pPkcs = { BCRYPT_SHA1_ALGORITHM };

    // Check the parameters
    if ((hAik == NULL) ||
        (pbAttestation == NULL) ||
        (cbAttestation < sizeof(PCP_KEY_ATTESTATION_BLOB)) ||
        (pAttestation->Magic != PCP_KEY_ATTESTATION_MAGIC) ||
        (cbAttestation != (pAttestation->HeaderSize +
            pAttestation->cbKeyAttest +
            pAttestation->cbSignature +
            pAttestation->cbKeyBlob)) ||
        ((pcrTable != NULL) && (cbPcrTable < AVAILABLE_PLATFORM_PCRS * SHA1_DIGEST_SIZE)))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Unpack the attestation blob
    cursor = pAttestation->HeaderSize;
    pbKeyAttest = &pbAttestation[cursor];
    cbKeyAttest = pAttestation->cbKeyAttest;
    cursor += pAttestation->cbKeyAttest;
    pbSignature = &pbAttestation[cursor];
    cbSignature = pAttestation->cbSignature;
    cursor += pAttestation->cbSignature;
    pbKeyBlob = &pbAttestation[cursor];
    cbKeyBlob = pAttestation->cbKeyBlob;
    cursor += pAttestation->cbKeyBlob;

    // Step 1: Calculate the digest of the certify
    if (FAILED(hr = TpmAttiShaHash(
        BCRYPT_SHA1_ALGORITHM,
        NULL,
        0,
        pbKeyAttest,
        cbKeyAttest,
        attestDigest,
        sizeof(attestDigest),
        &cbAttestDigest)))
    {
        goto Cleanup;
    }

    // Step 2: Verify the signature with the public AIK
    if (FAILED(hr = HRESULT_FROM_NT(BCryptVerifySignature(
        hAik,
        &pPkcs,
        attestDigest,
        sizeof(attestDigest),
        pbSignature,
        cbSignature,
        BCRYPT_PAD_PKCS1))))
    {
        goto Cleanup;
    }

    // Step 3: Platform specific verification of nonce, public key name and PCR policy
    if (pAttestation->Platform == TPM_VERSION_20)
    {
        if (FAILED(hr = ValidateKeyAttest20(
            pbKeyAttest,
            cbKeyAttest,
            pbNonce,
            cbNonce,
            pbKeyBlob,
            cbKeyBlob,
            pcrMask,
            pcrAlgId,
            pcrTable)))
        {
            goto Cleanup;
        }
    }
    else
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Congratulations! Everything checks out and the key may be considered trustworthy

Cleanup:
    return hr;
}

HRESULT
    TpmAttiShaHash(
        LPCWSTR pszAlgId,
        _In_reads_opt_(cbKey) PBYTE pbKey,
        UINT32 cbKey,
        _In_reads_(cbData) PBYTE pbData,
        UINT32 cbData,
        _Out_writes_to_opt_(cbResult, *pcbResult) PBYTE pbResult,
        UINT32 cbResult,
        _Deref_out_range_(0, cbResult) PUINT32 pcbResult)
{
    HRESULT hr = S_OK;
    BCRYPT_ALG_HANDLE* phAlg = NULL;
    BCRYPT_ALG_HANDLE  hTempAlg = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    DWORD dwFlags = 0;
    DWORD hashSize = 0;
    DWORD cbHashSize = 0;

    if ((cbKey == 0) || (pbKey == NULL))
    {
        if (wcscmp(pszAlgId, BCRYPT_SHA1_ALGORITHM) == 0)
        {
            phAlg = &g_hSHA1HashAlg;
        }
        else if (wcscmp(pszAlgId, BCRYPT_SHA256_ALGORITHM) == 0)
        {
            phAlg = &g_hSHA256HashAlg;
        }
        else
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }
    }
    else
    {
        if (wcscmp(pszAlgId, BCRYPT_SHA1_ALGORITHM) == 0)
        {
            phAlg = &g_hSHA1HmacAlg;
        }
        else if (wcscmp(pszAlgId, BCRYPT_SHA256_ALGORITHM) == 0)
        {
            phAlg = &g_hSHA256HmacAlg;
        }
        else
        {
            hr = E_INVALIDARG;
            goto Cleanup;
        }
        dwFlags = BCRYPT_ALG_HANDLE_HMAC_FLAG;
    }

    // Open the provider if not already open
    if (*phAlg == NULL)
    {
        if (FAILED(hr = HRESULT_FROM_NT(BCryptOpenAlgorithmProvider(
            &hTempAlg,
            pszAlgId,
            MS_PRIMITIVE_PROVIDER,
            dwFlags))))
        {
            goto Cleanup;
        }

        if (InterlockedCompareExchangePointer((volatile PVOID*)phAlg, (PVOID)hTempAlg, NULL) != NULL)
        {
            BCryptCloseAlgorithmProvider(hTempAlg, 0);
        }
    }

    // Check output buffer size
    if (FAILED(hr = HRESULT_FROM_NT(BCryptGetProperty(
        *phAlg,
        BCRYPT_HASH_LENGTH,
        (PUCHAR)&hashSize,
        sizeof(hashSize),
        &cbHashSize,
        0))))
    {
        goto Cleanup;
    }

    // Size check?
    if ((pbResult == NULL) || (cbResult == 0))
    {
        *pcbResult = hashSize;
        goto Cleanup;
    }
    else if (cbResult < hashSize)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        *pcbResult = hashSize;
        goto Cleanup;
    }

    // Create the hash
    if (FAILED(hr = HRESULT_FROM_NT(BCryptCreateHash(
        *phAlg,
        &hHash,
        NULL,
        0,
        pbKey,
        (ULONG)cbKey,
        0))))
    {
        goto Cleanup;
    }

    // Hash the data
    if (FAILED(hr = HRESULT_FROM_NT(BCryptHashData(
        hHash,
        pbData,
        (ULONG)cbData,
        0))))
    {
        goto Cleanup;
    }

    // Calculate the digest
    if (FAILED(hr = HRESULT_FROM_NT(BCryptFinishHash(
        hHash,
        pbResult,
        (ULONG)cbResult,
        0))))
    {
        goto Cleanup;
    }
    *pcbResult = hashSize;

Cleanup:
    if (hHash != NULL)
    {
        BCryptDestroyHash(hHash);
        hHash = NULL;
    }
    return hr;
}

HRESULT
ValidateKeyAttest20(
    _In_reads_(cbKeyAttest) PBYTE pbKeyAttest,
    UINT32 cbKeyAttest,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _In_reads_(cbKeyAttest) PBYTE pbKeyBlob,
    UINT32 cbKeyBlob,
    UINT32 pcrMask,
    UINT16 pcrAlgId,
    _In_reads_opt_(AVAILABLE_PLATFORM_PCRS* MAX_DIGEST_SIZE) PBYTE pcrTable
)
{
    HRESULT hr = E_FAIL;
    UINT32 cbRequired = 0;
    UINT32 attestCursor = 0;
    UINT32 keyCursor = 0;
    UINT32 magic = 0;
    UINT16 attestType = 0;
    PBYTE pbAttestNonce = NULL;
    UINT16 cbAttestNonce = 0;
    PBYTE pbKeyName = NULL;
    UINT16 cbKeyName = 0;
    BYTE keyNameReference[SHA256_DIGEST_SIZE + sizeof(UINT16)] = { 0 };
    UINT32 PolicyDigestCount = 0;
    PBYTE pbPolicyDigest = NULL;
    UINT16 cbPolicyDigest = 0;
    BYTE userPolicyDigestReference[SHA256_DIGEST_SIZE] = { 0 };
    BYTE policyDigestReference[SHA256_DIGEST_SIZE] = { 0 };
    PBYTE pbKeyAuthPolicy = NULL;
    UINT16 cbKeyAuthPolicy = 0;
    UINT32 cbPolicyOrDigestBuffer = 0;

    // Check parameters
    PPCP_KEY_BLOB_WIN8 pW8Key = (PPCP_KEY_BLOB_WIN8)pbKeyBlob;
    if ((pbKeyAttest == NULL) ||
        (cbKeyAttest == 0) ||
        (pW8Key == NULL) ||
        (cbKeyBlob < sizeof(PCP_KEY_BLOB_WIN8)) ||
        (pW8Key->magic != BCRYPT_PCP_KEY_MAGIC) ||
        (pW8Key->cbHeader < sizeof(PCP_KEY_BLOB_WIN8)) ||
        (pW8Key->pcpType != PCPTYPE_TPM20) ||
        (cbKeyBlob < pW8Key->cbHeader +
            pW8Key->cbPublic +
            pW8Key->cbPrivate +
            pW8Key->cbMigrationPublic +
            pW8Key->cbMigrationPrivate +
            pW8Key->cbPolicyDigestList +
            pW8Key->cbPCRBinding +
            pW8Key->cbPCRDigest +
            pW8Key->cbEncryptedSecret +
            pW8Key->cbTpm12HostageBlob))
    {
        hr = E_INVALIDARG;
        return hr;
    }

    // Parse and validate the attestation
    if (FAILED(hr = ReadBigEndian(pbKeyAttest, cbKeyAttest, &attestCursor, &magic))) // magic
    {
        return hr;
    }
    if (magic != 0xff544347) //TPM_GENERATED_VALUE
    {
        hr = E_INVALIDARG;
        return hr;
    }
    if (FAILED(hr = ReadBigEndian(pbKeyAttest, cbKeyAttest, &attestCursor, &attestType))) // type
    {
        return hr;
    }
    if (attestType != 0x8017) //TPM_ST_ATTEST_CERTIFY
    {
        hr = E_INVALIDARG;
        return hr;
    }
    if (FAILED(hr = SkipBigEndian2B(pbKeyAttest, cbKeyAttest, &attestCursor))) // qualifiedSigner
    {
        return hr;
    }
    if (FAILED(hr = ReadBigEndian2B(pbKeyAttest, cbKeyAttest, &attestCursor, &cbAttestNonce, &pbAttestNonce))) // extraData
    {
        return hr;
    }
    if (FAILED(hr = SkipBigEndian(pbKeyAttest, cbKeyAttest, &attestCursor, sizeof(UINT64) +
        sizeof(BYTE) +
        sizeof(UINT32) +
        sizeof(UINT32)))) // TPMS_CLOCK_INFO
    {
        return hr;
    }
    if (FAILED(hr = SkipBigEndian(pbKeyAttest, cbKeyAttest, &attestCursor, sizeof(UINT64)))) // firmwareVersion
    {
        return hr;
    }
    if (FAILED(hr = ReadBigEndian2B(pbKeyAttest, cbKeyAttest, &attestCursor, &cbKeyName, &pbKeyName))) // name
    {
        return hr;
    }
    if (FAILED(hr = SkipBigEndian2B(pbKeyAttest, cbKeyAttest, &attestCursor))) // qualifiedName
    {
        return hr;
    }
    // Ensure that there is no trailing data that has been signed
    if (attestCursor != cbKeyAttest)
    {
        hr = E_INVALIDARG;
        return hr;
    }

    // Get Name from key blob
    if (FAILED(hr = GetNameFromPublic(&pbKeyBlob[pW8Key->cbHeader + sizeof(UINT16)],
        pW8Key->cbPublic - sizeof(UINT16),
        NULL,
        keyNameReference,
        sizeof(keyNameReference),
        &cbRequired)))
    {
        return hr;
    }

    // Step 1: Validate key name
    if ((sizeof(keyNameReference) != cbKeyName) ||
        (memcmp(pbKeyName, keyNameReference, cbKeyName) != 0))
    {
        hr = E_INVALIDARG;
        return hr;
    }

    // Step 2: Check the nonce if requested
    if ((pbNonce != NULL) && (cbNonce != 0) &&
        ((cbNonce != cbAttestNonce) || ((memcmp(pbNonce, pbAttestNonce, cbNonce)) != 0)))
    {
        hr = E_INVALIDARG;
        return hr;
    }

    /*
    We are only going to recognize keys that have been created by the provider with the well known policy model:

    TPM2_PolicyOR(
        // USER policy
        {
            TPM2_PolicyAuthValue(usageAuth)
            TPM2_PolicyPCR(TPML_PCR_SELECTION) // omitted if pcrs = {00000000}
        },
        // Explicit ADMIN policies - only needed when PCRBound but always present
        {
            TPM2_PolicyCommandCode(TPM_CC_ObjectChangeAuth),
            TPM2_PolicyAuthValue(usageAuth)
        },
        {
            // Legacy Auth Policy for TPC_CC_Certify for Windows 8.1
            TPM2_PolicyCommandCode(TPM_CC_Certify),
            TPM2_PolicyAuthValue(usageAuth)
        },
        {
            TPM2_PolicyCommandCode(TPM_CC_ActivateCredential),
            TPM2_PolicyAuthValue(usageAuth)
        },
        {
            // DUPLICATION policy - only present when exportable
            TPM2_PolicyCommandCode(TPMW2_CC_Duplicate)
            TPM2_PolicySecret(migrationIdentity)
        },
        {
            // Auth Policy for TPM_CC_Certify for Windows 10
            TPM2_PolicyCommandCode(TPM_CC_Certify)
        }
        // REMINDER: the eighth policy in this TPM2_PolicyOR tree needs to be another TPM2_PolicyOR
        // See the TCG spec details on TPM2_PolicyOR for more information.
    )
    */

    // Read the policy digest list
    keyCursor = pW8Key->cbHeader +
        pW8Key->cbPublic +
        pW8Key->cbPrivate +
        pW8Key->cbMigrationPublic +
        pW8Key->cbMigrationPrivate;
    if (FAILED(hr = ReadBigEndian(pbKeyBlob, cbKeyBlob, &keyCursor, &PolicyDigestCount)))
    {
        return hr;
    }

    // Only non-exportable keys may be attested so there have to be exactly 4 or 6 policy digests
    // Keys created in Windows 8.1 will have 4 digests
    // Keys created in Windows 10 will have 6, with a zero-length digest in slot 5
    if ((PolicyDigestCount != 0x00000004) &&
        (PolicyDigestCount != 0x00000006))
    {
        hr = E_INVALIDARG;
        return hr;
    }

    // Calculate the user policy with the PCR data, if provided
    if ((pcrTable != NULL) && (pcrMask != 0))
    {
        UINT32 keyBlobPcrMaskCursor = 0;
        UINT32 keyBlobPcrMask = 0;
        UINT32 cbKeyBlobPcrDigest = 0;
        PBYTE pbKeyBlobPcrDigest = NULL;
        BYTE pcrComposite[AVAILABLE_PLATFORM_PCRS * MAX_DIGEST_SIZE] = { 0 };
        UINT32 compositeCursor = 0;
        BYTE pcrCompositeDigestReference[MAX_DIGEST_SIZE] = { 0 };
        UINT32 digestSize = (pcrAlgId == TPM_API_ALG_ID_SHA256) ? SHA256_DIGEST_SIZE : SHA1_DIGEST_SIZE;

        // Get pcr data from key blob
        keyCursor = pW8Key->cbHeader +
            pW8Key->cbPublic +
            pW8Key->cbPrivate +
            pW8Key->cbMigrationPublic +
            pW8Key->cbMigrationPrivate +
            pW8Key->cbPolicyDigestList;
        keyBlobPcrMaskCursor = keyCursor;
        keyBlobPcrMask = (pbKeyBlob[keyCursor]) |
            (pbKeyBlob[keyCursor + 1] << 8) |
            (pbKeyBlob[keyCursor + 2] << 16);
        keyCursor += 3;
        pbKeyBlobPcrDigest = &pbKeyBlob[keyCursor];
        cbKeyBlobPcrDigest = pW8Key->cbPCRDigest;

        // check that PCR algorithm matches
        if ((pW8Key->cbHeader >= sizeof(PCP_20_KEY_BLOB)) &&
            (pcrAlgId != ((PPCP_20_KEY_BLOB)pW8Key)->pcrAlgId))
        {
            hr = E_INVALIDARG;
            return hr;
        }

        // Write all PCRs in the composite that are in the mask
        for (UINT32 n = 0; n < 24; n++)
        {
            if ((pcrMask & (0x00000001 << n)) != 0)
            {
                if (FAILED(hr = WriteBigEndian(pcrComposite, sizeof(pcrComposite), &compositeCursor, &pcrTable[n * digestSize], digestSize)))
                {
                    return hr;
                }
            }
        }

        // Calculate the composite digest
        if (FAILED(hr = TpmAttiShaHash(BCRYPT_SHA256_ALGORITHM, // determined by policy not by algorithm of PCR bank
            NULL,
            0,
            pcrComposite,
            compositeCursor,
            pcrCompositeDigestReference,
            SHA256_DIGEST_SIZE,
            &cbRequired)))
        {
            return hr;
        }

        // Check pcr mask and digest with data in the key blob
        if ((pcrMask != keyBlobPcrMask) ||
            (cbKeyBlobPcrDigest != SHA256_DIGEST_SIZE) ||
            (memcmp(pbKeyBlobPcrDigest, pcrCompositeDigestReference, SHA256_DIGEST_SIZE) != 0))
        {
            hr = E_INVALIDARG;
            return hr;
        }

        // Calculate the user policy with the PCRs
        BYTE policyDigestBuffer[SHA256_DIGEST_SIZE + // policyHash old 
            sizeof(UINT32) +     // TPM_CC_PolicyPCR 
            sizeof(UINT32) +     // TPML_PCR_SELECTION.count
            sizeof(UINT16) +     // TPML_PCR_SELECTION.TPMS_PCR_SELECTION.hash
            sizeof(BYTE) +       // TPML_PCR_SELECTION.TPMS_PCR_SELECTION.sizeofSelect
            3 +                  // pcrSelect
            SHA256_DIGEST_SIZE] = { 0 }; // pcrDigest
        UINT32 policyDigestBufferCursor = 0;

        if (FAILED(hr = WriteBigEndian(policyDigestBuffer, sizeof(policyDigestBuffer), &policyDigestBufferCursor, (PBYTE)defaultUserPolicy, sizeof(defaultUserPolicy)))) // Default user policy digest
        {
            return hr;
        }
        if (FAILED(hr = WriteBigEndian(policyDigestBuffer, sizeof(policyDigestBuffer), &policyDigestBufferCursor, (UINT32)0x0000017F))) // TPM_CC_PolicyPCR
        {
            return hr;
        }
        if (FAILED(hr = WriteBigEndian(policyDigestBuffer, sizeof(policyDigestBuffer), &policyDigestBufferCursor, (UINT32)0x00000001))) // TPML_PCR_SELECTION.count
        {
            return hr;
        }
        if (FAILED(hr = WriteBigEndian(policyDigestBuffer, sizeof(policyDigestBuffer), &policyDigestBufferCursor, pcrAlgId))) // TPML_PCR_SELECTION.TPMS_PCR_SELECTION.hash = TPM_ALG_SHA
        {
            return hr;
        }
        if (FAILED(hr = WriteBigEndian(policyDigestBuffer, sizeof(policyDigestBuffer), &policyDigestBufferCursor, (BYTE)0x03))) // TPML_PCR_SELECTION.TPMS_PCR_SELECTION.sizeofSelect
        {
            return hr;
        }
        if (FAILED(hr = WriteBigEndian(policyDigestBuffer, sizeof(policyDigestBuffer), &policyDigestBufferCursor, &pbKeyBlob[keyBlobPcrMaskCursor], 3))) // TPML_PCR_SELECTION.TPMS_PCR_SELECTION.Select
        {
            return hr;
        }
        if (FAILED(hr = WriteBigEndian(policyDigestBuffer, sizeof(policyDigestBuffer), &policyDigestBufferCursor, pbKeyBlobPcrDigest, cbKeyBlobPcrDigest))) // digest
        {
            return hr;
        }
        if (FAILED(hr = TpmAttiShaHash(BCRYPT_SHA256_ALGORITHM, // determined by policy, not by algorithm of PCR bank
            NULL,
            0,
            policyDigestBuffer,
            sizeof(policyDigestBuffer),
            userPolicyDigestReference,
            sizeof(userPolicyDigestReference),
            &cbRequired)))
        {
            return hr;
        }
    }
    else
    {
        // The caller does not want to verify the PCR information
        // Pick the correct user policy reference digest based on the flags that tell us if this key is PCR bound or not
        keyCursor = pW8Key->cbHeader;
        if (FAILED(hr = SkipBigEndian(pbKeyBlob, cbKeyBlob, &keyCursor, sizeof(UINT16) +  // size
            sizeof(UINT16) +  // keytype
            sizeof(UINT16)))) // nameAlg
        {
            return hr;
        }
        UINT32 keyAttributes = 0;
        if (FAILED(hr = ReadBigEndian(pbKeyBlob, cbKeyBlob, &keyCursor, &keyAttributes)))
        {
            return hr;
        }

        if (keyAttributes & 0x00000040) //userWithAuth
        {
            // Key not bound to PCRs so we proceed with the default policy
            if (memcpy_s(userPolicyDigestReference,
                sizeof(userPolicyDigestReference),
                defaultUserPolicy,
                sizeof(defaultUserPolicy)))
            {
                hr = E_FAIL;
                return hr;
            }

        }
        else
        {
            // Key is bound to PCRs, but the user has not asked to validate them
            // We accept the user policy digest value that is stored in the key
            keyCursor = pW8Key->cbHeader +
                pW8Key->cbPublic +
                pW8Key->cbPrivate +
                pW8Key->cbMigrationPublic +
                pW8Key->cbMigrationPrivate +
                sizeof(UINT32);
            if (FAILED(hr = ReadBigEndian2B(pbKeyBlob, cbKeyBlob, &keyCursor, &cbPolicyDigest, &pbPolicyDigest)))
            {
                return hr;
            }
            if (memcpy_s(userPolicyDigestReference, sizeof(userPolicyDigestReference), pbPolicyDigest, cbPolicyDigest))
            {
                return hr;
            }
        }
    }

    // Step 3: Check the policy digests of each individual branch

    // Read and verify the user policy digest
    keyCursor = pW8Key->cbHeader +
        pW8Key->cbPublic +
        pW8Key->cbPrivate +
        pW8Key->cbMigrationPublic +
        pW8Key->cbMigrationPrivate +
        sizeof(UINT32);

    // Read and compare the user policy
    if (FAILED(hr = ReadBigEndian2B(pbKeyBlob, cbKeyBlob, &keyCursor, &cbPolicyDigest, &pbPolicyDigest)))
    {
        return hr;
    }
    if ((sizeof(userPolicyDigestReference) != cbPolicyDigest) ||
        (memcmp(userPolicyDigestReference, pbPolicyDigest, cbPolicyDigest) != 0))
    {
        hr = E_INVALIDARG;
        return hr;
    }

    // Read and compare the admin policy for ObjectChangeAuth
    if (FAILED(hr = ReadBigEndian2B(pbKeyBlob, cbKeyBlob, &keyCursor, &cbPolicyDigest, &pbPolicyDigest)))
    {
        return hr;
    }
    if ((sizeof(adminObjectChangeAuthPolicy) != cbPolicyDigest) ||
        (memcmp(adminObjectChangeAuthPolicy, pbPolicyDigest, cbPolicyDigest) != 0))
    {
        hr = E_INVALIDARG;
        return hr;
    }

    // Read and compare the admin policy for Certify
    if (FAILED(hr = ReadBigEndian2B(pbKeyBlob, cbKeyBlob, &keyCursor, &cbPolicyDigest, &pbPolicyDigest)))
    {
        return hr;
    }
    if ((sizeof(adminCertifyPolicy) != cbPolicyDigest) ||
        (memcmp(adminCertifyPolicy, pbPolicyDigest, cbPolicyDigest) != 0))
    {
        hr = E_INVALIDARG;
        return hr;
    }

    // Read and compare the admin policy for Certify
    if (FAILED(hr = ReadBigEndian2B(pbKeyBlob, cbKeyBlob, &keyCursor, &cbPolicyDigest, &pbPolicyDigest)))
    {
        return hr;
    }
    if ((sizeof(adminActivateCredentialPolicy) != cbPolicyDigest) ||
        (memcmp(adminActivateCredentialPolicy, pbPolicyDigest, cbPolicyDigest) != 0))
    {
        hr = E_INVALIDARG;
        return hr;
    }

    if (PolicyDigestCount > 4)
    {
        // Windows 10 attestable key policies
        // Read and verify the empty policy for Duplicate
        if (FAILED(hr = ReadBigEndian2B(pbKeyBlob, cbKeyBlob, &keyCursor, &cbPolicyDigest, &pbPolicyDigest)))
        {
            return hr;
        }

        if (0 != cbPolicyDigest)
        {
            hr = E_INVALIDARG;
            return hr;
        }

        // Read and compare the admin policy for Certify (no PIN)
        if (FAILED(hr = ReadBigEndian2B(pbKeyBlob, cbKeyBlob, &keyCursor, &cbPolicyDigest, &pbPolicyDigest)))
        {
            return hr;
        }

        if ((sizeof(adminCertifyPolicyNoPin) != cbPolicyDigest) ||
            (memcmp(adminCertifyPolicyNoPin, pbPolicyDigest, cbPolicyDigest) != 0))
        {
            hr = E_INVALIDARG;
            return hr;
        }
    }

    // Step 4: Calculate the entire policy digest and verify with the digest in the key
    BYTE policyOrDigestBuffer[SHA256_DIGEST_SIZE +              // policyHash old 
        sizeof(UINT32) +                  // TPM_CC_PolicyOR 
        5 * SHA256_DIGEST_SIZE] = { 0 };    // 4 or 5 policyDigests (duplicate policy is zero-length)
    cbPolicyOrDigestBuffer = sizeof(policyOrDigestBuffer);
    if (PolicyDigestCount == 4)
    {
        // Decrease the size of the data to hash by the size of the missing additional policy digest (6. Certify w/o PIN)
        cbPolicyOrDigestBuffer -= SHA256_DIGEST_SIZE;
    }
    UINT32 policyOrDigestBufferCursor = SHA256_DIGEST_SIZE;
    if (FAILED(hr = WriteBigEndian(policyOrDigestBuffer, cbPolicyOrDigestBuffer, &policyOrDigestBufferCursor, (UINT32)0x00000171))) // TPM_CC_PolicyOR
    {
        return hr;
    }
    if (FAILED(hr = WriteBigEndian(policyOrDigestBuffer, cbPolicyOrDigestBuffer, &policyOrDigestBufferCursor, userPolicyDigestReference, sizeof(userPolicyDigestReference))))
    {
        return hr;
    }
    if (FAILED(hr = WriteBigEndian(policyOrDigestBuffer, cbPolicyOrDigestBuffer, &policyOrDigestBufferCursor, (PBYTE)adminObjectChangeAuthPolicy, sizeof(adminObjectChangeAuthPolicy))))
    {
        return hr;
    }
    if (FAILED(hr = WriteBigEndian(policyOrDigestBuffer, cbPolicyOrDigestBuffer, &policyOrDigestBufferCursor, (PBYTE)adminCertifyPolicy, sizeof(adminCertifyPolicy))))
    {
        return hr;
    }
    if (FAILED(hr = WriteBigEndian(policyOrDigestBuffer, cbPolicyOrDigestBuffer, &policyOrDigestBufferCursor, (PBYTE)adminActivateCredentialPolicy, sizeof(adminActivateCredentialPolicy))))
    {
        return hr;
    }

    if (PolicyDigestCount > 4)
    {
        // Add in the hash of the Certify without PIN policy
        if (FAILED(hr = WriteBigEndian(policyOrDigestBuffer, cbPolicyOrDigestBuffer, &policyOrDigestBufferCursor, (PBYTE)adminCertifyPolicyNoPin, sizeof(adminCertifyPolicyNoPin))))
        {
            return hr;
        }
    }

    if (FAILED(hr = TpmAttiShaHash(BCRYPT_SHA256_ALGORITHM,
        NULL,
        0,
        policyOrDigestBuffer,
        cbPolicyOrDigestBuffer,
        policyDigestReference,
        sizeof(policyDigestReference),
        &cbRequired)))
    {
        return hr;
    }

    keyCursor = pW8Key->cbHeader +
        sizeof(UINT16) + //keysize
        sizeof(UINT16) + //type
        sizeof(UINT16) + //nameAlg
        sizeof(UINT32);  //TPMA_OBJECT
    if (FAILED(hr = ReadBigEndian2B(pbKeyBlob, cbKeyBlob, &keyCursor, &cbKeyAuthPolicy, &pbKeyAuthPolicy)))
    {
        return hr;
    }
    if ((cbKeyAuthPolicy != sizeof(policyDigestReference)) ||
        (memcmp(pbKeyAuthPolicy, policyDigestReference, cbKeyAuthPolicy)) != 0)
    {
        hr = E_INVALIDARG;
        return hr;
    }

    // This key checks out!
    hr = S_OK;

}
HRESULT
GetNameFromPublic(
    _In_reads_(cbKeyBlob) PBYTE pbKeyBlob,
    UINT32 cbKeyBlob,
    _Out_opt_ LPCWSTR* pNameAlg,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
)
{
    HRESULT hr = S_OK;
    UINT32 cursor = 0;
    UINT16 nameAlg = 0;
    LPCWSTR szHashAlg = NULL;

    if ((pbKeyBlob == NULL) ||
        (cbKeyBlob == 0) ||
        (pcbResult == NULL))
    {
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    // Make OACR happy
    if (pNameAlg != NULL)
    {
        *pNameAlg = NULL;
    }

    //objectType
    if (FAILED(hr = SkipBigEndian(pbKeyBlob, cbKeyBlob, &cursor, sizeof(UINT16))))
    {
        goto Cleanup;
    }
    // Get the nameAlg of the object
    if (FAILED(hr = ReadBigEndian(pbKeyBlob, cbKeyBlob, &cursor, &nameAlg)))
    {
        goto Cleanup;
    }

    // Select hash algorithm
    switch (nameAlg)
    {
    case TPM_API_ALG_ID_SHA1: //TPM_ALG_SHA1
        szHashAlg = BCRYPT_SHA1_ALGORITHM;
        *pcbResult = SHA1_DIGEST_SIZE;
        break;
    case TPM_API_ALG_ID_SHA256: //TPM_ALG_SHA256
        szHashAlg = BCRYPT_SHA256_ALGORITHM;
        *pcbResult = SHA256_DIGEST_SIZE;
        break;
    default:
        hr = E_INVALIDARG;
        goto Cleanup;
    }

    *pcbResult += sizeof(UINT16);

    // Just a size check?
    if ((pbOutput == NULL) || (cbOutput == 0))
    {
        goto Cleanup;
    }
    else if (cbOutput < *pcbResult)
    {
        hr = HRESULT_FROM_WIN32(ERROR_INSUFFICIENT_BUFFER);
        goto Cleanup;
    }

    // Calculate Object Digest
    if (FAILED(hr = TpmAttiShaHash(szHashAlg,
        NULL,
        0,
        pbKeyBlob,
        cbKeyBlob,
        &pbOutput[sizeof(UINT16)],
        cbOutput - sizeof(UINT16),
        (PUINT32)pcbResult)))
    {
        goto Cleanup;
    }

    *pcbResult += sizeof(UINT16);
    ENDIANSWAP_UINT16TOARRAY(nameAlg, pbOutput, 0);

    if (pNameAlg != NULL)
    {
        *pNameAlg = szHashAlg;
    }

Cleanup:
    return hr;
}
