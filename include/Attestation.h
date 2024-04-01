#pragma once

#include <Windows.h>
#include <bcrypt.h>
#include <ncrypt.h>
#include <tbs.h>
#include "../include/InlineFn.h"

#pragma comment(lib,"ncrypt.lib")
#pragma comment(lib,"bcrypt.lib")
#pragma comment(lib,"tbs.lib")

// SHA related constants
#define SHA1_DIGEST_SIZE   (20)
#define SHA256_DIGEST_SIZE (32)

#define MAX_DIGEST_SIZE    (64)

// TPM related constants
#define AVAILABLE_PLATFORM_PCRS (24)

// Key Blob Magic
#define BCRYPT_PCP_KEY_MAGIC 'MPCP' 

#define PCPTYPE_TPM20 0x00000002

#ifndef TPM_API_ALG_ID_SHA1
#define TPM_API_ALG_ID_SHA1         ((UINT16)0x0004)
#endif

#ifndef TPM_API_ALG_ID_SHA256
#define TPM_API_ALG_ID_SHA256       ((UINT16)0x000B)
#endif

// Check for errors
#define FAILED(hr)      (((HRESULT)(hr)) < 0)


#define PCP_KEY_ATTESTATION_MAGIC 'SDAK' // Key Attestation Data Structure
typedef struct _PCP_KEY_ATTESTATION_BLOB {
    ULONG Magic;
    ULONG Platform;
    ULONG HeaderSize;
    ULONG cbKeyAttest;
    ULONG cbSignature;
    ULONG cbKeyBlob;
} PCP_KEY_ATTESTATION_BLOB, * PPCP_KEY_ATTESTATION_BLOB;

typedef struct PCP_KEY_BLOB_WIN8 // Storage structure for 2.0 keys
{
    DWORD   magic;
    DWORD   cbHeader;
    DWORD   pcpType;
    DWORD   flags;
    ULONG   cbPublic;
    ULONG   cbPrivate;
    ULONG   cbMigrationPublic;
    ULONG   cbMigrationPrivate;
    ULONG   cbPolicyDigestList;
    ULONG   cbPCRBinding;
    ULONG   cbPCRDigest;
    ULONG   cbEncryptedSecret;
    ULONG   cbTpm12HostageBlob;
} PCP_KEY_BLOB_WIN8, * PPCP_KEY_BLOB_WIN8;

typedef struct PCP_20_KEY_BLOB // Storage structure for 2.0 keys
{
    DWORD   magic;
    DWORD   cbHeader;
    DWORD   pcpType;
    DWORD   flags;
    ULONG   cbPublic;
    ULONG   cbPrivate;
    ULONG   cbMigrationPublic;
    ULONG   cbMigrationPrivate;
    ULONG   cbPolicyDigestList;
    ULONG   cbPCRBinding;
    ULONG   cbPCRDigest;
    ULONG   cbEncryptedSecret;
    ULONG   cbTpm12HostageBlob;
    USHORT  pcrAlgId;
} PCP_20_KEY_BLOB, * PPCP_20_KEY_BLOB;

// Hard-coded policies
const BYTE defaultUserPolicy[] = { 0x8f, 0xcd, 0x21, 0x69, 0xab, 0x92, 0x69, 0x4e,
                                  0x0c, 0x63, 0x3f, 0x1a, 0xb7, 0x72, 0x84, 0x2b,
                                  0x82, 0x41, 0xbb, 0xc2, 0x02, 0x88, 0x98, 0x1f,
                                  0xc7, 0xac, 0x1e, 0xdd, 0xc1, 0xfd, 0xdb, 0x0e };
const BYTE adminObjectChangeAuthPolicy[] = { 0xe5, 0x29, 0xf5, 0xd6, 0x11, 0x28, 0x72, 0x95,
                                            0x4e, 0x8e, 0xd6, 0x60, 0x51, 0x17, 0xb7, 0x57,
                                            0xe2, 0x37, 0xc6, 0xe1, 0x95, 0x13, 0xa9, 0x49,
                                            0xfe, 0xe1, 0xf2, 0x04, 0xc4, 0x58, 0x02, 0x3a };
const BYTE adminCertifyPolicy[] = { 0xaf, 0x2c, 0xa5, 0x69, 0x69, 0x9c, 0x43, 0x6a,
                                   0x21, 0x00, 0x6f, 0x1c, 0xb8, 0xa2, 0x75, 0x6c,
                                   0x98, 0xbc, 0x1c, 0x76, 0x5a, 0x35, 0x59, 0xc5,
                                   0xfe, 0x1c, 0x3f, 0x5e, 0x72, 0x28, 0xa7, 0xe7 };
const BYTE adminCertifyPolicyNoPin[] = { 0x04, 0x8e, 0x9a, 0x3a, 0xce, 0x08, 0x58, 0x3f,
                                        0x79, 0xf3, 0x44, 0xff, 0x78, 0x5b, 0xbe, 0xa9,
                                        0xf0, 0x7a, 0xc7, 0xfa, 0x33, 0x25, 0xb3, 0xd4,
                                        0x9a, 0x21, 0xdd, 0x51, 0x94, 0xc6, 0x58, 0x50 };
const BYTE adminActivateCredentialPolicy[] = { 0xc4, 0x13, 0xa8, 0x47, 0xb1, 0x11, 0x12, 0xb1,
                                              0xcb, 0xdd, 0xd4, 0xec, 0xa4, 0xda, 0xaa, 0x15,
                                              0xa1, 0x85, 0x2c, 0x1c, 0x3b, 0xba, 0x57, 0x46,
                                              0x1d, 0x25, 0x76, 0x05, 0xf3, 0xd5, 0xaf, 0x53 };

HRESULT
TpmAttiGetTpmVersion(
    _Out_ PUINT32 pTpmVersion
);

HRESULT
TpmAttiShaHash(
    LPCWSTR pszAlgId,
    _In_reads_opt_(cbKey) PBYTE pbKey,
    UINT32 cbKey,
    _In_reads_(cbData) PBYTE pbData,
    UINT32 cbData,
    _Out_writes_to_opt_(cbResult, *pcbResult) PBYTE pbResult,
    UINT32 cbResult,
    _Deref_out_range_(0, cbResult) PUINT32 pcbResult
);

HRESULT
TpmAttGenerateKeyAttestation(
    NCRYPT_KEY_HANDLE hAik,
    NCRYPT_KEY_HANDLE hKey,
    _In_reads_opt_(cbNonce) PBYTE pbNonce,
    UINT32 cbNonce,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Deref_out_range_(0, cbOutput) PUINT32 pcbResult
);

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
);

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
);

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
);

HRESULT
GetNameFromPublic(
    _In_reads_(cbKeyBlob) PBYTE pbKeyBlob,
    UINT32 cbKeyBlob,
    _Out_opt_ LPCWSTR* pNameAlg,
    _Out_writes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    UINT32 cbOutput,
    _Out_ PUINT32 pcbResult
);
