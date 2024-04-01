#include "include/Attestation.h"

#include <vector>
#include <string>


#define TPM_STATIC_CONFIG_QUOTE_KEYS L"SYSTEM\\CurrentControlSet\\Services\\Tpm\\PlatformQuoteKeys"
#define TPM_STATIC_CONFIG_KEYATTEST_KEYS L"SYSTEM\\CurrentControlSet\\Services\\Tpm\\KeyAttestationKeys"

#define LAK L"lak"
#define LDEVID L"ldevid"

NCRYPT_PROV_HANDLE provHandle;
NCRYPT_KEY_HANDLE lakHandle;
NCRYPT_KEY_HANDLE ldevidHandle;

#define LOG(message) std::cout<<message<<std::endl

std::ostream& operator<<(std::ostream& os, std::vector<unsigned char> buffer) {
	for (int i = 0; i < buffer.size(); i++) {
		if (i) printf(" ");
		printf("%02x", buffer[i]);
	}
	return os;
}

void FinishConnection() {
	NCryptFreeObject(lakHandle);
	NCryptFreeObject(ldevidHandle);
	NCryptFreeObject(provHandle);
	exit(0);
}

#define Error(status, stage);\
	if (status != 0){\
		LOG("Error "<< stage<<": " <<std::hex<<status);\
		FinishConnection();\
	}\

void StartConnection() {
	Error(NCryptOpenStorageProvider(&provHandle, MS_PLATFORM_CRYPTO_PROVIDER, 0), "OpenStorage");
}

void CreateLAK() {

	DWORD keyUsage = NCRYPT_PCP_IDENTITY_KEY;

	Error(NCryptCreatePersistedKey(provHandle, &lakHandle, NCRYPT_RSA_ALGORITHM, LAK, 0, NCRYPT_OVERWRITE_KEY_FLAG), "CreateLAK");

	Error(NCryptSetProperty(lakHandle, NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY, (PBYTE)&keyUsage, sizeof(keyUsage), 0), "SetProperty (Identity Key)");

	Error(NCryptFinalizeKey(lakHandle, 0), "FinalizeKey");
}

void RegisterLAK() {

	Error(NCryptOpenKey(provHandle, &lakHandle, LAK, 0, 0), "OpenLAK");

	DWORD bufferSize = NULL;

	Error(NCryptExportKey(lakHandle, NULL, BCRYPT_OPAQUE_KEY_BLOB, NULL, NULL, NULL, &bufferSize, 0), "ExportKey (1)");

	std::vector<unsigned char> pbLAK(bufferSize);

	Error(NCryptExportKey(lakHandle, NULL, BCRYPT_OPAQUE_KEY_BLOB, NULL, pbLAK.data(), pbLAK.size(), &bufferSize, 0), "ExportKey (2)");

	HKEY hKey = NULL;

	Error(RegCreateKeyW(HKEY_LOCAL_MACHINE, TPM_STATIC_CONFIG_QUOTE_KEYS, &hKey),"Open the reg");

	Error(RegSetValueExW(hKey, LAK, NULL, REG_BINARY, pbLAK.data(), pbLAK.size()), "Set as trust point generation"); 

	RegCloseKey(hKey);
	hKey = NULL;

	Error(RegCreateKeyW(HKEY_LOCAL_MACHINE, TPM_STATIC_CONFIG_KEYATTEST_KEYS, &hKey), "Open the reg");

	Error(RegSetValueExW(hKey, LAK, NULL, REG_BINARY, pbLAK.data(), pbLAK.size()), "Set as trust point generation");

	LOG("Key LAK registered!");

}

void CreateLDevID() {

	Error(NCryptCreatePersistedKey(provHandle, &ldevidHandle, NCRYPT_RSA_ALGORITHM, LDEVID, 0, NCRYPT_OVERWRITE_KEY_FLAG), "Create LDEVID");

	DWORD keyUsage = AT_SIGNATURE;

	Error(NCryptSetProperty(ldevidHandle, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&keyUsage, sizeof(keyUsage), 0), "Setproperty");

	Error(NCryptFinalizeKey(ldevidHandle, 0), "Finalize key");

	LOG("Key LDEVID created!");
}

std::vector<unsigned char> Certify() {

	Error(NCryptOpenKey(provHandle, &lakHandle, LAK, 0, 0), "Open LAK");

	Error(NCryptOpenKey(provHandle, &ldevidHandle, LDEVID, 0, 0), "Open LDEVID");

	UINT32 cbAttestation = 0;

	Error(TpmAttGenerateKeyAttestation(lakHandle,
		ldevidHandle,
		NULL,
		0,
		NULL,
		0,
		&cbAttestation), "First certify");

	std::vector<unsigned char> pbAttestation(cbAttestation);

	Error(TpmAttGenerateKeyAttestation(lakHandle,
		ldevidHandle,
		NULL,
		0,
		pbAttestation.data(),
		pbAttestation.size(),
		&cbAttestation), "Second certify");

	LOG("Certify done!");
	LOG("Certify bytes:\n"<<pbAttestation);

	return pbAttestation;
}

void ValidateCertify(std::vector<unsigned char> certify) {

	DWORD cbLAK = NULL;

	Error(NCryptOpenKey(provHandle, &lakHandle, LAK, 0, 0), "Open LAK");

	Error(NCryptExportKey(lakHandle,NULL,BCRYPT_RSAPUBLIC_BLOB, NULL,NULL,NULL,&cbLAK, NULL), "Get LAK public key (1)");

	std::vector<unsigned char> pbLAK(cbLAK);

	Error(NCryptExportKey(lakHandle,
		NULL,
		BCRYPT_RSAPUBLIC_BLOB,
		NULL,
		pbLAK.data(),
		pbLAK.size(),
		&cbLAK, 0), "Get LAK public key (2)");

	BCRYPT_ALG_HANDLE hAlg = NULL;

	Error(BCryptOpenAlgorithmProvider(&hAlg,
		BCRYPT_RSA_ALGORITHM,
		MS_PRIMITIVE_PROVIDER,
		0), "Open rsa algorithm");

	BCRYPT_KEY_HANDLE lak = NULL;

	Error(BCryptImportKeyPair(hAlg,
				NULL,
				BCRYPT_RSAPUBLIC_BLOB,
				&lak,
				pbLAK.data(),
				pbLAK.size(),
				0), "Import LAK public key");

	Error(TpmAttValidateKeyAttestation(lak,
		NULL,
		0,
		certify.data(),
		certify.size(),
		0,
		0,
		NULL,
		0), "Validate certify");

	BCryptDestroyKey(lak);
	BCryptCloseAlgorithmProvider(hAlg,0);
	LOG("Certify validated!");
}

int main() {

	StartConnection();

	//CreateLAK();

	//RegisterLAK();
	
	//CreateLDevID();

	LOG("Creating the attestation blob...");
	auto certify = Certify();

	LOG("Validating the attestation blob...");
	ValidateCertify(certify);

	FinishConnection();

	return 0;
}
