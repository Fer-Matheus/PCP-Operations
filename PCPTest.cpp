#include <Windows.h>
#include <iostream>
#include <vector>
#include <string>
#include <ncrypt.h>

#pragma comment(lib,"ncrypt.lib")

#define TPM_STATIC_CONFIG_QUOTE_KEYS L"SYSTEM\\CurrentControlSet\\Services\\Tpm\\PlatformQuoteKeys"
#define TPM_STATIC_CONFIG_KEYATTEST_KEYS L"SYSTEM\\CurrentControlSet\\Services\\Tpm\\KeyAttestationKeys"

#define LAK L"lak"
#define LDEVID L"ldevid"

NCRYPT_PROV_HANDLE provHandle;
NCRYPT_KEY_HANDLE keyHandle;

#define LOG(message) std::cout<<message<<std::endl

void FinishConnection() {
	NCryptFreeObject(keyHandle);
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

	Error(NCryptCreatePersistedKey(provHandle, &keyHandle, NCRYPT_RSA_ALGORITHM, LAK, 0, NCRYPT_OVERWRITE_KEY_FLAG), "CreateLAK");

	Error(NCryptSetProperty(keyHandle, NCRYPT_PCP_KEY_USAGE_POLICY_PROPERTY, (PBYTE)&keyUsage, sizeof(keyUsage), 0), "SetProperty (Identity Key)");

	Error(NCryptFinalizeKey(keyHandle, 0), "FinalizeKey");
}

void RegisterLAK() {

	Error(NCryptOpenKey(provHandle, &keyHandle, LAK, 0, 0), "OpenLAK");

	DWORD bufferSize = NULL;

	Error(NCryptExportKey(keyHandle, NULL, BCRYPT_OPAQUE_KEY_BLOB, NULL, NULL, NULL, &bufferSize, 0), "ExportKey (1)");

	std::vector<unsigned char> pbLAK(bufferSize);

	Error(NCryptExportKey(keyHandle, NULL, BCRYPT_OPAQUE_KEY_BLOB, NULL, pbLAK.data(), pbLAK.size(), &bufferSize, 0), "ExportKey (2)");

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

	Error(NCryptCreatePersistedKey(provHandle, &keyHandle, NCRYPT_RSA_ALGORITHM, LDEVID, 0, NCRYPT_OVERWRITE_KEY_FLAG), "Create LDEVID");

	DWORD keyUsage = AT_SIGNATURE;

	Error(NCryptSetProperty(keyHandle, NCRYPT_KEY_USAGE_PROPERTY, (PBYTE)&keyUsage, sizeof(keyUsage), 0), "Setproperty");

	Error(NCryptFinalizeKey(keyHandle, 0), "Finalize key");
}

int main() {

	StartConnection();

	CreateLAK();
	RegisterLAK();
	CreateLDevID();
	FinishConnection();

	return 0;
}
