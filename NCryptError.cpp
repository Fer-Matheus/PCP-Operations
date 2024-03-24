#include <string>
#include "NCryptError.h"
#include <winerror.h>

std::string GetStatusMessage(SECURITY_STATUS status) {
    switch (status) {
    case ERROR_SUCCESS:
        return "The operation completed successfully.";
    case NTE_BAD_UID:
        return "Bad UID.";
    case NTE_BAD_HASH:
        return "Bad hash.";
    case NTE_BAD_KEY:
        return "Bad key.";
    case NTE_BAD_LEN:
        return "Bad length.";
    case NTE_BAD_DATA:
        return "Bad data.";
    case NTE_BAD_SIGNATURE:
        return "Invalid signature.";
    case NTE_BAD_VER:
        return "Bad version of provider.";
    case NTE_BAD_ALGID:
        return "Invalid algorithm specified.";
    case NTE_BAD_FLAGS:
        return "Invalid flags specified.";
    case NTE_BAD_TYPE:
        return "Invalid type specified.";
    case NTE_BAD_KEY_STATE:
        return "Key not valid for use in specified state.";
    case NTE_BAD_HASH_STATE:
        return "Hash not valid for use in specified state.";
    case NTE_NO_KEY:
        return "Key does not exist.";
    case NTE_NO_MEMORY:
        return "Insufficient memory available for the operation.";
    case NTE_EXISTS:
        return "Object already exists.";
    case NTE_PERM:
        return "Access denied.";
    case NTE_NOT_FOUND:
        return "Object was not found.";
    case NTE_DOUBLE_ENCRYPT:
        return "Data already encrypted.";
    case NTE_BAD_PROVIDER:
        return "Invalid provider specified.";
    case NTE_BAD_PROV_TYPE:
        return "Invalid provider type specified.";
    case NTE_BAD_PUBLIC_KEY:
        return "Invalid provider public key.";
    case NTE_BAD_KEYSET:
        return "Keyset does not exist.";
    case NTE_PROV_TYPE_NOT_DEF:
        return "Provider type not defined.";
    case NTE_PROV_TYPE_ENTRY_BAD:
        return "Invalid registration for provider type.";
    case NTE_KEYSET_NOT_DEF:
        return "The keyset not defined.";
    case NTE_KEYSET_ENTRY_BAD:
        return "Invalid keyset registration.";
    case NTE_PROV_TYPE_NO_MATCH:
        return "Provider type does not match registered value.";
    case NTE_SIGNATURE_FILE_BAD:
        return "Corrupt digital signature file.";
    case NTE_PROVIDER_DLL_FAIL:
        return "Provider DLL failed to initialize correctly.";
    case NTE_PROV_DLL_NOT_FOUND:
        return "Provider DLL not found.";
    case NTE_BAD_KEYSET_PARAM:
        return "Invalid keyset parameter.";
    case NTE_FAIL:
        return "Internal error occurred.";
    case NTE_SYS_ERR:
        return "Base error occurred.";
    case NTE_BUFFER_TOO_SMALL:
        return "The buffer supplied to a function was too small.";
    case NTE_NOT_SUPPORTED:
        return "The requested operation is not supported.";
    case NTE_NO_MORE_ITEMS:
        return "No more data is available.";
    case NTE_SILENT_CONTEXT:
        return "Provider could not perform the action since the context was acquired as silent.";
    case NTE_TOKEN_KEYSET_STORAGE_FULL:
        return "The security token does not have storage space available for an additional container.";
    case NTE_TEMPORARY_PROFILE:
        return "The profile for the user is a temporary profile.";
    case NTE_FIXEDPARAMETER:
        return "The key parameters could not be set because the CSP uses fixed parameters.";
    case NTE_INVALID_HANDLE:
        return "The supplied handle is invalid.";
    case NTE_INVALID_PARAMETER:
        return "The parameter is incorrect.";
    case NTE_BUFFERS_OVERLAP:
        return "The supplied buffers overlap incorrectly.";
    case NTE_DECRYPTION_FAILURE:
        return "The specified data could not be decrypted.";
    case NTE_INTERNAL_ERROR:
        return "An internal consistency check failed.";
    case NTE_UI_REQUIRED:
        return "This operation requires input from the user.";
    case NTE_HMAC_NOT_SUPPORTED:
        return "The cryptographic provider does not support HMAC.";
    case NTE_DEVICE_NOT_READY:
        return "The device that is required by this cryptographic provider is not ready for use.";
    case NTE_AUTHENTICATION_IGNORED:
        return "The dictionary attack mitigation is triggered and the provided authorization was ignored by the provider.";
    case NTE_VALIDATION_FAILED:
        return "The validation of the provided data failed the integrity or signature validation.";
    case NTE_INCORRECT_PASSWORD:
        return "Incorrect password.";
    case NTE_ENCRYPTION_FAILURE:
        return "Encryption failed.";
    case NTE_DEVICE_NOT_FOUND:
        return "The device that is required by this cryptographic provider is not found on this platform.";
    default:
        return "Unknown status code.";
    }
}
