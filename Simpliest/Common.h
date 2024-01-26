#pragma once
#include <Windows.h>
#include "Structs.h"

#define HASH(API) _crc32h((char*)API)
#define SET_SYSCALL(NtSys)(SetSSn((DWORD)NtSys.dwSSn,(PVOID)NtSys.pSyscallInstAddress))

#define SEED        0xEDB88320
#define RANGE       255
#define UP			32
#define DOWN		-32

#define NtAllocateVirtualMemory_CRC32	0xE0762FEB
#define NtProtectVirtualMemory_CRC32	0x5C2D1A97
#define NtCreateThreadEx_CRC32			0x2073465A
#define NtWaitForSingleObject_CRC32		0xDD554681

typedef struct _NT_SYSCALL
{
	DWORD dwSSn;
	DWORD dwSyscallHash;
	PVOID pSyscallAddress;
	PVOID pSyscallInstAddress;

}NT_SYSCALL, * PNT_SYSCALL;

typedef struct _NTDLL_CONFIG
{
	PDWORD      pdwArrayOfAddresses;
	PDWORD      pdwArrayOfNames;
	PWORD       pwArrayOfOrdinals;
	DWORD       dwNumberOfNames;
	ULONG_PTR   uModule;

}NTDLL_CONFIG, * PNTDLL_CONFIG;

typedef struct _NTAPI_FUNC
{
	NT_SYSCALL	NtAllocateVirtualMemory;
	NT_SYSCALL	NtProtectVirtualMemory;
	NT_SYSCALL	NtCreateThreadEx;
	NT_SYSCALL	NtWaitForSingleObject;

}NTAPI_FUNC, * PNTAPI_FUNC;

PTEB RtlGetThreadEnvironmentBlock();
BOOL GetImageExportDirectory(PVOID pModuleBase, PIMAGE_EXPORT_DIRECTORY* ppImageExportDirectory);
BOOL FetchNtSyscall(IN DWORD dwSysHash, OUT PNT_SYSCALL pNtSys);