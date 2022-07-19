// dllmain.cpp : Definiert den Einstiegspunkt für die DLL-Anwendung.
#include "pch.h"

#include <iostream>
#include <TlHelp32.h>
#include <Psapi.h>
#include <deque>
#include <string>

#define DECLSPEC_HOTPATCH   __attribute__((__ms_hook_prologue__))

typedef struct _VECTORED_HANDLER_ENTRY
{
	LIST_ENTRY ExecuteHandlerList;
	union
	{
		struct
		{
			ULONG Refs;
			PVOID Handler;
		} Old;
		struct
		{
			PVOID Unknown1;
			ULONG Unknown2;
			PVOID Handler;
		} New;
	};
} VECTORED_HANDLER_ENTRY, * PVECTORED_HANDLER_ENTRY;

typedef struct _VECTORED_HANDLER_LIST
{
	SRWLOCK SrwLock;
	LIST_ENTRY ExecuteHandlerList;
} VECTORED_HANDLER_LIST, * PVECTORED_HANDLER_LIST;

MODULEINFO GetModuleInfo(const char* szModule) {
	MODULEINFO modInfo = { 0 };
	HMODULE hModule = GetModuleHandleA(szModule);
	if (hModule == 0)
		return modInfo;

	GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));
	return modInfo;
}

DWORD SignatureScan(const char* pModule, const char* pSig, const char* mask) {
	MODULEINFO mInfo = GetModuleInfo(pModule);

	DWORD base = (DWORD)mInfo.lpBaseOfDll;
	DWORD size = (DWORD)mInfo.SizeOfImage;

	DWORD patternLength = (DWORD)strlen(mask);

	for (DWORD i = 0; i < size - patternLength; i++) {
		bool bFound = true;
		for (DWORD j = 0; j < patternLength; j++) {
			bFound &= mask[j] == '?' || pSig[j] == *(char*)(base + i + j);
		}

		if (bFound)
			return base + i;
	}
}

LONG __stdcall HackedHandler(EXCEPTION_POINTERS* pExceptionInfo) {
	std::cout << "here";
	int num = rand() % 4;
	if (num == 2 && pExceptionInfo->ContextRecord->Eip != NULL)
		return EXCEPTION_CONTINUE_EXECUTION;

	return EXCEPTION_CONTINUE_SEARCH;
}

LONG __stdcall VEH(EXCEPTION_POINTERS* pExceptionInfo) {
	int num = rand() % 2;
	if (num == 0)
		return EXCEPTION_CONTINUE_EXECUTION;

	return EXCEPTION_CONTINUE_SEARCH;
}

LONG __stdcall VEHHandler23(EXCEPTION_POINTERS* pExceptionInfo) {
	DWORD dwAddr = -1;
	PVOID pExceptAddr = pExceptionInfo->ExceptionRecord->ExceptionAddress;

	// check if we found an exception at a hooked address, if we do change eip and continue execution
	if (dwAddr != -1 && pExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION) {
		pExceptionInfo->ContextRecord->Eip = dwAddr;
		return EXCEPTION_CONTINUE_EXECUTION;
	}

	// if we arrive here, there was no excpetion at a hook, so we let the normal handler deal with it
	return EXCEPTION_CONTINUE_SEARCH;
}

using tRtlAddVectoredHandler = PVOID(NTAPI*)(IN ULONG FirstHandler, IN PVECTORED_EXCEPTION_HANDLER VectoredHandler);

int main() {
	AllocConsole();
	freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
	void* pHandlerCall = reinterpret_cast<void*>(SignatureScan("ntdll.dll", "\x81\xC3\x00\x00\x00\x00\x8D\x7B", "xx????xx"));
	void* pHandlerList = *reinterpret_cast<void**>(SignatureScan("ntdll.dll", "\x81\xC3\x00\x00\x00\x00\x8D\x7B", "xx????xx") + 0x02);

	std::cout << "[+] Handler Call 0x" << pHandlerCall << std::endl;
	std::cout << "[+] Handler List 0x" << pHandlerList << std::endl;

	AddVectoredExceptionHandler(true, VEH);

	PVECTORED_HANDLER_LIST vectored_handler_list_ = reinterpret_cast<PVECTORED_HANDLER_LIST>(pHandlerList);
	PLIST_ENTRY forward_link = vectored_handler_list_->ExecuteHandlerList.Flink;

	int i = 0;
	for (PLIST_ENTRY link = forward_link; link != &vectored_handler_list_->ExecuteHandlerList; link = link->Flink) {
		PVECTORED_HANDLER_ENTRY handler_entry = reinterpret_cast<PVECTORED_HANDLER_ENTRY>(link);
		void* decoded_pointer = (handler_entry->Old.Refs < sizeof(ULONG)) ? DecodePointer(handler_entry->Old.Handler) : DecodePointer(handler_entry->New.Handler);

		std::cout << "	Entry" << "[" << i << "]" << " => 0x" << decoded_pointer << std::endl;

		i++;
	}

	return 0;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        CreateThread(NULL, NULL, LPTHREAD_START_ROUTINE(main), NULL, NULL, NULL);
        return 1;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

