#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <psapi.h>
#include <detours.h>
#include <iostream>
#include <sstream>
#include "EzError.h"
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "D:/Coding/C++/celeste2++/Detours/lib.X86/detours.lib")

void CloseHandleSafely(HANDLE handle) {
	if (!CloseHandle(handle)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}
}
BOOL strcmpLowerW(LPCWSTR strA, LPCWSTR strB) {
	while (TRUE) {
		if (tolower(*strA) != tolower(*strB)) {
			return FALSE;
		}
		if (*strA == '\0') {
			return TRUE;
		}
		strA++;
		strB++;
	}
}
BOOL strcmpLowerA(LPCSTR strA, LPCSTR strB) {
	while (TRUE) {
		if (tolower(*strA) != tolower(*strB)) {
			return FALSE;
		}
		if (*strA == '\0') {
			return TRUE;
		}
		strA++;
		strB++;
	}
}
BOOL strEndsWithLowerW(LPCWSTR strA, LPCWSTR strB) {
	LPCWSTR strAEnd = strA;
	while (*strAEnd != L'\0') {
		strAEnd++;
	}
	LPCWSTR strBEnd = strB;
	while (*strBEnd != L'\0') {
		strBEnd++;
	}
	while (TRUE) {
		if (tolower(*strAEnd) != tolower(*strBEnd)) {
			return FALSE;
		}
		if (strAEnd == strA || strBEnd == strB) {
			return TRUE;
		}
		strAEnd--;
		strBEnd--;
	}
}
BOOL strEndsWithLowerA(LPCSTR strA, LPCSTR strB) {
	LPCSTR strAEnd = strA;
	while (*strAEnd != '\0') {
		strAEnd++;
	}
	LPCSTR strBEnd = strB;
	while (*strBEnd != '\0') {
		strBEnd++;
	}
	while (TRUE) {
		if (tolower(*strAEnd) != tolower(*strBEnd)) {
			return FALSE;
		}
		if (strAEnd == strA || strBEnd == strB) {
			return TRUE;
		}
		strAEnd--;
		strBEnd--;
	}
}

typedef NTSTATUS(NTAPI* PNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
PEB GetProcessPEB(HANDLE hProcess) {
	HMODULE ntdll = GetModuleHandle(L"ntdll.dll");
	if (ntdll == NULL) {
		ntdll = LoadLibrary(L"ntdll.dll");
		if (ntdll == NULL) {
			EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
		}
	}

	PNtQueryInformationProcess NtQueryInformationProcess = reinterpret_cast<PNtQueryInformationProcess>(GetProcAddress(ntdll, "NtQueryInformationProcess"));
	if (NtQueryInformationProcess == NULL) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	PROCESS_BASIC_INFORMATION pbi = { };
	EzError::ThrowFromNT(NtQueryInformationProcess(hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL));

	PEB peb = { };
	if (!ReadProcessMemory(hProcess, pbi.PebBaseAddress, &peb, sizeof(PEB), NULL)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	return peb;
}
HMODULE GetProcessBaseAddress(HANDLE hProcess) {
	PEB peb = GetProcessPEB(hProcess);

	HMODULE imageBaseAddress = reinterpret_cast<HMODULE>(peb.Reserved3[1]);
	if (imageBaseAddress == NULL) {
		throw EzError(L"PEB.ImageBaseAddress was NULL.", __FILE__, __LINE__);
	}

	return imageBaseAddress;
}
IMAGE_NT_HEADERS ReadModuleHeaders(HANDLE hProcess, HMODULE hModule) {
	PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
	IMAGE_DOS_HEADER dosHeader = { };
	if (!ReadProcessMemory(hProcess, pDosHeader, &dosHeader, sizeof(IMAGE_DOS_HEADER), NULL)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}
	if (dosHeader.e_magic != 0x5A4D) {
		throw EzError(L"Bad MZ magic.", __FILE__, __LINE__);
	}

	PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(hModule) + dosHeader.e_lfanew);
	IMAGE_NT_HEADERS ntHeaders = { };
	if (!ReadProcessMemory(hProcess, pNtHeaders, &ntHeaders, sizeof(IMAGE_NT_HEADERS), NULL)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}
	if (ntHeaders.Signature != 0x00004550) {
		throw EzError(L"Bad PE magic.", __FILE__, __LINE__);
	}
	if (ntHeaders.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR_MAGIC) {
		throw EzError(L"Bad PE Optional magic.", __FILE__, __LINE__);
	}

	return ntHeaders;
}
void RunToEntryPoint(HANDLE hProcess, HANDLE hThread) {
	DWORD processId = GetProcessId(hProcess);
	DWORD threadId = GetThreadId(hThread);

	HMODULE processMainModule = GetProcessBaseAddress(hProcess);

	IMAGE_NT_HEADERS ntHeaders = ReadModuleHeaders(hProcess, processMainModule);

	LPVOID entryPoint = reinterpret_cast<PBYTE>(processMainModule) + ntHeaders.OptionalHeader.AddressOfEntryPoint;

	if (!DebugActiveProcess(processId)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	BYTE originalInstruction = 0;
	if (!ReadProcessMemory(hProcess, entryPoint, &originalInstruction, 1, NULL)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	BYTE newInstruction = 0xCC;
	if (!WriteProcessMemory(hProcess, entryPoint, &newInstruction, 1, NULL)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	if (!FlushInstructionCache(hProcess, entryPoint, 1)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	if (ResumeThread(hThread) == 0xFFFFFFFF) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	DEBUG_EVENT debugEvent = { };
	while (WaitForDebugEvent(&debugEvent, INFINITE)) {
		if (debugEvent.dwProcessId != processId ||
			debugEvent.dwDebugEventCode != EXCEPTION_DEBUG_EVENT ||
			debugEvent.u.Exception.ExceptionRecord.ExceptionCode != EXCEPTION_BREAKPOINT ||
			debugEvent.u.Exception.ExceptionRecord.ExceptionAddress != entryPoint) {
			if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE)) {
				EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
			}
			continue;
		}

		CONTEXT context = { };
		context.ContextFlags = CONTEXT_FULL;
		if (!GetThreadContext(hThread, &context)) {
			EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
		}

		if (!WriteProcessMemory(hProcess, entryPoint, &originalInstruction, 1, NULL)) {
			EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
		}

		if (!FlushInstructionCache(hProcess, entryPoint, 1)) {
			EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
		}

		context.Eip = reinterpret_cast<DWORD>(entryPoint);
		if (!SetThreadContext(hThread, &context)) {
			EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
		}

		if (SuspendThread(hThread) == 0xFFFFFFFF) {
			EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
		}
		if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE)) {
			EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
		}
		break;
	}

	if (!DebugActiveProcessStop(processId)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}
}
HMODULE FindModuleInProcess(HANDLE hProcess, LPCWSTR moduleName) {
	PEB peb = GetProcessPEB(hProcess);
	if (peb.Ldr == NULL) {
		throw EzError(L"The windows loader has not yet completed initialization.", __FILE__, __LINE__);
	}

	PEB_LDR_DATA ldrData = { };
	if (!ReadProcessMemory(hProcess, peb.Ldr, &ldrData, sizeof(PEB_LDR_DATA), NULL)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	LIST_ENTRY* listCurrent = ldrData.InMemoryOrderModuleList.Flink;
	do {
		LDR_DATA_TABLE_ENTRY ldrEntry = {  };
		if (!ReadProcessMemory(hProcess, CONTAINING_RECORD(listCurrent, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &ldrEntry, sizeof(LDR_DATA_TABLE_ENTRY), NULL)) {
			EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
		}

		LPWSTR baseDllName = new WCHAR[ldrEntry.FullDllName.Length];
		if (!ReadProcessMemory(hProcess, ldrEntry.FullDllName.Buffer, baseDllName, ldrEntry.FullDllName.Length * sizeof(WCHAR), nullptr)) {
			EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
		}

		if (strEndsWithLowerW(baseDllName, moduleName)) {
			delete[] baseDllName;
			return (HMODULE)ldrEntry.DllBase;
		}

		delete[] baseDllName;
		listCurrent = ldrEntry.InMemoryOrderLinks.Flink;
	} while (listCurrent != ldrData.InMemoryOrderModuleList.Flink);

	throw EzError(L"The specified module could not be found in the remote process.", __FILE__, __LINE__);
}
FARPROC FindFunctionInProcess(HANDLE hProcess, HMODULE hModule, LPCSTR functionName) {
	IMAGE_NT_HEADERS ntHeaders = ReadModuleHeaders(hProcess, hModule);

	if (ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
		throw EzError(L"hModule did not contain an export table.", __FILE__, __LINE__);
	}
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<BYTE*>(hModule) + ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	IMAGE_EXPORT_DIRECTORY exportDirectory = { };
	if (!ReadProcessMemory(hProcess, pExportDirectory, &exportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), NULL)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	PDWORD pNames = reinterpret_cast<PDWORD>(reinterpret_cast<BYTE*>(hModule) + exportDirectory.AddressOfNames);
	DWORD* names = new DWORD[exportDirectory.NumberOfNames];
	if (!ReadProcessMemory(hProcess, pNames, names, sizeof(DWORD) * exportDirectory.NumberOfNames, NULL)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	PWORD pOrdinals = reinterpret_cast<PWORD>(reinterpret_cast<BYTE*>(hModule) + exportDirectory.AddressOfNameOrdinals);
	WORD* ordinals = new WORD[exportDirectory.NumberOfNames];
	if (!ReadProcessMemory(hProcess, pOrdinals, ordinals, sizeof(WORD) * exportDirectory.NumberOfNames, NULL)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	PDWORD pFunctions = reinterpret_cast<PDWORD>(reinterpret_cast<BYTE*>(hModule) + exportDirectory.AddressOfFunctions);
	DWORD* functions = new DWORD[exportDirectory.NumberOfFunctions];
	if (!ReadProcessMemory(hProcess, pFunctions, functions, sizeof(DWORD) * exportDirectory.NumberOfFunctions, NULL)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	for (DWORD i = 0; i < exportDirectory.NumberOfNames; ++i) {
		PCHAR pName = reinterpret_cast<PCHAR>(reinterpret_cast<BYTE*>(hModule) + names[i]);
		CHAR* name = new CHAR[MAX_PATH];
		SIZE_T nameLength = 0;
		if (!ReadProcessMemory(hProcess, pName, name, sizeof(CHAR) * MAX_PATH, &nameLength)) {
			DWORD errorCode = GetLastError();
			if (errorCode != ERROR_PARTIAL_COPY) {
				EzError::ThrowFromCode(errorCode, __FILE__, __LINE__);
			}
		}
		if (nameLength == 0) {
			EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
		}

		if (strcmpLowerA(functionName, name)) {
			FARPROC output = reinterpret_cast<FARPROC>(reinterpret_cast<BYTE*>(hModule) + functions[ordinals[i]]);
			delete[] name;
			delete[] names;
			delete[] ordinals;
			delete[] functions;
			return output;
		}

		delete[] name;
	}

	delete[] names;
	delete[] ordinals;
	delete[] functions;
	throw EzError(L"The specified function could not be found in the remote process.");
}
void LoadModuleInProcess(HANDLE hProcess, LPCWSTR moduleName) {
	LPVOID pRemoteDllPath = VirtualAllocEx(hProcess, NULL, (lstrlen(moduleName) + 1) * sizeof(WCHAR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (pRemoteDllPath == NULL) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	if (!WriteProcessMemory(hProcess, pRemoteDllPath, moduleName, (lstrlen(moduleName) + 1) * sizeof(WCHAR), NULL)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	HMODULE hKernel32 = FindModuleInProcess(hProcess, L"kernel32.dll");
	if (hKernel32 == NULL) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	FARPROC pLoadLibraryW = FindFunctionInProcess(hProcess, hKernel32, "LoadLibraryW");
	if (pLoadLibraryW == NULL) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(pLoadLibraryW), pRemoteDllPath, 0, NULL);
	if (hThread == INVALID_HANDLE_VALUE) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	if (WaitForSingleObject(hThread, INFINITE) == WAIT_FAILED) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	DWORD exitCode = 0; // exitCode from thread will be low 32 bits of return value from LoadLibraryW
	if (!GetExitCodeThread(hThread, &exitCode)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}
	if (exitCode == NULL) {
		throw EzError(L"LoadLibraryW returned NULL from the remote thread.", __FILE__, __LINE__);
	}

	CloseHandleSafely(hThread);
	if (!VirtualFreeEx(hProcess, pRemoteDllPath, 0 /* Must be 0 for MEM_RELEASE */, MEM_RELEASE)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}
}

PVOID SetDetourForThread(PVOID originalFunction, PVOID detourFunction, HANDLE hThread = INVALID_HANDLE_VALUE) {
	/* KNOWN ISSUE
	Detours.h makes changes to the function's machine code which apply to all threads no matter what.
	The only purpose of DetourUpdateThread is to suspend other threads and ensure their instruction
	pointer is not invalid during the transaction commit. As such calling DetourUpdateThread on the
	current thread causes it to become suspended and therefore deadlocks the program.
	*/
	EzError::ThrowFromCode(DetourTransactionBegin(), __FILE__, __LINE__);
	if (hThread != INVALID_HANDLE_VALUE && GetThreadId(hThread) == GetCurrentThreadId()) {
		EzError::ThrowFromCode(DetourUpdateThread(hThread), __FILE__, __LINE__);
	}
	PVOID swapFunction = originalFunction;
	EzError::ThrowFromCode(DetourAttach(&swapFunction, detourFunction), __FILE__, __LINE__);
	EzError::ThrowFromCode(DetourTransactionCommit(), __FILE__, __LINE__);
	return swapFunction;
}
PVOID SetDetour(PVOID originalFunction, PVOID detourFunction) {
	/* KNOWN ISSUE
	Detours.h does not make copies of thread handles it is given through DetourUpdateThread
	as such you must keep all handles open until after DetourTransationCommit. Failure to do
	so will result in deadlocks because DetourUpdateThread suspends the given thread and it
	will not be resumed until after DetourTransactionCommit.
	*/
	struct ThreadListNode {
		HANDLE threadHandle;
		ThreadListNode* next;
	};
	ThreadListNode* threadList = NULL;

	EzError::ThrowFromCode(DetourTransactionBegin(), __FILE__, __LINE__);
	DWORD currentThreadID = GetCurrentThreadId();

	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	THREADENTRY32 te = { };
	te.dwSize = sizeof(te);
	if (!Thread32First(hSnapshot, &te)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}
	do {
		if (te.th32OwnerProcessID == GetCurrentProcessId() && te.th32ThreadID != currentThreadID) {
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
			if (hThread == INVALID_HANDLE_VALUE) {
				EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
			}
			ThreadListNode* newNode = new ThreadListNode();
			newNode->threadHandle = hThread;
			newNode->next = threadList;
			threadList = newNode;
			EzError::ThrowFromCode(DetourUpdateThread(hThread), __FILE__, __LINE__);
		}
	} while (Thread32Next(hSnapshot, &te));
	if (GetLastError() != ERROR_NO_MORE_FILES) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	PVOID swapFunction = originalFunction;
	EzError::ThrowFromCode(DetourAttach(&swapFunction, detourFunction), __FILE__, __LINE__);
	EzError::ThrowFromCode(DetourTransactionCommit(), __FILE__, __LINE__);

	CloseHandleSafely(hSnapshot);
	while (threadList != NULL) {
		ThreadListNode* currentNode = threadList;
		threadList = currentNode->next;
		CloseHandleSafely(currentNode->threadHandle);
		delete currentNode;
	}
	return swapFunction;
}

typedef SHORT(WINAPI* PGetAsyncKeyState)(int vKey);
PGetAsyncKeyState GetAsyncKeyStateOriginal = NULL;
SHORT WINAPI GetAsyncKeyStateDetour(int vKey) {
	return 0;
}
typedef BOOL(WINAPI* PGetKeyboardState)(PBYTE lpKeyState);
PGetKeyboardState GetKeyboardStateOriginal = NULL;
BOOL WINAPI GetKeyboardStateDetour(PBYTE lpKeyState) {
	BYTE realKeyboardState[256] = { };
	BOOL output = GetKeyboardStateOriginal(realKeyboardState);

	BYTE up = realKeyboardState['W'] | realKeyboardState[VK_UP];
	BYTE down = realKeyboardState['D'] | realKeyboardState[VK_DOWN];
	BYTE left = realKeyboardState['A'] | realKeyboardState[VK_LEFT];
	BYTE right = realKeyboardState['D'] | realKeyboardState[VK_RIGHT];
	BYTE jump = realKeyboardState[VK_SPACE] | realKeyboardState['W'] | realKeyboardState[VK_UP];
	BYTE grapple = realKeyboardState['J'];
	BYTE pause = realKeyboardState[VK_ESCAPE] | realKeyboardState['E'];

	BYTE outputKeyboardState[256] = { };
	outputKeyboardState[VK_UP] = up;
	outputKeyboardState[VK_DOWN] = down;
	outputKeyboardState[VK_LEFT] = left;
	outputKeyboardState[VK_RIGHT] = right;
	outputKeyboardState['Z'] = jump;
	outputKeyboardState['X'] = grapple;
	outputKeyboardState['P'] = pause;

	for (DWORD i = 0; i < 256; i++) {
		lpKeyState[i] = 0;
	}
	return output;
}
void SetDetours() {
	GetAsyncKeyStateOriginal = reinterpret_cast<PGetAsyncKeyState>(SetDetour(GetAsyncKeyState, GetAsyncKeyStateDetour));
	GetKeyboardStateOriginal = reinterpret_cast<PGetKeyboardState>(SetDetour(GetKeyboardState, GetKeyboardStateDetour));
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	try {
		switch (ul_reason_for_call)
		{
		case DLL_PROCESS_ATTACH:
			SetDetours();
			MessageBoxW(NULL, L"Hello world from injected DLL.", L"Hello World", MB_OK);
			break;
		case DLL_THREAD_ATTACH:
			break;
		case DLL_THREAD_DETACH:
			break;
		case DLL_PROCESS_DETACH:
			break;
		}
	}
	catch (EzError error) {
		MessageBoxW(NULL, error._message, L"Error from injected DLL", MB_OK);
		error.Print();
	}
	return TRUE;
}
int main()
{
	// TODO hook GetRawInputData and WM_INPUT
	try {
		STARTUPINFO si = { };
		si.cb = sizeof(STARTUPINFO);
		GetStartupInfo(&si);
		PROCESS_INFORMATION pi = { };
		if (!CreateProcess(L"D:\\Coding\\C++\\celeste2++\\celeste2++\\Debug\\celeste2.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
			EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
		}
		RunToEntryPoint(pi.hProcess, pi.hThread);
		LoadModuleInProcess(pi.hProcess, L"celeste2++.dll");
		if (ResumeThread(pi.hThread) == 0xFFFFFFFF) {
			EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
		}

		CloseHandleSafely(pi.hThread);
		CloseHandleSafely(pi.hProcess);
	}
	catch (EzError error) {
		error.Print();
	}
	return 0;
}