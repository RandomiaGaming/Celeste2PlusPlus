#include <windows.h>
#include <tlhelp32.h>
#include <winternl.h>
#include <psapi.h>
#include <detours.h>
#include <iostream>
#include <sstream>
#include "EzError.h"
using namespace std;
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

typedef struct _SYSTEM_MODULE {
	PVOID Reserved[2];
	PVOID Base;
	PVOID EntryPoint;
	ULONG Size;
	ULONG Flags;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;
typedef struct _SYSTEM_MODULE_INFORMATION {
	ULONG ModulesCount;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;
typedef NTSTATUS(NTAPI* NtQuerySystemInformationFn)(SYSTEM_INFORMATION_CLASS SystemInformationClass, PVOID SystemInformation, ULONG SystemInformationLength, PULONG ReturnLength);
HMODULE FindModuleInProcess2(HANDLE hProcess, LPCWSTR moduleName) {
	HMODULE hNtdll = GetModuleHandle(L"ntdll.dll");
	if (!hNtdll) return NULL;

	NtQuerySystemInformationFn NtQuerySystemInformation = (NtQuerySystemInformationFn)GetProcAddress(hNtdll, "NtQuerySystemInformation");
	if (!NtQuerySystemInformation) return NULL;

	ULONG bufferSize = 0x10000; // Initial buffer size
	PVOID buffer = malloc(bufferSize);
	if (!buffer) return NULL;

	ULONG returnLength = 0;
	NTSTATUS status = NtQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &returnLength);
	if (status == STATUS_INFO_LENGTH_MISMATCH) {
		free(buffer);
		bufferSize = returnLength;
		buffer = malloc(bufferSize);
		if (!buffer) return NULL;
		status = NtQuerySystemInformation(SystemModuleInformation, buffer, bufferSize, &returnLength);
	}

	if (status != STATUS_SUCCESS) {
		free(buffer);
		return NULL;
	}

	PSYSTEM_MODULE_INFORMATION moduleInfo = (PSYSTEM_MODULE_INFORMATION)buffer;
	for (ULONG i = 0; i < moduleInfo->ModulesCount; ++i) {
		PSYSTEM_MODULE module = &moduleInfo->Modules[i];
		if (module->Base && module->ModuleNameOffset) {
			// Ensure the module name is properly null-terminated
			WCHAR moduleNameBuffer[256];
			mbstowcs_s(NULL, moduleNameBuffer, (const char*)module->ImageName, sizeof(module->ImageName));

			// Compare the module name
			if (_wcsicmp(moduleNameBuffer, moduleName) == 0) {
				free(buffer);
				return (HMODULE)module->Base;
			}
		}
	}

	free(buffer);
	return NULL;
}
HMODULE FindModuleInProcess(HANDLE hProcess, LPCWSTR moduleName) {

	MODULEINFO moduleInfo = { };
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProcess));
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	MODULEENTRY32 moduleEntry = { };
	moduleEntry.dwSize = sizeof(MODULEENTRY32);
	if (Module32First(hSnapshot, &moduleEntry)) {
		do {
			if (strcmpLowerW(moduleName, moduleEntry.szModule)) {
				CloseHandleSafely(hSnapshot);
				return moduleEntry.hModule;
			}
		} while (Module32Next(hSnapshot, &moduleEntry));
	}

	if (GetLastError() != ERROR_NO_MORE_FILES) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	CloseHandleSafely(hSnapshot);
	throw EzError(L"Specified module could not be found in the remote process.", __FILE__, __LINE__);
}
FARPROC FindFunctionInProcess(HANDLE hProcess, HMODULE hModule, LPCSTR functionName) {
	MEMORY_BASIC_INFORMATION memInfo = { };
	if (!VirtualQueryEx(hProcess, hModule, &memInfo, sizeof(MEMORY_BASIC_INFORMATION))) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(memInfo.AllocationBase);
	IMAGE_DOS_HEADER dosHeader = { };
	if (!ReadProcessMemory(hProcess, pDosHeader, &dosHeader, sizeof(IMAGE_DOS_HEADER), NULL)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}
	if (dosHeader.e_magic != 0x5A4D) {
		throw EzError(L"Bad MZ magic.", __FILE__, __LINE__);
	}

	PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(memInfo.AllocationBase) + dosHeader.e_lfanew);
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

	if (ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size < sizeof(IMAGE_EXPORT_DIRECTORY)) {
		throw EzError(L"hModule did not contain an export table.", __FILE__, __LINE__);
	}
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = reinterpret_cast<PIMAGE_EXPORT_DIRECTORY>(reinterpret_cast<BYTE*>(memInfo.AllocationBase) + ntHeaders.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	IMAGE_EXPORT_DIRECTORY exportDirectory = { };
	if (!ReadProcessMemory(hProcess, pExportDirectory, &exportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), NULL)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	PDWORD pNames = reinterpret_cast<PDWORD>(reinterpret_cast<BYTE*>(memInfo.AllocationBase) + exportDirectory.AddressOfNames);
	DWORD* names = new DWORD[exportDirectory.NumberOfNames];
	if (!ReadProcessMemory(hProcess, pNames, names, sizeof(DWORD) * exportDirectory.NumberOfNames, NULL)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	PWORD pOrdinals = reinterpret_cast<PWORD>(reinterpret_cast<BYTE*>(memInfo.AllocationBase) + exportDirectory.AddressOfNameOrdinals);
	WORD* ordinals = new WORD[exportDirectory.NumberOfNames];
	if (!ReadProcessMemory(hProcess, pOrdinals, ordinals, sizeof(WORD) * exportDirectory.NumberOfNames, NULL)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	PDWORD pFunctions = reinterpret_cast<PDWORD>(reinterpret_cast<BYTE*>(memInfo.AllocationBase) + exportDirectory.AddressOfFunctions);
	DWORD* functions = new DWORD[exportDirectory.NumberOfFunctions];
	if (!ReadProcessMemory(hProcess, pFunctions, functions, sizeof(DWORD) * exportDirectory.NumberOfFunctions, NULL)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}

	for (DWORD i = 0; i < exportDirectory.NumberOfNames; ++i) {
		PCHAR pName = reinterpret_cast<PCHAR>(reinterpret_cast<BYTE*>(memInfo.AllocationBase) + names[i]);
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

// Replaces all calls to originalFunction with detourFunction. Returns a special pointer which can be used to call originalFunction even after a detour is set.
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
	HMODULE user32Dll = GetModuleHandle(L"User32.dll");
	if (user32Dll == NULL) {
		throw EzError(L"User32.dll could not be found.", __FILE__, __LINE__);
	}

	FARPROC getAsyncKeyState = GetProcAddress(user32Dll, "GetAsyncKeyState");
	if (getAsyncKeyState == NULL) {
		throw EzError(L"GetAsyncKeyState could not be found.", __FILE__, __LINE__);
	}
	GetAsyncKeyStateOriginal = reinterpret_cast<PGetAsyncKeyState>(SetDetour(getAsyncKeyState, GetAsyncKeyStateDetour));

	FARPROC getKeyboardState = GetProcAddress(user32Dll, "GetKeyboardState");
	if (getKeyboardState == NULL) {
		throw EzError(L"GetKeyboardState could not be found.", __FILE__, __LINE__);
	}
	GetKeyboardStateOriginal = reinterpret_cast<PGetKeyboardState>(SetDetour(getKeyboardState, GetKeyboardStateDetour));
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
	// TODO fix error if CREATE_SUSPENDED = TRUE

	try {
		STARTUPINFO si = { };
		si.cb = sizeof(STARTUPINFO);
		GetStartupInfo(&si);
		PROCESS_INFORMATION pi = { };
		if (!CreateProcess(L"D:\\Coding\\C++\\celeste2++\\celeste2++\\Debug\\celeste2.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
			EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
		}

		LoadModuleInProcess(pi.hProcess, L"celeste2++.dll");

		CloseHandleSafely(pi.hThread);
		CloseHandleSafely(pi.hProcess);
	}
	catch (EzError error) {
		error.Print();
	}
	return 0;
}