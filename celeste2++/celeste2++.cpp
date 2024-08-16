#include <windows.h>
#include <detours.h>
#include <tlhelp32.h>
#include <iostream>
using namespace std;
#pragma comment(lib, "D:/Coding/C++/celeste2++/Detours/lib.X86/detours.lib")

HMODULE FindModuleBaseAddress(HANDLE hProcess, const std::wstring& moduleName) {
	MODULEINFO moduleInfo;
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(hProcess));
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		std::cerr << "CreateToolhelp32Snapshot failed with error " << GetLastError() << std::endl;
		return NULL;
	}

	MODULEENTRY32 moduleEntry;
	moduleEntry.dwSize = sizeof(MODULEENTRY32);

	if (Module32First(hSnapshot, &moduleEntry)) {
		do {
			if (moduleName == moduleEntry.szModule) {
				CloseHandle(hSnapshot);
				return moduleEntry.hModule;
			}
		} while (Module32Next(hSnapshot, &moduleEntry));
	}

	CloseHandle(hSnapshot);
	return NULL;
}
FARPROC GetFuncAddressInProc(HANDLE hProcess, HMODULE hModule, const std::string& funcName) {
	// Read the module's base address and other required structures
	MEMORY_BASIC_INFORMATION memInfo;
	if (!VirtualQueryEx(hProcess, hModule, &memInfo, sizeof(memInfo))) {
		std::cerr << "VirtualQueryEx failed with error " << GetLastError() << std::endl;
		return NULL;
	}

	// Read the module's PE header
	PIMAGE_DOS_HEADER pDosHeader;
	if (!ReadProcessMemory(hProcess, memInfo.BaseAddress, &pDosHeader, sizeof(pDosHeader), NULL)) {
		std::cerr << "ReadProcessMemory failed with error " << GetLastError() << std::endl;
		return NULL;
	}

	PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)pDosHeader + pDosHeader->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)pDosHeader + pNtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	DWORD* pNames = (DWORD*)((BYTE*)pDosHeader + pExportDirectory->AddressOfNames);
	WORD* pOrdinals = (WORD*)((BYTE*)pDosHeader + pExportDirectory->AddressOfNameOrdinals);
	DWORD* pFunctions = (DWORD*)((BYTE*)pDosHeader + pExportDirectory->AddressOfFunctions);

	for (DWORD i = 0; i < pExportDirectory->NumberOfNames; ++i) {
		char name[256];
		if (ReadProcessMemory(hProcess, (LPCVOID)((BYTE*)pDosHeader + pNames[i]), &name, sizeof(name), NULL)) {
			if (funcName == name) {
				DWORD funcRva = pFunctions[pOrdinals[i]];
				return (FARPROC)((BYTE*)hModule + funcRva);
			}
		}
	}

	return NULL;
}
FARPROC FindFunctionInRemoteProcess(HANDLE hProcess, const std::wstring& moduleName, const std::string& funcName) {
	HMODULE hModule = FindModuleBaseAddress(hProcess, moduleName);
	if (!hModule) {
		std::cerr << "Failed to find module " << moduleName << std::endl;
		return NULL;
	}

	return GetFuncAddressInProc(hProcess, hModule, funcName);
}
SHORT WINAPI HookGetAsyncKeyState(_In_ int vKey) {
	return 0;
}
void SetDetourForThread(PVOID originalFunc, PVOID hookFunc, HANDLE thread) {
	DetourTransactionBegin();
	PVOID funcAddy = reinterpret_cast<PVOID>(originalFunc);
	DetourAttach(&funcAddy, hookFunc);
	DetourTransactionCommit();
}
void SetDetour(PVOID originalFunc, PVOID hookFunc) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE) {
		std::cout << "CreateToolhelp32Snapshot failed" << std::endl;
		ExitProcess(1);
	}

	THREADENTRY32 te;
	te.dwSize = sizeof(te);

	if (!Thread32First(hSnapshot, &te)) {
		std::cerr << "Thread32First failed with error " << GetLastError() << std::endl;
		ExitProcess(1);
	}

	do {
		if (te.th32OwnerProcessID == GetCurrentProcessId()) {
			HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);
			if (hThread == NULL) {
				std::cerr << "OpenThread failed for Thread ID: " << te.th32ThreadID << std::endl;
				ExitProcess(1);
			}
			SetDetourForThread(originalFunc, hookFunc, hThread);
			CloseHandle(hThread);
		}
	} while (Thread32Next(hSnapshot, &te));

	CloseHandle(hSnapshot);
}
void LoadLibraryInProc(HANDLE hProcess, LPCWSTR dllPath) {
	// Allocate memory in the target process for the DLL path
	LPVOID pRemoteDllPath = VirtualAllocEx(hProcess, NULL, (wcslen(dllPath) + 1) * sizeof(wchar_t), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (!pRemoteDllPath) {
		std::cerr << "VirtualAllocEx failed with error " << GetLastError() << std::endl;
		CloseHandle(hProcess);
		return 1;
	}

	// Write the DLL path to the allocated memory
	if (!WriteProcessMemory(hProcess, pRemoteDllPath, dllPath, (wcslen(dllPath) + 1) * sizeof(wchar_t), NULL)) {
		std::cerr << "WriteProcessMemory failed with error " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return 1;
	}

	// Get the address of LoadLibraryW in the target process
	HMODULE hKernel32 = GetModuleHandle(L"kernel32.dll");
	FARPROC pLoadLibraryW = GetProcAddress(hKernel32, "LoadLibraryW");
	if (!pLoadLibraryW) {
		std::cerr << "GetProcAddress failed with error " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return 1;
	}

	// Create a remote thread in the target process that calls LoadLibraryW
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryW, pRemoteDllPath, 0, NULL);
	if (!hThread) {
		std::cerr << "CreateRemoteThread failed with error " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
		CloseHandle(hProcess);
		return 1;
	}

	// Wait for the remote thread to finish
	WaitForSingleObject(hThread, INFINITE);

	// Clean up
	VirtualFreeEx(hProcess, pRemoteDllPath, 0, MEM_RELEASE);
}
int main()
{
	SetupHook();
	GetAsyncKeyState(10);
	return 0;

	// Launch celeste2.exe suspended
	STARTUPINFO si = { };
	si.cb = sizeof(STARTUPINFO);
	GetStartupInfo(&si);
	PROCESS_INFORMATION pi = { };
	if (!CreateProcess(L"D:\\Coding\\C++\\celeste2++\\x64\\Debug\\celeste2.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
		cout << "Failed to launch celeste2.exe." << endl;
		return 1;
	}

	// Allocate memory for the function in the target process
	HANDLE hProcess = pi.hProcess;
	LPVOID pRemoteFunction = VirtualAllocEx(hProcess, NULL, sizeof(SetupHook), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (!pRemoteFunction) {
		std::cerr << "VirtualAllocEx failed with error " << GetLastError() << std::endl;
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return 1;
	}

	// Write the function into the target process
	if (!WriteProcessMemory(hProcess, pRemoteFunction, (LPCVOID)TargetFunction, sizeof(TargetFunction), NULL)) {
		std::cerr << "WriteProcessMemory failed with error " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, pRemoteFunction, 0, MEM_RELEASE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return 1;
	}

	// Create a remote thread in the target process
	HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteFunction, NULL, 0, NULL);

	if (!hThread) {
		std::cerr << "CreateRemoteThread failed with error " << GetLastError() << std::endl;
		VirtualFreeEx(hProcess, pRemoteFunction, 0, MEM_RELEASE);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		return 1;
	}

	// Wait for the remote thread to complete (optional)
	WaitForSingleObject(hThread, INFINITE);

	// Clean up
	VirtualFreeEx(hProcess, pRemoteFunction, 0, MEM_RELEASE);
	CloseHandle(hThread);



	ResumeThread(pi.hThread);
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);
	return 0;
}