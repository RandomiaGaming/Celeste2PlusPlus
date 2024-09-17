#include "RemoteProcessHelpers.h"
#include "EzError.h"

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

	if (!CloseHandle(hThread)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}
	if (!VirtualFreeEx(hProcess, pRemoteDllPath, 0 /* Must be 0 for MEM_RELEASE */, MEM_RELEASE)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}
}