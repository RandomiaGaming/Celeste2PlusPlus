#include "Detours++.h"
#include <detours.h>
#include <tlhelp32.h>
#include "EzError.h"
#pragma comment(lib, "D:/ImportantData/Coding/C++/celeste2++/Detours/lib.X86/detours.lib")

PVOID SetDetourForThread(PVOID originalFunction, PVOID detourFunction, HANDLE hThread) {
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
	DWORD lastError = GetLastError();
	if (lastError != ERROR_NO_MORE_FILES) {
		EzError::ThrowFromCode(lastError, __FILE__, __LINE__);
	}

	PVOID swapFunction = originalFunction;
	EzError::ThrowFromCode(DetourAttach(&swapFunction, detourFunction), __FILE__, __LINE__);
	EzError::ThrowFromCode(DetourTransactionCommit(), __FILE__, __LINE__);

	if (!CloseHandle(hSnapshot)) {
		EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
	}
	while (threadList != NULL) {
		ThreadListNode* currentNode = threadList;
		threadList = currentNode->next;
		if (!CloseHandle(currentNode->threadHandle)) {
			EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
		}
		delete currentNode;
	}
	return swapFunction;
}