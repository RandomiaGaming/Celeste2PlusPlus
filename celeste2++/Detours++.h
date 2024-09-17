#include <Windows.h>

PVOID SetDetourForThread(PVOID originalFunction, PVOID detourFunction, HANDLE hThread = INVALID_HANDLE_VALUE);
PVOID SetDetour(PVOID originalFunction, PVOID detourFunction);