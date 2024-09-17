#include <windows.h>
#include <winternl.h>

PEB GetProcessPEB(HANDLE hProcess);
HMODULE GetProcessBaseAddress(HANDLE hProcess);
IMAGE_NT_HEADERS ReadModuleHeaders(HANDLE hProcess, HMODULE hModule);
void RunToEntryPoint(HANDLE hProcess, HANDLE hThread);
HMODULE FindModuleInProcess(HANDLE hProcess, LPCWSTR moduleName);
FARPROC FindFunctionInProcess(HANDLE hProcess, HMODULE hModule, LPCSTR functionName);
void LoadModuleInProcess(HANDLE hProcess, LPCWSTR moduleName);