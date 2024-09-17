#include "RemoteProcessHelpers.h"
#include "Detours++.h"
#include "EzError.h"
#include "SDL_Scancodes.h"
#include <Windows.h>
#include <iostream>

typedef SHORT(WINAPI* PGetAsyncKeyState)(int vKey);
PGetAsyncKeyState GetAsyncKeyStateOriginal = NULL;
SHORT WINAPI GetAsyncKeyStateDetour(int vKey) {
	std::cout << "GetAsyncKeyState called with vKey = " << vKey << std::endl;
	return GetAsyncKeyStateOriginal(vKey);
}

typedef BOOL(WINAPI* PGetKeyboardState)(PBYTE lpKeyState);
PGetKeyboardState GetKeyboardStateOriginal = NULL;
BOOL WINAPI GetKeyboardStateDetour(PBYTE lpKeyState) {
	/*BYTE realKeyboardState[256] = {};
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
	return output;*/

	std::cout << "GetKeyboardState called with lpKeyState = " << reinterpret_cast<void*>(lpKeyState) << std::endl;
	return GetKeyboardStateOriginal(lpKeyState);
}

typedef UINT(WINAPI* PGetRawInputData)(HRAWINPUT hRawInput, UINT uiCommand, LPVOID pData, PUINT pcbSize, UINT cbSizeHeader);
PGetRawInputData GetRawInputDataOriginal = NULL;
UINT WINAPI GetRawInputDataDetour(HRAWINPUT hRawInput, UINT uiCommand, LPVOID pData, PUINT pcbSize, UINT cbSizeHeader) {
	std::cout << "GetRawInputData called with hRawInput = " << reinterpret_cast<void*>(hRawInput)
		<< ", uiCommand = " << uiCommand
		<< ", pData = " << reinterpret_cast<void*>(pData)
		<< ", cbSize = " << reinterpret_cast<void*>(pcbSize)
		<< ", cbSizeHeader = " << cbSizeHeader << std::endl;

	return GetRawInputDataOriginal(hRawInput, uiCommand, pData, pcbSize, cbSizeHeader);
}

typedef UINT(WINAPI* PGetRawInputBuffer)(PRAWINPUT pData, PUINT pcbSize, UINT cbSizeHeader);
PGetRawInputBuffer GetRawInputBufferOriginal = NULL;
UINT WINAPI GetRawInputBufferDetour(PRAWINPUT pData, PUINT pcbSize, UINT cbSizeHeader) {
	std::cout << "GetRawInputBuffer called with pData = " << reinterpret_cast<void*>(pData)
		<< ", pcbSize = " << reinterpret_cast<void*>(pcbSize)
		<< ", cbSizeHeader = " << cbSizeHeader << std::endl;
	return GetRawInputBufferOriginal(pData, pcbSize, cbSizeHeader);
}

typedef LRESULT(WINAPI* PDispatchMessage)(const MSG* lpMsg);
PDispatchMessage DispatchMessageOriginal = NULL;
LRESULT WINAPI DispatchMessageDetour(const MSG* lpMsg) {
	return DispatchMessageOriginal(lpMsg);
}

typedef const UINT8*(__cdecl* PSDL_GetKeyboardState)(int* numKeys);
PSDL_GetKeyboardState SDL_GetKeyboardStateOriginal = NULL;
UINT8* KeyboardStateBuffer = NULL;
const UINT8* __cdecl SDL_GetKeyboardStateDetour(int* numKeys) {
	const UINT8* SDL_KeyboardStateBuffer = SDL_GetKeyboardStateOriginal(numKeys);
	for (int i = 0; i < SDL_NUM_SCANCODES; i++)
	{
		KeyboardStateBuffer[i] = SDL_KeyboardStateBuffer[i];
	}
	KeyboardStateBuffer[SDL_SCANCODE_UP] = SDL_KeyboardStateBuffer[SDL_SCANCODE_W];
	KeyboardStateBuffer[SDL_SCANCODE_DOWN] = SDL_KeyboardStateBuffer[SDL_SCANCODE_S];
	KeyboardStateBuffer[SDL_SCANCODE_LEFT] = SDL_KeyboardStateBuffer[SDL_SCANCODE_A];
	KeyboardStateBuffer[SDL_SCANCODE_RIGHT] = SDL_KeyboardStateBuffer[SDL_SCANCODE_D];
	KeyboardStateBuffer[SDL_SCANCODE_C] = SDL_KeyboardStateBuffer[SDL_SCANCODE_SPACE];
	KeyboardStateBuffer[SDL_SCANCODE_X] = SDL_KeyboardStateBuffer[SDL_SCANCODE_J];
	return KeyboardStateBuffer;
}

void SetDetours() {
	/*
	SDL_GetKeyboardState
	SDL_GetModState
	SDL_GetMouseState
	SDL_Joystick APIS
	GetAsyncKeyState
	GetCursorPos
	GetKeyState
	GetKeyboardState
	GetRawInputData
	GetRawInputDeviceInfoA
	GetRawInputDeviceList
	MapVirtualKeyW
	RegisterDeviceNotificationW
	RegisterRawInputDevices
	*/

	KeyboardStateBuffer = new UINT8[SDL_NUM_SCANCODES];
	HMODULE sdl2 = GetModuleHandle(L"SDL2.dll");
	FARPROC SDL_GetKeyboardState = GetProcAddress(sdl2, "SDL_GetKeyboardState");
	SDL_GetKeyboardStateOriginal = reinterpret_cast<PSDL_GetKeyboardState>(SetDetour(SDL_GetKeyboardState, SDL_GetKeyboardStateDetour));
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
	try {
		switch (ul_reason_for_call)
		{
		case DLL_PROCESS_ATTACH:
			if (!AllocConsole()) {
				EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
			}
			FILE* fp;
			freopen_s(&fp, "CONOUT$", "w", stdout);
			std::ios::sync_with_stdio();
			std::cout.clear();
			std::cout << "Hello World from injected DLL." << std::endl;
			SetDetours();
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
	try {
		STARTUPINFO si = { };
		si.cb = sizeof(STARTUPINFO);
		GetStartupInfo(&si);
		PROCESS_INFORMATION pi = { };
		if (!CreateProcess(L"D:\\ImportantData\\Coding\\C++\\celeste2++\\celeste2++\\Debug\\celeste2.exe", NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
			EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
		}
		RunToEntryPoint(pi.hProcess, pi.hThread);
		LoadModuleInProcess(pi.hProcess, L"celeste2++.dll");
		if (ResumeThread(pi.hThread) == 0xFFFFFFFF) {
			EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
		}

		if (!CloseHandle(pi.hThread)) {
			EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
		}
		if (!CloseHandle(pi.hProcess)) {
			EzError::ThrowFromCode(GetLastError(), __FILE__, __LINE__);
		}
	}
	catch (EzError error) {
		error.Print();
	}
	return 0;
}