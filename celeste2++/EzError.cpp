#include "EzError.h"
#include <Windows.h>
#include <comdef.h>
#include <sstream>
#include <winternl.h>

#pragma comment(lib, "ntdll.lib")

// Formats multiple pieces of data into a full error message and allocates that string on the heap.
LPWSTR ConstructMessage(LPCWSTR errorMessage, LPCSTR file, int line) {
	try {
		std::wostringstream messageStream;

		if (file == NULL) { messageStream << "ERROR in UnknownFile"; }
		else {
			LPCSTR fileNameOnly = file + lstrlenA(file);
			while (fileNameOnly >= file && *fileNameOnly != '\\') { fileNameOnly--; }
			messageStream << "ERROR in " << (fileNameOnly + 1);
		}

		if (line < 0) { messageStream << " at UnknownLine"; }
		else { messageStream << " at line " << line; }

		SYSTEMTIME timeNow;
		GetLocalTime(&timeNow);
		if (timeNow.wHour == 0) {
			messageStream << " at 12:" << timeNow.wMinute << ":" << timeNow.wSecond << "am";
		}
		else if (timeNow.wHour < 12) {
			messageStream << " at " << (timeNow.wHour % 12) << ":" << timeNow.wMinute << ":" << timeNow.wSecond << "am";
		}
		else {
			messageStream << " at " << (timeNow.wHour % 12) << ":" << timeNow.wMinute << ":" << timeNow.wSecond << "pm";
		}
		messageStream << " on " << timeNow.wMonth << "/" << timeNow.wDay << "/" << timeNow.wYear;

		messageStream << ": " << errorMessage;

		DWORD errorMessageLength = lstrlenW(errorMessage);
		if (errorMessageLength >= 2) {
			LPCWSTR lastTwoChars = errorMessage + (errorMessageLength - 2);
			if (lastTwoChars[0] != L'\r' || lastTwoChars[1] != L'\n') {
				messageStream << L"\r\n";
			}
		}

		std::wstring messageString = messageStream.str();
		LPWSTR message = new WCHAR[messageString.size() + 1];
		lstrcpyW(message, messageString.c_str());

		return message;
	}
	catch (...) { return NULL; }
}

EzError::EzError(DWORD errorCode, LPCSTR file, int line) {
	try {
		DWORD errorCode = GetLastError();

		LPWSTR errorMessage = NULL;
		DWORD systemErrorLength = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPWSTR>(&errorMessage), 0, NULL);

		_message = ConstructMessage(errorMessage, file, line);

		LocalFree(errorMessage);
	}
	catch (...) {}
}
EzError::EzError(HRESULT hr, LPCSTR file, int line) {
	try {
		LPWSTR errorMessage = NULL;
		DWORD errorMessageLength = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, hr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPWSTR>(&errorMessage), 0, NULL);

		if (errorMessageLength > 0) {
			_message = ConstructMessage(errorMessage, file, line);

			LocalFree(errorMessage);
		}
		else {
			_com_error comError(hr);
			LPCWSTR comErrorMessage = comError.ErrorMessage();

			_message = ConstructMessage(comErrorMessage, file, line);
		}
	}
	catch (...) {}
}
EzError::EzError(LONGLONG ntLonger, LPCSTR file, int line) {
	try {
		NTSTATUS nt = static_cast<NTSTATUS>(ntLonger);

		DWORD errorCode = RtlNtStatusToDosError(nt);
		if (errorCode != ERROR_MR_MID_NOT_FOUND) {
			LPWSTR errorMessage = NULL;
			DWORD systemErrorLength = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL, errorCode, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPWSTR>(&errorMessage), 0, NULL);

			_message = ConstructMessage(errorMessage, file, line);

			LocalFree(errorMessage);
		}
		else {
			HRESULT hr = HRESULT_FROM_NT(nt);

			LPWSTR errorMessage = NULL;
			DWORD errorMessageLength = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
				NULL, hr, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), reinterpret_cast<LPWSTR>(&errorMessage), 0, NULL);

			if (errorMessageLength > 0) {
				_message = ConstructMessage(errorMessage, file, line);

				LocalFree(errorMessage);
			}
			else {
				_com_error comError(hr);
				LPCWSTR comErrorMessage = comError.ErrorMessage();

				_message = ConstructMessage(comErrorMessage, file, line);
			}
		}
	}
	catch (...) {}
}
EzError::EzError(LPCWSTR errorMessage, LPCSTR file, int line) {
	try {
		_message = ConstructMessage(errorMessage, file, line);
	}
	catch (...) {}
}

EzError::EzError(const EzError& other) {
	if (other._message != NULL) {
		size_t messageLength = lstrlenW(other._message) + 1;
		_message = new WCHAR[messageLength];
		lstrcpyW(_message, other._message);
	}
	else {
		_message = NULL;
	}
}
EzError& EzError::operator=(const EzError& other) {
	if (this != &other) {
		this->~EzError();
		if (other._message != NULL) {
			size_t messageLength = lstrlenW(other._message) + 1;
			_message = new WCHAR[messageLength];
			lstrcpyW(_message, other._message);
		}
		else {
			_message = NULL;
		}
	}
	return *this;
}

void EzError::Print() {
	try {
		HANDLE stdoutHandle = GetStdHandle(STD_OUTPUT_HANDLE);

		// Get initial console attributes.
		CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
		GetConsoleScreenBufferInfo(stdoutHandle, &consoleInfo);
		WORD savedAttributes = consoleInfo.wAttributes;

		// Set console attributes to red text.
		SetConsoleTextAttribute(stdoutHandle, static_cast<WORD>(EzConsoleColor::Red));

		// Print error message.
		DWORD charsWritten = 0;
		WriteConsole(stdoutHandle, _message, lstrlenW(_message), &charsWritten, NULL);

		// Restore initial console attributes.
		SetConsoleTextAttribute(stdoutHandle, savedAttributes);
	}
	catch (...) {}
}
EzError::~EzError() {
	try {
		if (_message != NULL) {
			delete[] _message;
		}
	}
	catch (...) {}
}

void EzError::ThrowFromCode(DWORD errorCode, LPCSTR file, int line) {
	if (errorCode != 0) {
		throw EzError(errorCode, file, line);
	}
}
void EzError::ThrowFromHR(HRESULT hr, LPCSTR file, int line) {
	if (!SUCCEEDED(hr)) {
		throw EzError(hr, file, line);
	}
}
void EzError::ThrowFromNT(NTSTATUS nt, LPCSTR file, int line) {
	if (!SUCCEEDED(nt)) {
		throw EzError(static_cast<LONGLONG>(nt), file, line);
	}
}