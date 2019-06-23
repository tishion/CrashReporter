#pragma once
#include <windows.h>
#include <tchar.h>

#include <string>
#include <locale>

namespace StrCov {
std::string
U16ToU8(const std::wstring& s);

std::wstring
U8ToU16(const std::string& s);

std::string
TToU8(const TCHAR* s);

std::wstring
TToU16(const TCHAR* s);
}
