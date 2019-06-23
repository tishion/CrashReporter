#pragma once
#include <string>
#include <locale>

namespace StrCov {
std::string
U16ToU8(const std::wstring& s);

std::wstring
U8ToU16(const std::string& s);
}
