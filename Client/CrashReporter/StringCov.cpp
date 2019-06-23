#include <codecvt>

#include "StringCov.h"

namespace StrCov {
static std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>, wchar_t>
  u16_u8_cvt;

std::string
U16ToU8(const std::wstring& s)
{
  return u16_u8_cvt.to_bytes(s);
}

std::wstring
U8ToU16(const std::string& s)
{
  return u16_u8_cvt.from_bytes(s);
}

std::string
TToU8(const TCHAR* s)
{
#if defined(UNICODE) || defined(_UNICODE)
  return U16ToU8(s);
#else
  return std::string(s);
#endif
}

std::wstring
TToU16(const TCHAR* s)
{
#if defined(UNICODE) || defined(_UNICODE)
  return std::wstring(s);
#else
  return U8ToU16(s);
#endif
}

}
