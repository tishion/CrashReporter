
#include <windows.h>
#include <atlconv.h>
#include <atlstr.h>
#include <iterator>
#include <shellapi.h>
#include <sstream>
#include <string>
#include <vector>

#include "ArgumentParser.h"
#include "Log.h"

namespace CrashReporter {
ArgumentParser::ArgumentParser(const std::wstring& cmdline)
{
  // Validate the command line
  if (cmdline.empty())
    return;

  // Convert the command line to UTF8 and store it.
  m_cmdline = ::CW2A(cmdline.c_str(), CP_UTF8);

  // Split the command line to argument list
  int argCount = 0;
  auto argList = ::CommandLineToArgvW(cmdline.c_str(), &argCount);

  // Parse the arguments list
  for (int i = 0; i < argCount; ++i) {
    // Get current argument and validate it
    std::wstring temp = argList[i];
    if (temp.empty())
      continue;

    // If the argument is start with '-', the recognize it as the option name
    if (temp.at(0) == L'-') {
      // Remove the first '-'
      temp.erase(temp.begin());
      std::string name = ::CW2A(temp.c_str(), CP_UTF8).m_psz;

      // Read next argument
      i += 1;
      if (i < argCount && argList[i][0] != L'-') {
        // If next argument is not option name, read it as the value.
        std::string value = ::CW2A(argList[i], CP_UTF8).m_psz;
        m_optionMap[name] = value;
      } else {
        // If next argument is option, it means the current command line is
        // invalid
        LogError("Invalid command line: " << m_cmdline);

        // Stop parsing
        break;
      }
    }
  }
}

ArgumentParser::~ArgumentParser()
{
  // Empty
}

bool
ArgumentParser::GetStringValue(const char* name, std::string& value)
{
  // Find the target name
  auto it = m_optionMap.find(name);
  if (it != m_optionMap.end()) {
    // Return the value if found
    value = it->second;
    return true;
  }

  // Not found
  LogError("Option not found: " << name);
  return false;
}

bool
ArgumentParser::GetInt32Value(const char* name, int32_t& value)
{
  auto it = m_optionMap.find(name);
  if (it != m_optionMap.end()) {
    try {
      // Return the value if found
      value = std::stoi(it->second, 0, 16);
      return true;
    } catch (const std::exception& e) {
      // Failed to convert it to int32_t
      LogError("Failed to convert " << it->second
                                    << " to int32_t: " << e.what());
      return false;
    }
  }

  // Not found
  LogError("Option not found: " << name);
  return false;
}

bool
ArgumentParser::GetInt64Value(const char* name, int64_t& value)
{
  // Find the target name
  auto it = m_optionMap.find(name);
  if (it != m_optionMap.end()) {
    try {
      // Return the value if found
      value = std::stoll(it->second, 0, 16);
      return true;
    } catch (const std::exception& e) {
      // Failed to convert it to int64_t
      LogError("Failed to convert " << it->second << " to int64_t "
                                    << e.what());
      return false;
    }
  }

  // Not found
  LogError("Option not found: " << name);
  return false;
}

bool
ArgumentParser::GetUInt32Value(const char* name, uint32_t& value)
{
  auto it = m_optionMap.find(name);
  if (it != m_optionMap.end()) {
    try {
      // Return the value if found
      value = std::stoul(it->second, 0, 16);
      return true;
    } catch (const std::exception& e) {
      // Failed to convert it to int32_t
      LogError("Failed to convert " << it->second
                                    << " to uint32_t: " << e.what());
      return false;
    }
  }

  // Not found
  LogError("Option not found: " << name);
  return false;
}

bool
ArgumentParser::GetUInt64Value(const char* name, uint64_t& value)
{ // Find the target name
  auto it = m_optionMap.find(name);
  if (it != m_optionMap.end()) {
    try {
      // Return the value if found
      value = std::stoull(it->second, 0, 16);
      return true;
    } catch (const std::exception& e) {
      // Failed to convert it to int64_t
      LogError("Failed to convert " << it->second << " to uint64_t "
                                    << e.what());
      return false;
    }
  }

  // Not found
  LogError("Option not found: " << name);
  return false;
}
}
