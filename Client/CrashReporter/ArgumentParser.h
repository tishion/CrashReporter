#pragma once
#include <cstdint>
#include <map>
#include <string>

namespace CrashReporter {
/// <summary>
/// Represents the arguments parser
/// </summary>
class ArgumentParser
{
  /// <summary>
  /// Argument map type.
  /// </summary>
  typedef std::map<std::string, std::string> ArgumentMap;

public:
  /// <summary>
  /// Constructor.
  /// </summary>
  /// <param name="cmdline">Command line to be parsed.</param>
  ArgumentParser(const std::wstring& cmdline);

  /// <summary>
  /// Destructor.
  /// </summary>
  ~ArgumentParser();

  /// <summary>
  /// Gets the string value.
  /// </summary>
  /// <param name="name">The name of the value.</param>
  /// <param name="value">The string value.</param>
  /// <returns>True if successful, otherwise false;</returns>
  bool GetStringValue(const char* name, std::string& value);

  /// <summary>
  /// Gets the int 32 value.
  /// </summary>
  /// <param name="name">The name of the value.</param>
  /// <param name="value">The int32 value.</param>
  /// <returns>True if successful, otherwise false;</returns>
  bool GetInt32Value(const char* name, int32_t& value);

  /// <summary>
  /// Gets the unsigned int 64 value.
  /// </summary>
  /// <param name="name">The name of the value.</param>
  /// <param name="value">The int64 value.</param>
  /// <returns>True if successful, otherwise false;</returns>
  bool GetInt64Value(const char* name, int64_t& value);

  /// <summary>
  /// Gets the unsigned int 32 value.
  /// </summary>
  /// <param name="name">The name of the value.</param>
  /// <param name="value">The int32 value.</param>
  /// <returns>True if successful, otherwise false;</returns>
  bool GetUInt32Value(const char* name, uint32_t& value);

  /// <summary>
  /// Gets the unsigned int 64 value.
  /// </summary>
  /// <param name="name">The name of the value.</param>
  /// <param name="value">The int64 value.</param>
  /// <returns>True if successful, otherwise false;</returns>
  bool GetUInt64Value(const char* name, uint64_t& value);

private:
  /// <summary>
  /// Original command line sting.
  /// </summary>
  std::string m_cmdline;

  /// <summary>
  /// Map used to store the argument names and values.
  /// </summary>
  ArgumentMap m_optionMap;
};
}
