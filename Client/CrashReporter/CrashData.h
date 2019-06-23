#pragma once
#include <string>

namespace CrashReporter {
/// <summary>
/// Represents the crash detail information.
/// </summary>
struct CrashDetailData
{
  /// <summary>
  /// Unique signature of this crash.
  /// </summary>
  std::string CrashSignature;

  /// <summary>
  /// Product name.
  /// </summary>
  std::string ProductName;

  /// <summary>
  /// Product version.
  /// </summary>
  std::string ProductVersion;

  /// <summary>
  /// Application name.
  /// </summary>
  std::string ApplicationName;

  /// <summary>
  /// Crash address.
  /// </summary>
  std::string CrashAddress;

  /// <summary>
  /// Crash module name.
  /// </summary>
  std::string CrashModule;

  /// <summary>
  /// OS version
  /// </summary>
  std::string OSVersion;

  /// <summary>
  /// Call stack of this crash.
  /// </summary>
  std::string CallStack;

  /// <summary>
  /// Crash data file path.
  /// </summary>
  std::wstring FilePath;
};

/// <summary>
/// Represents the basic crash data.
/// </summary>
struct CrashLogData
{
  /// <summary>
  ///
  /// </summary>
  uint32_t pid;

  /// <summary>
  ///
  /// </summary>
  uint32_t tid;

  /// <summary>
  ///
  /// </summary>
  uint64_t ExceptionPointer;

  /// <summary>
  ///
  /// </summary>
  uint64_t ExceptionContext;

  /// <summary>
  ///
  /// </summary>
  uint32_t ExceptionContextLength;

  /// <summary>
  ///
  /// </summary>
  uint64_t xip;

  /// <summary>
  ///
  /// </summary>
  uint64_t xbp;

  /// <summary>
  ///
  /// </summary>
  uint64_t xsp;

  /// <summary>
  /// IP Address.
  /// </summary>
  std::string IPAddress;

  /// <summary>
  /// Machine Id.
  /// </summary>
  std::wstring MachineId;

  /// <summary>
  /// Crash detail data.
  /// </summary>
  CrashDetailData Detail;
};
}
