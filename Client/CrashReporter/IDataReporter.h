#pragma once
#include <memory>
#include <string>

#include "CrashData.h"

namespace CrashReporter {
/// <summary>
/// Represents the crash reporter class.
/// </summary>
class IDataReporter
{
public:
  /// <summary>
  /// Destructor.
  /// </summary>
  virtual ~IDataReporter(){};

  /// <summary>
  /// Reports the data.
  /// </summary>
  /// <param name="cmdLine">The crash log data.</param>
  virtual bool Report(CrashLogData& logData) = 0;
};

/// <summary>
/// Short name of the shared pointer type of <see cref="IDataReporter" />.
/// </summary>
typedef std::shared_ptr<IDataReporter> DataReporterPtr;
}
