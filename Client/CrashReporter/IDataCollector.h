#pragma once
#include <cstdint>
#include <list>
#include <memory>
#include <string>
#include <vector>

#include "CrashData.h"

namespace CrashReporter {
/// <summary>
/// The collector used to collect the crash information.
/// </summary>
class IDataCollector
{
public:
  /// <summary>
  /// Destructor.
  /// </summary>
  virtual ~IDataCollector(){};

  /// <summary>
  /// Collects all the crash information.
  /// </summary>
  virtual bool Collect(CrashLogData& logData) = 0;
};

/// <summary>
/// Short name of the shared pointer type of <see cref="ICrashInfoCollector" />.
/// </summary>
typedef std::shared_ptr<IDataCollector> CrashInfoCollectorPtr;
}
