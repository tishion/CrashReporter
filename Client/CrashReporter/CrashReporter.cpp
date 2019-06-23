// CrashReporter.cpp : Defines the entry point for the application.
//

#include "framework.h"
#include "resource.h"

#include "ArgumentParser.h"
#include "Constants.h"
#include "CrashData.h"
#include "IDataCollector.h"
#include "IDataReporter.h"
#include "StringCov.h"
#include "Log.h"

#include "DataCollector.h"
#include "DataReporter.h"

bool
CollectBasicInformation(LPTSTR lpstrCmdLine,
                        CrashReporter::CrashLogData& logData)
{
#if defined(_DEBUG) || defined(DEBUG)
  ::MessageBox(NULL, _T("Application Crashed"), _T("CrashReporter"), MB_OK);
#endif

  // Parse the command line
  CrashReporter::ArgumentParser argumentParser(StrCov::TToU16(lpstrCmdLine));

  // Get process id
  uint32_t pid = 0;
  if (!argumentParser.GetUInt32Value(ARG_PROCESS_ID, pid)) {
    // If failed, then stop reporting
    LogError("Failed to get pid");
    return false;
  }
  logData.pid = pid;

  // Get thread id
  uint32_t tid = 0;
  if (!argumentParser.GetUInt32Value(ARG_THREAD_ID, tid)) {
    // If failed, then stop reporting
    LogError("Failed to get tid");
    return false;
  }
  logData.tid = tid;

  // Get exception pointer
  uint64_t exceptionPointer = 0;
  if (!argumentParser.GetUInt64Value(ARG_EXCEPTION_POINTER, exceptionPointer)) {
    // If failed, then stop reporting
    LogError("Failed to get exception pointer");
    return false;
  }
  logData.ExceptionPointer = exceptionPointer;

  // Get context pointer
  uint64_t ctx = 0;
  if (!argumentParser.GetUInt64Value(ARG_CONTEXT, ctx)) {
    // If failed, then stop reporting
    LogError("Failed to get context pointer");
    return false;
  }
  logData.ExceptionContext = ctx;

  // Get context length
  uint32_t ctxLen = 0;
  if (!argumentParser.GetUInt32Value(ARG_CONTEXT_LEN, ctxLen)) {
    // If failed, then stop reporting
    LogError("Failed to get context length");
    return false;
  }
  logData.ExceptionContextLength = ctxLen;

  // Get xip
  uint64_t xip = 0;
  if (!argumentParser.GetUInt64Value(ARG_XIP, xip)) {
    // If failed, then stop reporting
    LogError("Failed to get xip");
    return false;
  }
  logData.xip = xip;

  // Get xbp
  uint64_t xbp = 0;
  if (!argumentParser.GetUInt64Value(ARG_XBP, xbp)) {
    // If failed, then stop reporting
    LogError("Failed to get xbp");
    return false;
  }
  logData.xbp = xbp;

  // Get xsp
  uint64_t xsp = 0;
  if (!argumentParser.GetUInt64Value(ARG_XSP, xsp)) {
    // If failed, then stop reporting
    LogError("Failed to get xsp");
    return false;
  }
  logData.xsp = xsp;

  // The server will use the remote address of the IP address, so we can ignore
  // this field
  logData.IPAddress = "0.0.0.0";

  // Get the machine ID
  logData.MachineId = L"";

  // Get product name
  std::string temp;
  if (argumentParser.GetStringValue(ARG_PRODUCT_NAME, temp))
    logData.Detail.ProductName = temp;
  else {
    LogError("Failed to get product name");
    logData.Detail.ProductName = UNKNOWN_VALUE;
  }

  // Get product version
  if (argumentParser.GetStringValue(ARG_PRODUCT_VERSION, temp))
    logData.Detail.ProductVersion = temp;
  else {
    LogError("Failed to get product version");
    logData.Detail.ProductVersion = UNKNOWN_VALUE;
  }

  // Get application name
  if (argumentParser.GetStringValue(ARG_APPLICATION_NAME, temp))
    logData.Detail.ApplicationName = temp;
  else {
    LogError("Failed to get application name");
    logData.Detail.ApplicationName = UNKNOWN_VALUE;
  }
  return true;
}

int WINAPI
_tWinMain(HINSTANCE hInstance,
          HINSTANCE /*hPrevInstance*/,
          LPTSTR lpstrCmdLine,
          int nCmdShow)
{
  // Parse the command line
  CrashReporter::CrashLogData logData;
  if (!CollectBasicInformation(lpstrCmdLine, logData)) {
    return -1;
  }

  // Collect the crash information
  CrashReporter::CrashInfoCollectorPtr collector =
    std::make_shared<CrashReporter::DataCollector>();
  if (!collector->Collect(logData)) {
    return -1;
  }

  // Report the crash log data
  CrashReporter::DataReporterPtr reporter =
    std::make_shared<CrashReporter::DataReporter>();
  if (!reporter->Report(logData)) {
    return -1;
  }

  // Exit the process
  return 0;
}
