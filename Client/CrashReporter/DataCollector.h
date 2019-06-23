#pragma once
#include <windows.h>

#include "DbgHelpLib.h"
#include "IDataCollector.h"

namespace CrashReporter {
/// <summary>
/// The collector for crash information.
/// </summary>
class DataCollector : public IDataCollector
{
  /// <summary>
  /// Represents the module information.
  /// </summary>
  typedef struct ModuleInfo
  {
    /// <summary>
    /// Module name.
    /// </summary>
    std::wstring Name;

    /// <summary>
    /// Module full path.
    /// </summary>
    std::wstring FullPathName;

    /// <summary>
    /// Module image base.
    /// </summary>
    uint64_t ImageBase;

    /// <summary>
    /// Module image size.
    /// </summary>
    uint64_t ImageSize;

    /// <summary>
    /// Constructor.
    /// </summary>
    ModuleInfo()
    {
      // Initialize the members
      ImageBase = 0;
      ImageSize = 0;
    }
  } ModuleInfo;

  /// <summary>
  /// Represents the module information list.
  /// </summary>
  typedef std::list<ModuleInfo> ModuleList;

  /// <summary>
  /// Represents the stack frame.
  /// </summary>
  typedef struct StackFrame
  {
    /// <summary>
    /// Frame module name.
    /// </summary>
    std::wstring ModuleName;

    /// <summary>
    /// Frame address.
    /// </summary>
    uint64_t Address;

    /// <summary>
    /// Frame module base.
    /// </summary>
    uint64_t ModuleBase;

    /// <summary>
    /// Frame module offset.
    /// </summary>
    uint64_t ModuleOffset;

    /// <summary>
    /// Constructor.
    /// </summary>
    StackFrame()
    {
      // Initialize the members
      Address = 0;
      ModuleBase = 0;
      ModuleOffset = 0;
    }
  } FrameStack;

  /// <summary>
  /// Represents the stack.
  /// </summary>
  typedef std::vector<StackFrame> StackTrace;

public:
  /// <summary>
  /// Constructor.
  /// </summary>
  DataCollector();

  /// <summary>
  /// Destructor.
  /// </summary>
  ~DataCollector();

  /// <summary>
  /// Collects all the crash information.
  /// </summary>
  virtual bool Collect(CrashLogData& logData) override;

  /// <summary>
  /// Initializes this instance.
  /// </summary>
  /// <param name="pid">Process id.</param>
  /// <param name="tid">Thread id.</param>
  /// <param name="exception">Exception pointer.</param>
  /// <param name="ctx">Context pointer.</param>
  /// <param name="ctxLen">Context length.</param>
  /// <param name="xip">The value of Eip or Rip register.</param>
  /// <param name="xbp">The value of Ebp or Rbp register.</param>
  /// <param name="xsp">The value of Esp or Rsp register.</param>
  /// <param name="appName">Application name register.</param>
  /// <returns>True if successful; otherwise false.</returns>
  bool Initialize(int pid,
                  int tid,
                  int64_t exception,
                  int64_t ctx,
                  int32_t ctxLen,
                  int64_t xip,
                  int64_t xbp,
                  int64_t xsp,
                  const std::string& appName);

  /// <summary>
  /// Uninitializes this instance.
  /// </summary>
  void Uninitialize();

protected:
  /// <summary>
  /// Initializes the dump root folder.
  /// </summary>
  void InitializeDumpRootPath();

  /// <summary>
  /// Collects the OS version.
  /// </summary>
  void CollectOSVersion();

  /// <summary>
  /// Collects the machine id.
  /// </summary>
  void CollectMachineId();

  /// <summary>
  /// Collects the module list.
  /// </summary>
  void CollectAllModules();

  /// <summary>
  /// Collects the stack trace.
  /// </summary>
  void CollectStackTrace();

  /// <summary>
  /// Generates the crash signature.
  /// </summary>
  void GenerateCrashSignature();

  /// <summary>
  /// Reads the exception record from 32bit process.
  /// </summary>
  /// <param name="exceptionRecord">Receive the converted exception
  /// record.</param>
  void ReadExceptionRecordFrom32bitProcess(PEXCEPTION_RECORD exceptionRecord);

  /// <summary>
  /// Generates the mini dump file.
  /// </summary>
  void GenerateMiniDumpFile();

  /// <summary>
  /// Generates the summary report file.
  /// </summary>
  void GenerateSummaryReportFile();

  /// <summary>
  /// Gets the path of the manged crash information file.
  /// </summary>
  void GetManagedCrashInfoFile();

  /// <summary>
  /// Creates the zip file.
  /// </summary>
  void CreateZipFile();

  /// <summary>
  /// Notifies the process to exit.
  /// </summary>
  void NotifyProcessToExit();

  /// <summary>
  /// Converts address to stack frame.
  /// </summary>
  /// <param name="programCounter">The address.</param>
  /// <returns>Stack frame.</returns>
  StackFrame ConvertToStackFrame(DWORD_PTR programCounter);

  /// <summary>
  /// Gets file content of the summary data.
  /// </summary>
  /// <returns>Summary content.</returns>
  std::string GetSummaryData();

  /// <summary>
  /// Gets string of the module list data.
  /// </summary>
  /// <returns>Module list.</returns>
  std::string GetModuleListData();

  /// <summary>
  /// Gets the string of the stack frame.
  /// </summary>
  /// <param name="frame">Stack frame.</param>
  /// <returns>Readable string of the stack frame.</returns>
  std::wstring GetFrameString(StackFrame& frame);

  /// <summary>
  /// Gets the machine type.
  /// </summary>
  /// <param name="process">Process handle.</param>
  /// <returns>Machine type.</returns>
  int GetMachineType(HANDLE process);

private:
  /// <summary>
  /// Max frame count of the stack.
  /// </summary>
  DWORD m_maxFrameCount;

  /// <summary>
  /// Process id.
  /// </summary>
  DWORD m_pid;

  /// <summary>
  /// Thread id.
  /// </summary>
  DWORD m_tid;

  /// <summary>
  /// Exception pointer.
  /// </summary>
  int64_t m_exceptionPointer;

  /// <summary>
  /// Context
  /// </summary>
  int64_t m_contextAddress;

  /// <summary>
  /// Context length.
  /// </summary>
  int32_t m_contextLength;

  /// <summary>
  /// Value of Eip or Rip.
  /// </summary>
  int64_t m_xip;

  /// <summary>
  /// Value of Ebp or Rbp.
  /// </summary>
  int64_t m_xbp;

  /// <summary>
  /// Value of Esp or Rsp.
  /// </summary>
  int64_t m_xsp;

  /// <summary>
  /// Machine type of target process.
  /// </summary>
  int32_t m_machineType;

  /// <summary>
  /// Process handle.
  /// </summary>
  HANDLE m_processHandle;

  /// <summary>
  /// Thread handle.
  /// </summary>
  HANDLE m_threadHandle;

  /// <summary>
  /// Module list.
  /// </summary>
  ModuleList m_moduleList;

  /// <summary>
  /// Stack trace.
  /// </summary>
  StackTrace m_stackTrace;

  /// <summary>
  /// Root path for dump files.
  /// </summary>
  std::wstring m_dumpRootPath;

  /// <summary>
  /// Dump file path.
  /// </summary>
  std::wstring m_dumpFilePath;

  /// <summary>
  /// Machine ID.
  /// </summary>
  std::wstring m_machineId;

  /// <summary>
  /// Summary file path.
  /// </summary>
  std::wstring m_summaryFilePath;

  /// <summary>
  /// Managed crash information file path.
  /// </summary>
  std::wstring m_managedCrashInfoPath;

  /// <summary>
  /// Zip file path.
  /// </summary>
  std::wstring m_zipFilePath;

  /// <summary>
  /// Application name.
  /// </summary>
  std::wstring m_applicationName;

  /// <summary>
  /// Crash signature.
  /// </summary>
  std::string m_crashSignature;

  /// <summary>
  /// Crash module name.
  /// </summary>
  std::string m_crashModuleName;

  /// <summary>
  /// Crash address.
  /// </summary>
  std::string m_crashAddress;

  /// <summary>
  /// Crash call stack.
  /// </summary>
  std::string m_crashCallStack;

  /// <summary>
  /// OS version.
  /// </summary>
  std::string m_OSVersion;

  /// <summary>
  /// Context buffer.
  /// </summary>
  std::vector<unsigned char> m_contextBuffer;

  /// <summary>
  /// The helper object of DbgHelp API manager.
  /// </summary>
  DbgHelpLib m_dbgHelpLib;
};
}
