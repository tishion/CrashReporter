#include <windows.h>
#include <Psapi.h>
#include <TlHelp32.h>
#include <shlobj.h>
#include <strsafe.h>

#include <atlfile.h>
#include <atltime.h>
#include <atlstr.h>

#include <algorithm>
#include <cstdio>
#include <sstream>
#include <vector>

#include "Constants.h"
#include "DataCollector.h"
#include "StringCov.h"
#include "Log.h"
#include "Md5.h"
#include "ZipFileWriter.h"

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "version.lib")

namespace CrashReporter {
DataCollector::DataCollector()
  : m_maxFrameCount(0)
  , m_pid(0)
  , m_tid(0)
  , m_exceptionPointer(0)
{
  // Empty
}

DataCollector::~DataCollector()
{
  // Uninitialize this instance
  Uninitialize();
}

bool
DataCollector::Collect(CrashLogData& logData)
{
  if (Initialize(logData.pid,
                 logData.tid,
                 logData.ExceptionPointer,
                 logData.ExceptionContext,
                 logData.ExceptionContextLength,
                 logData.xip,
                 logData.xbp,
                 logData.xsp,
                 logData.Detail.ApplicationName)) {
    // Initialize DbgHelp module
    if (m_dbgHelpLib.InitializeDbgHelpModule()) {
      // Initialize the root path
      InitializeDumpRootPath();

      // Collect the OS version
      CollectOSVersion();
      logData.Detail.OSVersion = m_OSVersion;

      // Collect the machine id
      CollectMachineId();
      logData.MachineId = m_machineId;

      // Collect the module list
      CollectAllModules();

      // Collect the stack trace
      CollectStackTrace();
      logData.Detail.CrashAddress = m_crashAddress;
      logData.Detail.CallStack = m_crashCallStack;
      logData.Detail.CrashModule = m_crashModuleName;

      // Collect the crash signature
      GenerateCrashSignature();
      logData.Detail.CrashSignature = m_crashSignature;

      // Generate the mini dump file
      GenerateMiniDumpFile();

      // Generate the summary report file
      GenerateSummaryReportFile();

      // Collect file
      GetManagedCrashInfoFile();

      // Create zip file
      CreateZipFile();
      logData.Detail.FilePath = m_zipFilePath;

      // Notify target process to exit
      NotifyProcessToExit();

      // Release the DbgHelp module
      m_dbgHelpLib.ReleaseDbgHelpModule();

      Uninitialize();

      return true;
    } else {
      LogError("Failed to initialize DbgHelpLib");
    }
  } else {
    LogError("Failed to initialize collector");
  }
  return false;
}

bool
DataCollector::Initialize(int pid,
                          int tid,
                          int64_t exception,
                          int64_t ctx,
                          int32_t ctxLen,
                          int64_t xip,
                          int64_t xbp,
                          int64_t xsp,
                          const std::string& appName)
{
  // Open the target process
  m_processHandle = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
  if (m_processHandle) {
    // Open the target thread
    m_threadHandle = ::OpenThread(THREAD_QUERY_INFORMATION, FALSE, tid);
    if (m_threadHandle) {
      // Initialize all the data and return true
      m_pid = pid;
      m_tid = tid;
      m_exceptionPointer = exception;
      m_contextAddress = ctx;
      m_contextLength = ctxLen;
      m_xip = xip;
      m_xbp = xbp;
      m_xsp = xsp;
      if (!appName.empty())
        m_applicationName = StrCov::U8ToU16(appName);
      return true;
    } else
      LogError("Failed to open the thread");

    // Failed to open the thread, close the process and return false
    ::CloseHandle(m_processHandle);
  } else
    LogError("Failed to open the process");

  // Failed to initialize this instance
  return false;
}

void
DataCollector::Uninitialize()
{
  // Check the thread handle
  if (m_threadHandle) {
    // Close the thread and reset the handle
    ::CloseHandle(m_threadHandle);
    m_threadHandle = nullptr;
  }

  // Check the process handle
  if (m_processHandle) {
    // Close the process and reset the handle
    ::CloseHandle(m_processHandle);
    m_processHandle = nullptr;
  }

  // Clean the resource
  m_moduleList.clear();
  m_stackTrace.clear();
  m_dumpFilePath.clear();
  m_summaryFilePath.clear();
  m_zipFilePath.clear();
  m_crashSignature.clear();
  m_crashModuleName.clear();
  m_crashAddress.clear();
  m_crashCallStack.clear();
  m_OSVersion.clear();

  // Reset the member variables
  m_pid = 0;
  m_tid = 0;
  m_exceptionPointer = 0;
  m_contextAddress = 0;
  m_contextLength = 0;
  m_xip = 0;
  m_xbp = 0;
  m_xsp = 0;
}

void
DataCollector::InitializeDumpRootPath()
{
  // Get the temporary folder path
  CStringW tempPath;

  // First try to get the common app data
  CStringW commonApp;
  BOOL result = ::SHGetSpecialFolderPathW(
    NULL, commonApp.GetBuffer(MAX_PATH), CSIDL_LOCAL_APPDATA, FALSE);
  commonApp.ReleaseBuffer();
  if (result) {
    // If we can get common app data, then create temporary folder
    ::PathCombineW(tempPath.GetBuffer(MAX_PATH), commonApp, TEMP_FOLDER_NAMEW);
    tempPath.ReleaseBuffer();

    // If failed to create directory then reset the temp path
    if (FALSE == ::CreateDirectoryW(tempPath, nullptr) &&
        ERROR_ALREADY_EXISTS != ::GetLastError())
      tempPath.Empty();
  }

  // If the temp path is empty then use the system temp path
  if (tempPath.IsEmpty()) {
    ::GetTempPathW(MAX_PATH, tempPath.GetBuffer(MAX_PATH));
    tempPath.ReleaseBuffer();
  }

  // Build the path %temp%/AppCrashDump/
  CStringW rootPath;
  ::PathCombineW(rootPath.GetBuffer(MAX_PATH), tempPath, DUMP_FOLDER_NAMEW);
  rootPath.ReleaseBuffer();

  // Try to create the root folder
  if (::CreateDirectoryW(rootPath, nullptr) ||
      ERROR_ALREADY_EXISTS == ::GetLastError()) {
    LogInfo("Dump root folder path " << rootPath.GetString());
    m_dumpRootPath = rootPath.GetString();
    return;
  } else
    LogError("Failed to create dump folder " << rootPath.GetString());

  // return the system temp path
  m_dumpRootPath = tempPath.GetString();
}

void
DataCollector::CollectOSVersion()
{
  // Set OS default value
  m_OSVersion = std::string(UNKNOWN_VALUE);

  // Get the full path to NTDLL.DLL
  std::vector<wchar_t> buffer(MAX_PATH + 1, 0);
  int lenght =
    ::GetModuleFileNameW(::GetModuleHandleA("ntdll"), buffer.data(), MAX_PATH);
  if (lenght > MAX_PATH) {
    buffer.resize(lenght + 1, 0);
    ::GetModuleFileNameW(::GetModuleHandleA("ntdll"),
                         buffer.data(),
                         static_cast<DWORD>(buffer.size()));
  }

  // Store the Unicode path
  std::wstring utf16Path = buffer.data();

  // Get the size of the file version info
  DWORD size = ::GetFileVersionInfoSizeW(utf16Path.c_str(), NULL);
  if (size <= 0) {
    LogError(
      "Failed to get the size of the file version info. Path = " << utf16Path);
    return;
  }

  // Load the file version info
  std::vector<BYTE> data(size);
  if (!::GetFileVersionInfoW(utf16Path.c_str(), NULL, size, data.data())) {
    LogError("Failed to get the file version info. Path = " << utf16Path);
    return;
  }

  // Get language code page list
  struct LANGANDCODEPAGE
  {
    WORD wLanguage;
    WORD wCodePage;
  } * languageCode;
  UINT len = 0;
  if (FALSE == ::VerQueryValueW(data.data(),
                                L"\\VarFileInfo\\Translation",
                                (void**)&languageCode,
                                &len)) {
    LogError("Failed to query the language list. Path = " << utf16Path);
    return;
  }

  // Validate the lange page code list
  if (len < sizeof(struct LANGANDCODEPAGE)) {
    LogError("Failed to query the language list. Path = " << utf16Path);
    return;
  }

  // Build the product version path wiht the language code
  std::vector<wchar_t> productVersionPath(MAX_PATH, 0);
  HRESULT hr = ::StringCchPrintfW(productVersionPath.data(),
                                  50,
                                  L"\\StringFileInfo\\%04x%04x\\ProductVersion",
                                  languageCode[0].wLanguage,
                                  languageCode[0].wCodePage);
  if (FAILED(hr)) {
    LogError("Failed to query the language list. Path = " << utf16Path);
    return;
  }

  // Get the version
  len = 0;
  wchar_t* proudctVersion = nullptr;
  if (FALSE == ::VerQueryValueW(data.data(),
                                productVersionPath.data(),
                                (void**)&proudctVersion,
                                &len)) {
    LogError("Failed to query the version. Path = " << utf16Path);
    return;
  }

  // Store the version string
  std::wstring osVersion;
  if (proudctVersion)
    osVersion = proudctVersion;

  // Convert to UTF8
  m_OSVersion = ::CW2A(osVersion.c_str(), CP_UTF8);

  // If failed to get the OS version, replace it with unknown
  if (m_OSVersion.empty())
    m_OSVersion = std::string(UNKNOWN_VALUE);
}

void
DataCollector::CollectMachineId()
{
  // Query the machine id from the registry
  CRegKey reg;
  LSTATUS result = reg.Open(
    HKEY_LOCAL_MACHINE, _T("SOFTWARE\\Microsoft\\Cryptography"), KEY_READ);
  if (ERROR_SUCCESS == result) {
    CString machineId;
    ULONG charCount = MAX_PATH;
    result = reg.QueryStringValue(
      _T("MachineGuid"), machineId.GetBuffer(MAX_PATH), &charCount);
    machineId.ReleaseBuffer();
    if (ERROR_SUCCESS == result)
      m_machineId = std::wstring(::CT2W(machineId));
  }
}

void
DataCollector::CollectAllModules()
{
  // Declaration
  MODULEENTRY32 me32;

  // Take a snapshot of all modules in the specified process
  HANDLE hModuleSnap =
    ::CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_pid);
  if (INVALID_HANDLE_VALUE == hModuleSnap) {
    LogError("Failed to create the snapshot, error code: " << ::GetLastError());
    return;
  }

  // Set the size of the structure before using it
  me32.dwSize = sizeof(MODULEENTRY32);

  // Retrieve information about the first module, and exit if unsuccessful
  if (!::Module32First(hModuleSnap, &me32)) {
    LogError("Failed to call Module32First" << ::GetLastError());
    ::CloseHandle(hModuleSnap);
    return;
  }

  // Now walk the module list of the process, and collect information about each
  // module
  do {
    // Copy the data of the current module
    ModuleInfo modInfo;
    modInfo.ImageBase = (uint64_t)me32.modBaseAddr;
    modInfo.ImageSize = me32.modBaseSize;
    modInfo.Name = StrCov::TToU16(me32.szModule);
    modInfo.FullPathName = StrCov::TToU16(me32.szExePath);

    // Save the current module information
    m_moduleList.push_back(modInfo);

  } while (::Module32Next(hModuleSnap, &me32));

  // Close the snapshot handle
  ::CloseHandle(hModuleSnap);

  // Sort the module list to improve the efficiency when searching in it
  m_moduleList.sort([](const ModuleInfo& a, const ModuleInfo& b) {
    // Sort by the image base address
    return a.ImageBase < b.ImageBase;
  });
}

void
DataCollector::CollectStackTrace()
{
  // Declarations
  BOOL result = FALSE;
  PCONTEXT contextPointer = nullptr;
  std::vector<unsigned char> contextBuffer;

  // Get machine type of the target process
  m_machineType = GetMachineType(m_processHandle);

  // Allocate the buffer
  m_contextBuffer.resize(m_contextLength, 0);

  // Copy context data into current process memory
  SIZE_T lengthRead = 0;
  result = ::ReadProcessMemory(m_processHandle,
                               (LPVOID)m_contextAddress,
                               m_contextBuffer.data(),
                               m_contextLength,
                               &lengthRead);
  if (result && lengthRead == m_contextLength) {
    if (IMAGE_FILE_MACHINE_AMD64 == m_machineType) {
      // Copy the context data and get the pointer to the new context
      contextBuffer = m_contextBuffer;
      contextPointer = (PCONTEXT)contextBuffer.data();
    }
  } else
    LogError(
      "Failed to read the context content, error code: " << ::GetLastError());

  // Initialize the stack frame
  STACKFRAME64 stackFrame;
  ZeroMemory(&stackFrame, sizeof(STACKFRAME64));
  stackFrame.AddrPC.Offset = m_xip;
  stackFrame.AddrPC.Mode = AddrModeFlat;
  stackFrame.AddrFrame.Offset = m_xbp;
  stackFrame.AddrFrame.Mode = AddrModeFlat;
  stackFrame.AddrStack.Offset = m_xsp;
  stackFrame.AddrStack.Mode = AddrModeFlat;

  // Initialize the DbgHelp module
  result = m_dbgHelpLib.SymInitializeW(m_processHandle, L"", TRUE);
  int frameCount = m_maxFrameCount;

  // Walk the stack
  std::wostringstream woss;
  while (--frameCount) {
    // Walk the current frame of the stack
    result = m_dbgHelpLib.StackWalk64(m_machineType,
                                      m_processHandle,
                                      m_threadHandle,
                                      &stackFrame,
                                      contextPointer,
                                      nullptr,
                                      nullptr,
                                      nullptr,
                                      nullptr);

    // Check the frame result
    if (result) {
      // Convert the address to stack frame and store it
      auto frame = ConvertToStackFrame((DWORD_PTR)stackFrame.AddrPC.Offset);
      m_stackTrace.push_back(frame);

      // Get the string of the stack frame
      woss << GetFrameString(frame);
    } else
      break;
  }

  // Clean the resource of DbgHelp module
  m_dbgHelpLib.SymCleanup(m_processHandle);

  // Convert the stack string to UTF8
  m_crashCallStack = ::CW2A(woss.str().c_str(), CP_UTF8);

  // Check the stack trace length
  if (!m_stackTrace.empty()) {
    // Get the crash address
    m_crashModuleName = ::CW2A(m_stackTrace[0].ModuleName.c_str(), CP_UTF8);
    std::ostringstream oss;
    oss << "0x" << std::hex << m_stackTrace[0].Address;
    m_crashAddress = oss.str();
  }
}

void
DataCollector::GenerateCrashSignature()
{
  // Declarations
  std::wostringstream oss;

  // Build a string to represent the stack, use ModuleName:Offset as the basic
  // unit
  for (auto frame : m_stackTrace)
    oss << frame.ModuleName << L":0x" << std::hex << frame.ModuleOffset << L"|";

  // Append OS version
  std::wstring osVersion = ::CA2W(m_OSVersion.c_str()).m_psz;
  oss << osVersion << "|";

  // Append application name
  oss << m_applicationName << "|";

  // Make all the characters lowercase
  std::wstring hashSrouce = oss.str();
  std::transform(
    hashSrouce.begin(), hashSrouce.end(), hashSrouce.begin(), ::tolower);

  // Get MD5 of this stack string
  CrashReporter::MD5 md5;
  md5.update((char*)hashSrouce.data(),
             static_cast<unsigned int>(hashSrouce.length() *
                                       sizeof(std::wstring::value_type)));
  md5.finalize();

  // Save it as the crash signature
  m_crashSignature = md5.hexdigest().c_str();
}

void
DataCollector::ReadExceptionRecordFrom32bitProcess(
  PEXCEPTION_RECORD exceptionRecord)
{
  // Validate the argument
  if (!exceptionRecord)
    return;

  // Declarations
  DWORD32 remoteExceptionRecordAddress = 0;
  SIZE_T lengthRead = 0;

  // Read the exception record address
  if (::ReadProcessMemory(m_processHandle,
                          (LPVOID)m_exceptionPointer,
                          &remoteExceptionRecordAddress,
                          sizeof(DWORD32),
                          &lengthRead)) {
    // Read the 32bit exception record
    EXCEPTION_RECORD32 exceptionsRecord32 = { 0 };
    if (::ReadProcessMemory(m_processHandle,
                            (LPVOID)(DWORD64)remoteExceptionRecordAddress,
                            &exceptionsRecord32,
                            sizeof(EXCEPTION_RECORD32),
                            &lengthRead)) {
      // Copy the exception_pointer structure into current process memory
      // (convert EXCEPTION_RECORD32 TO EXCEPTION_RECORD64)
      exceptionRecord->ExceptionCode = exceptionsRecord32.ExceptionCode;
      exceptionRecord->ExceptionFlags = exceptionsRecord32.ExceptionFlags;
      exceptionRecord->ExceptionRecord = nullptr;
      exceptionRecord->ExceptionAddress =
        (PVOID)(DWORD64)exceptionsRecord32.ExceptionAddress;
      exceptionRecord->NumberParameters = exceptionsRecord32.NumberParameters;
      for (int i = 0; i < EXCEPTION_MAXIMUM_PARAMETERS; i++)
        exceptionRecord->ExceptionInformation[i] =
          (ULONG_PTR)exceptionsRecord32.ExceptionInformation[i];

      // Return
      return;
    } else
      LogError("Failed to read the remote exception record content, error: "
               << ::GetLastError());
  } else
    LogError("Failed to read the remote exception record address, error: "
             << ::GetLastError());

  // Reset the exceptions structure
  exceptionRecord->ExceptionCode = 0;
  exceptionRecord->ExceptionFlags = 0;
  exceptionRecord->ExceptionRecord = 0;
  exceptionRecord->ExceptionAddress = 0;
  exceptionRecord->NumberParameters = 0;
  for (int i = 0; i < EXCEPTION_MAXIMUM_PARAMETERS; i++)
    exceptionRecord->ExceptionInformation[i] = 0;
}

void
DataCollector::GenerateMiniDumpFile()
{
  // Set the flags for creating dump file
  MINIDUMP_TYPE dumpType = (MINIDUMP_TYPE)(
    MiniDumpNormal | MiniDumpWithFullAuxiliaryState | MiniDumpWithDataSegs |
    MiniDumpWithHandleData | MiniDumpScanMemory | MiniDumpWithUnloadedModules |
    MiniDumpWithIndirectlyReferencedMemory | MiniDumpWithProcessThreadData |
    MiniDumpWithFullMemoryInfo | MiniDumpWithThreadInfo |
    MiniDumpIgnoreInaccessibleMemory);

  // Set the exception information for creating mini dump
  MINIDUMP_EXCEPTION_INFORMATION dumpExceptionInfo;

  // Set thread id
  dumpExceptionInfo.ThreadId = m_tid;

#if defined(_M_IX86) || defined(__i386)
  // Current process is 32bit, check the process machine type
  if (IMAGE_FILE_MACHINE_I386 == m_machineType) {
    // The target process is 32bit too, just use the memory in target process
    dumpExceptionInfo.ExceptionPointers =
      (PEXCEPTION_POINTERS)m_exceptionPointer;
    dumpExceptionInfo.ClientPointers = TRUE;
  }
#elif defined(_M_X64) || defined(__x86_64__)
  // Current process is 64bit, set the exception information for creating mini
  // dump
  EXCEPTION_RECORD exceptionsRecord;
  EXCEPTION_POINTERS exceptionPointers;

  // Check the target process machine type
  if (IMAGE_FILE_MACHINE_I386 == m_machineType) {
    // The target process is 32bit, we need to copy the record information to
    // current process
    ReadExceptionRecordFrom32bitProcess(&exceptionsRecord);

    // Fill the EXCEPTION_POINTERS
    exceptionPointers.ContextRecord = (PCONTEXT)m_contextBuffer.data();
    exceptionPointers.ExceptionRecord = &exceptionsRecord;

    // Fill the MINIDUMP_EXCEPTION_INFORMATION
    dumpExceptionInfo.ExceptionPointers = &exceptionPointers;
    dumpExceptionInfo.ClientPointers = FALSE;
  } else if (IMAGE_FILE_MACHINE_AMD64 == m_machineType) {
    // If it is 64bit process just use the remote data
    dumpExceptionInfo.ExceptionPointers =
      (PEXCEPTION_POINTERS)m_exceptionPointer;
    dumpExceptionInfo.ClientPointers = TRUE;
  }
#endif
  // Build the file name
  CString fileName;

  // Get the time stamp string
  CString timeStamp = CTime::GetCurrentTime().Format(_T(TIME_FORMAT));
  fileName.Format(
    _T(DUMP_FILE_NAME_FORMAT), m_applicationName.c_str(), timeStamp);

  // Get the root directory
  CString rootPath = ::CW2T(m_dumpRootPath.c_str()).m_psz;

  // Build the dump file path
  CString filePath;
  ::PathCombine(filePath.GetBuffer(MAX_PATH), rootPath, fileName);
  filePath.ReleaseBuffer();

  // Create the dump file
  CAtlFile dumpFile;
  HRESULT hr = dumpFile.Create(
    filePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS);
  if (SUCCEEDED(hr)) {
    // Write the dump data into the file
    if (m_dbgHelpLib.MiniDumpWriteDump(m_processHandle,
                                       m_pid,
                                       dumpFile,
                                       dumpType,
                                       &dumpExceptionInfo,
                                       nullptr,
                                       nullptr)) {
      m_dumpFilePath = StrCov::TToU16(filePath);
      LogInfo("Dump file path: " << m_dumpFilePath);
      return;
    } else
      LogError(
        "Failed to write dump data into file, error: " << ::GetLastError());
  } else
    LogError("Failed to create dump file, error: " << hr);
}

void
DataCollector::GenerateSummaryReportFile()
{
  // Build the file name
  CString fileName;

  // Get the time stamp string
  CString timeStamp = CTime::GetCurrentTime().Format(_T(TIME_FORMAT));
  fileName.Format(
    _T(SUMMARY_FILE_NAME_FORMAT), m_applicationName.c_str(), timeStamp);

  // Get the root directory
  CString rootPath = ::CW2T(m_dumpRootPath.c_str()).m_psz;

  // Build the summary file path
  CString filePath;
  ::PathCombine(filePath.GetBuffer(MAX_PATH), rootPath, fileName);
  filePath.ReleaseBuffer();

  // Create summary report file
  CAtlFile summaryFile;
  HRESULT hr = summaryFile.Create(
    filePath, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, CREATE_ALWAYS);
  if (SUCCEEDED(hr)) {
    // Build the summary report content
    std::string content;
    content += GetSummaryData();
    content += GetModuleListData();

    // Write the summary report content into the file
    hr =
      summaryFile.Write(content.data(), static_cast<DWORD>(content.length()));
    if (SUCCEEDED(hr)) {
      m_summaryFilePath = StrCov::TToU16(filePath);
      LogInfo("Summary file path: " << m_summaryFilePath);
      return;
    } else
      LogError("Failed to write summary report file, error code: " << hr);
  } else
    LogError("Failed to create summary report file, error: " << hr);
}

void
DataCollector::GetManagedCrashInfoFile()
{
  // Get process image file path
  CStringW processExePath;
  ::GetModuleFileNameExW(
    m_processHandle, nullptr, processExePath.GetBuffer(MAX_PATH), MAX_PATH);
  processExePath.ReleaseBuffer();
  m_managedCrashInfoPath = processExePath;

  // Append the file extension
  m_managedCrashInfoPath += MANAGEDCRASHINFOR_FILE_EXTENSION;
}

void
DataCollector::CreateZipFile()
{
  // Get the time stamp string
  CString timeStamp = CTime::GetCurrentTime().Format(_T(TIME_FORMAT));

  // Convert the crash signature string
  CString crashSignature = ::CA2T(m_crashSignature.c_str()).m_psz;

  // Build the file name
  CString fileName;
  fileName.Format(
    _T(ZIP_FILE_NAME_FORMAT), m_applicationName.c_str(), timeStamp);

  // Get the root directory
  CString rootPath = ::CW2T(m_dumpRootPath.c_str()).m_psz;

  // Build the dump file path
  CString zipFilePath;
  ::PathCombine(zipFilePath.GetBuffer(MAX_PATH), rootPath, fileName);
  zipFilePath.ReleaseBuffer();

  // Create zip file
  auto hZip = ZipFile::CreateZip(zipFilePath.GetString(), nullptr);
  if (hZip != INVALID_HANDLE_VALUE) {
    // Get the dump file path and name
    CString filePath = ::CW2T(m_dumpFilePath.c_str()).m_psz;
    CString fileName = ::PathFindFileName(filePath);

    // Add the dump file into the zip file
    ZipFile::ZipAdd(hZip, fileName, filePath);

    // Get the summary report file and path
    filePath = ::CW2T(m_summaryFilePath.c_str());
    fileName = ::PathFindFileName(filePath);

    // Add the summary report file into the zip file
    ZipFile::ZipAdd(hZip, fileName, filePath);

    // Get the summary report file and path
    filePath = ::CW2T(m_managedCrashInfoPath.c_str());
    fileName = ::PathFindFileName(filePath);

    // Add managed crash information file into zip file if it exists
    ZipFile::ZipAdd(hZip, fileName, filePath);

    // Close the zip file
    ZipFile::CloseZip(hZip);

    // Save the zip file path
    m_zipFilePath = StrCov::TToU16(zipFilePath);
    LogInfo("Zip file path: " << m_zipFilePath);

    // Remove the dump file
    if (!::DeleteFileW(m_dumpFilePath.c_str()))
      LogError("Failed to delete the file " << m_dumpFilePath);

    // Remove the summary file
    if (!::DeleteFileW(m_summaryFilePath.c_str()))
      LogError("Failed to delete the file " << m_summaryFilePath);

    ::DeleteFileW(m_managedCrashInfoPath.c_str());
  } else
    LogError("Failed to create zip file : " << zipFilePath.GetString());
}

void
DataCollector::NotifyProcessToExit()
{
  // Build the event name used for the notification of process exit
  std::wostringstream exitEventName;
  exitEventName << EXIT_EVENT_NAME_PREFIX << std::hex << m_pid;

  // Create the event for exit process
  HANDLE exitWaitEvent =
    ::OpenEventW(EVENT_MODIFY_STATE, FALSE, exitEventName.str().c_str());
  if (exitWaitEvent) {
    // Notify target process to exit
    if (!::SetEvent(exitWaitEvent))
      // Failed to notify the process
      LogError("Failed to signal the exit event for target process.");
    else
      // Notified the process successfully
      return;
  } else
    // If failed to notify the process then try to terminate it
    LogError("Failed to open event for process exit.");

  // Validate the process handle
  if (nullptr == m_processHandle)
    return;

  // Terminate the process
  if (FALSE == ::TerminateProcess(m_processHandle, -1))
    LogError("Failed to terminate the process: " << ::GetLastError());
}

DataCollector::StackFrame
DataCollector::ConvertToStackFrame(DWORD_PTR programCounter)
{
  // Declaration
  StackFrame frame;
  frame.Address = programCounter;

  // Find the module which contains this address, we only need to find the first
  // module which the base address is greater than the target address
  auto it = std::find_if(m_moduleList.begin(),
                         m_moduleList.end(),
                         [programCounter](const ModuleInfo& a) {
                           return programCounter < a.ImageBase;
                         });

  // If the module found is the first one, it means the address is not in any
  // module
  if (it != m_moduleList.begin()) {
    // If the module found is not the first one, get the previous one
    auto previous = --it;

    // Compare the address with the previous module base and module end address
    if (programCounter <= previous->ImageBase + previous->ImageSize) {
      // If the PC is in the range of this module, record it
      frame.ModuleName = previous->Name;
      frame.ModuleBase = previous->ImageBase;
      frame.ModuleOffset = (programCounter - frame.ModuleBase);
      return frame;
    }
  }

  // No modules containing the address found
  LogInfo("Target address " << std::hex << programCounter
                            << " is not in any module");
  return frame;
}

std::string
DataCollector::GetSummaryData()
{
  // Format the summary report data
  std::string summaryData;
  summaryData += CRASH_SIGNATURE;
  summaryData += m_crashSignature + NEW_LINE;
  summaryData += NEW_LINE NEW_LINE;

  // Append the call stack
  summaryData += CALL_STACK NEW_LINE;
  summaryData += m_crashCallStack;
  summaryData += NEW_LINE NEW_LINE;

  // Return the string
  return summaryData;
}

std::string
DataCollector::GetModuleListData()
{
  // Format the module list string
  std::wostringstream oss;
  oss << MODULE_LISTW << NEW_LINEW;
  for (auto& module : m_moduleList)
    oss << module.FullPathName << NEW_LINEW;

  // Convert to UTF8 and return
  std::string utf8Result = ::CW2A(oss.str().c_str(), CP_UTF8).m_psz;
  return utf8Result;
}

std::wstring
DataCollector::GetFrameString(StackFrame& frame)
{
  // Format the stack frame to string
  CStringW frameSymbol;
  frameSymbol.Format(L"0x%016llX ", frame.Address);

  // Format the frame address
  if (!frame.ModuleName.empty())
    frameSymbol.AppendFormat(L"%s!", frame.ModuleName.c_str());
  else {
    // If module name is not empty then use it
    if (0 != frame.ModuleBase)
      frameSymbol.AppendFormat(L"0x%016llX!", frame.ModuleBase);
    else {
      // If module base is empty too, just return the address
      frameSymbol.AppendFormat(L"0x%016llX\r\n", frame.Address);
      return frameSymbol.GetString();
    }
  }

  // Try to get the symbol name
  DWORD64 displacement = 0;
  std::vector<unsigned char> buffer(
    sizeof(SYMBOL_INFOW) + MAX_SYM_NAME * sizeof(WCHAR), 0);
  PSYMBOL_INFOW pSymbol = (PSYMBOL_INFOW)buffer.data();
  pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
  pSymbol->MaxNameLen = MAX_SYM_NAME;

  // Try to get the symbol of the address
  if (m_dbgHelpLib.SymFromAddrW(
        m_processHandle, frame.Address, &displacement, pSymbol)) {
    // Format the stack frame with symbol string
    frameSymbol.AppendFormat(L"%s", pSymbol->Name);
    DWORD64 offset = frame.Address - pSymbol->Address;

    // Append the offset to the symbol base
    if (offset > 0)
      frameSymbol.AppendFormat(L"+0x%X", offset);
  } else
    frameSymbol.AppendFormat(L"0x%X", frame.ModuleOffset);

  // Append new line
  frameSymbol.Append(L"\r\n");

  // Return the result
  return frameSymbol.GetString();
}

int
DataCollector::GetMachineType(HANDLE process)
{
  // Declaration
  BOOL isUnderWow = FALSE;

#if defined(_M_IX86) || defined(__i386)
  // Current process is 32bit
  if (!::IsWow64Process(::GetCurrentProcess(), &isUnderWow))
    return 0;

  // Check if it is under Wow (windows on windows)
  if (isUnderWow) {
    // Current process is under Wow, so current OS is 64bit
    if (!::IsWow64Process(process, &isUnderWow))
      return 0;

    // If target process is under wow then it is 32bit, otherwise 64bit
    if (isUnderWow)
      return IMAGE_FILE_MACHINE_I386;
    else
      return IMAGE_FILE_MACHINE_AMD64;
  } else
    // Current process is not under Wow, so current OS is 32bit, then target
    // process is 32bit too
    return IMAGE_FILE_MACHINE_I386;

#elif defined(_M_X64) || defined(__x86_64__)
  // Current application is 64bit, then current OS is 64bit
  if (!::IsWow64Process(process, &isUnderWow))
    return 0;

  // If target process is under Wow then it is 32bit, otherwise 64bit
  if (isUnderWow)
    return IMAGE_FILE_MACHINE_I386;
  else
    return IMAGE_FILE_MACHINE_AMD64;
#endif
}
}
