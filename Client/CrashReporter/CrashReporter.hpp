#pragma once

// Argument names of the crash reporter
#define ARG_PRODUCT_NAME "product"
#define ARG_PRODUCT_VERSION "ver"
#define ARG_APPLICATION_NAME "app"
#define ARG_PROCESS_ID "pid"
#define ARG_THREAD_ID "tid"
#define ARG_EXCEPTION_POINTER "exp"
#define ARG_CONTEXT "ctx"
#define ARG_CONTEXT_LEN "ctxlen"
#define ARG_XIP "xip"
#define ARG_XBP "xbp"
#define ARG_XSP "xsp"
#define EMPTY_VALUE "unknown"
#define EXIT_EVENT_NAME_PREFIX L"{4aa014c4-a90d-4b78-b97b-4436b90f934e}_"

#ifndef CRASH_REPORTER_EXE_BUILD
//#if 1
#define CRASH_REPORTER_EXE_NAME _T("CrashReporter.exe")

#define LibLogInfo(...) __noop
#define LibLogError(...) __noop

#include <windows.h>
#include <winnt.h>
#include <intsafe.h>
#include <TlHelp32.h>

#include <atlstr.h>
#include <atlsync.h>
#include <atlcoll.h>

#pragma comment(lib, "version")

namespace CrashReporter {
namespace Details {
/// <summary>
/// Represents the unhandled exception handler for windows.
/// </summary>
class UnhandledExceptionHandler
{
public:
  /// <summary>
  /// Constructor.
  /// </summary>
  UnhandledExceptionHandler()
  {
    // Store the instance
    if (!m_pThis)
      m_pThis = this;
  }

  /// <summary>
  /// Destructor.
  /// </summary>
  ~UnhandledExceptionHandler()
  {
    // Empty
  }

  /// <summary>
  /// Initializes the handler.
  /// </summary>
  /// <returns>True on successfully; otherwise false.</returns>
  virtual bool Initialize(LPCTSTR productName)
  {
    // Set filter to handle unhandled exceptions
    m_previousHandler = ::SetUnhandledExceptionFilter(
      &UnhandledExceptionHandler::UnhandledExceptionFilter);
    if (NULL == m_previousHandler)
      // If previous handler is null then log it
      LibLogInfo("Previous handler is null.");

    // Save the product name
    m_productName = productName;

    // Redirect UnhandledExceptionFilter
    OverwriteSetUnhandledExceptionFilter();

    // Return the result
    return true;
  }

  /// <summary>
  /// Uninitializes the handler.
  /// </summary>
  virtual void Uninitialize()
  {
    // Log this calling of Uninitialize
    LibLogInfo("Unintialize the UnhandledExceptionHandler");
  }

  /// <summary>
  /// Gets called on application crash.
  /// </summary>
  void OnCrash(PEXCEPTION_POINTERS exceptionPointer)
  {
    // Acquire the lock
    m_lock.Enter();

    // Log this crash
    LibLogInfo("Application crashed");

    // Disable the WER dialog box. This can only disable the WER of windows
    // system. If the application is .net it will launch dw20.exe and display
    // its dialog
    // DWORD errorMode = ::SetErrorMode(0);
    // errorMode |= SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX |
    // SEM_NOOPENFILEERRORBOX;
    //::SetErrorMode(errorMode);

    // If the exception pointer is invalid then return
    if (nullptr == exceptionPointer) {
      // Log the error and return
      LibLogError("The exception pointer is null");
      return;
    }

    // Suspend all other threads to make it easier to solve the multi-thread
    // problems
    SuspendAllOtherThreads();

    // Unlock the loader locker in case some other thread is holding it
    UnlockLoaderLock();

    // Build command line to launch the reporter
    CString cmdLine = BuildCommandline(exceptionPointer);
    if (cmdLine.IsEmpty())
      ::ExitProcess(-1);

    // Build the event name used for the notification of process exit
    CString exitEventName;
    exitEventName.Format(EXIT_EVENT_NAME_PREFIX L"%x", GetCurrentProcessId());

    CEvent waitEvent;
    waitEvent.Create(NULL, FALSE, FALSE, exitEventName);
    if (!waitEvent)
      LibLogError("Failed to create event for process exit.");

    // Create the reporter process
    STARTUPINFOW si;
    ZeroMemory(&si, sizeof(STARTUPINFOW));
    si.cb = sizeof(STARTUPINFOW);
    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, 0);
    if (::CreateProcessW(nullptr,
                         const_cast<wchar_t*>(cmdLine.GetBuffer()),
                         nullptr,
                         nullptr,
                         FALSE,
                         0,
                         nullptr,
                         nullptr,
                         &si,
                         &pi)) {
      // Wait for crash reporter to finish
      if (waitEvent)
        ::WaitForSingleObject(waitEvent, INFINITE);
      else
        ::WaitForSingleObject(pi.hProcess, INFINITE);

      // Close the handle after creating process successfully
      ::CloseHandle(pi.hProcess);
      ::CloseHandle(pi.hThread);
    } else
      LibLogError("Failed to launch the reporter.");

    cmdLine.ReleaseBuffer();
  }

protected:
  /// <summary>
  /// Handler for the unhandled exception.
  /// </summary>
  /// <param name="ExceptionInfo">The exception pointers.</param>
  /// <returns>Return EXCEPTION_CONTINUE_SEARCH or
  /// EXCEPTION_EXECUTE_HANDLER.</returns>
  static LONG WINAPI
  UnhandledExceptionFilter(PEXCEPTION_POINTERS exceptionPointer)
  {
#if defined(_DEBUG) || defined(DEBUG)
    MessageBox(nullptr,
               _T("Application crashed"),
               _T("Unhandled Exception Handler"),
               MB_OK);
#endif
    // Call the crash handling method
    if (m_pThis)
      m_pThis->OnCrash(exceptionPointer);

    // Pass this exception event to system
    return EXCEPTION_CONTINUE_SEARCH;
  }

  /// <summary>
  /// Redirects the UnhandledExceptionFilter.
  /// </summary>
  void OverwriteSetUnhandledExceptionFilter()
  {
    // Get the address of the API SetUnhandledExceptionFilter
    LPVOID apiEntry = (LPVOID)::GetProcAddress(
      ::GetModuleHandleA("Kernel32.dll"), "SetUnhandledExceptionFilter");
    if (nullptr == apiEntry) {
      // If failed log and return
      LibLogError(
        "Failed to GetProcAddress of SetUnhandledExceptionFilter, error code = "
        << ::GetLastError());
      return;
    }

    // Declaration
    BOOL result = FALSE;
    DWORD oldProtectFlag = 0;

    // Make sure the memory can be written to
    result = ::VirtualProtect(
      apiEntry, sizeof(DWORD), PAGE_EXECUTE_READWRITE, &oldProtectFlag);
    if (result) {
      // The byte code of instruction: ret 4. The calling convention of
      // SetUnhandledExceptionFilter is stdcall and only has one parameter, So
      // when the function is called there will be one parameter pushed into the
      // stack. if we just want the function to return without doing anything,
      // We need to replace the first instruction with a ret instruction.
      // Meanwhile we need to keep the balance of the stack, so we must use:
      // ret 4. The byte code depends on the instruction set of Intel x86
      // instruction set, the function calling convention and the parameter
      // counts. This is a simplified implementation of Windows API Inline Hook.
#if defined(_M_IX86) || defined(__i386)
      // _asm ret 4
      static unsigned char returnInstruction[] = { 0xc2, 0x04, 0x00 };
#elif defined(_M_X64) || defined(__x86_64__)
      // _asm ret
      static unsigned char returnInstruction[] = { 0xc3 };
#endif
      // Replace the instruction
      ::CopyMemory(apiEntry, returnInstruction, sizeof(returnInstruction));

      // Restore the memory page protect status
      result = ::VirtualProtect(
        apiEntry, sizeof(DWORD), oldProtectFlag, &oldProtectFlag);
      if (FALSE == result)
        LibLogError("Failed to restore the protect flag after overwrite the "
                    "SetUnhandledExceptionFilter entry, error code: "
                    << GetLastError());
    } else
      LibLogError("Failed to change the protect flag when overwriting the "
                  "SetUnhandledExceptionFilter entry, error code: "
                  << GetLastError());
  }

  /// <summary>
  /// Unlocks the loader lock.
  /// </summary>
  /// <returns>True on successfully; otherwise false.</returns>
  bool UnlockLoaderLock()
  {
    // Function pointer type of LdrUnlockLoaderLock
    typedef NTSTATUS(NTAPI * Type_LdrUnlockLoaderLock)(ULONG, ULONG);

    // Get the function pointer of LdrUnlockLoaderLock
    Type_LdrUnlockLoaderLock pfnLdrUnlockLoaderLock =
      (Type_LdrUnlockLoaderLock)GetProcAddress(GetModuleHandle(_T("ntdll")),
                                               "LdrUnlockLoaderLock");

    // Unlock the loader lock
    if (pfnLdrUnlockLoaderLock)
      return SUCCEEDED(pfnLdrUnlockLoaderLock(0, 0));

    // Failed to unlock the loader lock
    return FALSE;
  }

  /// <summary>
  /// Suspends all other threads.
  /// </summary>
  void SuspendAllOtherThreads()
  {
    // Declarations
    HANDLE threadSnap = INVALID_HANDLE_VALUE;
    THREADENTRY32 te32;

    // Take a snapshot of all running threads
    threadSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (INVALID_HANDLE_VALUE == threadSnap)
      return;

    // Fill in the size of the structure
    te32.dwSize = sizeof(THREADENTRY32);

    // Retrieve information about the first thread, and exit if unsuccessful
    if (!::Thread32First(threadSnap, &te32)) {
      // Clean up the snapshot object
      ::CloseHandle(threadSnap);
      return;
    }

    // Walk the thread list of the system and display information about each
    // thread associated with the specified process
    do {
      if (te32.th32OwnerProcessID == ::GetCurrentProcessId() &&
          te32.th32ThreadID != ::GetCurrentThreadId()) {
        // If this thread is in the current process and it is not the current
        // thread then suspend it
        HANDLE threadHandle =
          ::OpenThread(THREAD_SUSPEND_RESUME, FALSE, te32.th32ThreadID);
        if (threadHandle) {
          // Suspend it and clean the resource
          ::SuspendThread(threadHandle);
          ::CloseHandle(threadHandle);
        }
      }
    } while (::Thread32Next(threadSnap, &te32));

    // Clean up the snapshot object.
    ::CloseHandle(threadSnap);
    return;
  }

  /// <summary>
  /// Gets the current executable file path.
  /// </summary>
  /// <returns>The path.</returns>
  CString GetAppFullPath()
  {
    // Find the reporter in the application directory
    CString appPathName;
    ::GetModuleFileName(nullptr, appPathName.GetBuffer(MAX_PATH), MAX_PATH);
    appPathName.ReleaseBuffer();
    return appPathName;
  }

  /// <summary>
  /// Gets the current executable file name.
  /// </summary>
  /// <returns>The file name.</returns>
  CString GetAppFileName()
  {
    CString appPathName = GetAppFullPath();
    CString appFileName = ::PathFindFileName(appPathName);
    return appFileName;
  }

  /// <summary>
  /// Gets the folder path of current executable file.
  /// </summary>
  /// <returns>The folder path.</returns>
  CString GetAppFolderPath()
  {
    // Find the reporter in the application directory
    CString appFolderPath = GetAppFullPath();
    ::PathRemoveFileSpec(appFolderPath.GetBuffer(MAX_PATH));
    appFolderPath.ReleaseBuffer();
    return appFolderPath;
  }

  /// <summary>
  /// Searches the reporter image path.
  /// </summary>
  /// <returns>Path of the reporter.</returns>
  CString SearchReporterPath()
  {
    // Find the reporter in the application directory
    CString appFolderPath = GetAppFolderPath();
    CString reporterExePathName;
    ::PathCombine(reporterExePathName.GetBuffer(MAX_PATH),
                  appFolderPath,
                  CRASH_REPORTER_EXE_NAME);
    reporterExePathName.ReleaseBuffer();

    // If it exists, return the path
    if (::PathFileExists(reporterExePathName.GetString()))
      return reporterExePathName;

    return CString();
  }

  /// <summary>
  /// Gets the product version.
  /// </summary>
  /// <returns>Product version.</returns>
  CString GetProductVersion()
  {
    CString version;
    CString appFullPath = GetAppFullPath();

    // Get the size of the file version info
    DWORD size = ::GetFileVersionInfoSize(appFullPath, NULL);
    if (size <= 0) {
      return version;
    }

    // Load the file version info
    CAtlArray<BYTE> data;
    data.SetCount(size);
    if (!::GetFileVersionInfo(appFullPath, NULL, size, data.GetData())) {
      return version;
    }

    // Get language code page list
    struct LANGANDCODEPAGE
    {
      WORD wLanguage;
      WORD wCodePage;
    } * languageCode;
    UINT len = 0;
    if (FALSE == ::VerQueryValue(data.GetData(),
                                 _T("\\VarFileInfo\\Translation"),
                                 (void**)&languageCode,
                                 &len)) {
      return version;
    }

    // Validate the language page code list
    if (len < sizeof(struct LANGANDCODEPAGE)) {
      return version;
    }

    // Build the product version path with the language code
    CString productVersionPath;
    productVersionPath.Format(_T("\\StringFileInfo\\%04x%04x\\ProductVersion"),
                              languageCode[0].wLanguage,
                              languageCode[0].wCodePage);

    // Get the version
    len = 0;
    TCHAR* productVersion = nullptr;
    if (FALSE ==
        ::VerQueryValue(
          data.GetData(), productVersionPath, (void**)&productVersion, &len)) {
      return version;
    }

    version = productVersion;

    // Return version string
    return version;
  }

  /// <summary>
  /// Checks whether current OS is 64 bit.
  /// </summary>
  /// <returns>True on successfully; otherwise false.</returns>
  bool Is64BitWindows()
  {
    // Declarations
    BOOL isUnderWow = FALSE;

#if defined(_M_IX86) || defined(__i386)
    // Current process is 32bit
    if (!::IsWow64Process(::GetCurrentProcess(), &isUnderWow))
      return false;

    // Check if it is under Wow (windows on windows)
    return isUnderWow != FALSE;
#elif defined(_M_X64) || defined(__x86_64__)
    // Current process is 64bit, then the OS must be 64bit
    return true;
#endif
  }

  /// <summary>
  /// Build the command line used to launch the reporter.
  /// </summary>
  /// <param name="exceptionPointer">Exceptions pointer value.</param>
  /// <returns>The command used to launch the reporter.</returns>
  CString BuildCommandline(PEXCEPTION_POINTERS exceptionPointer)
  {
    CString cmdline;

    // Get crash reporter path
    CString reporterExePath = SearchReporterPath();
    if (reporterExePath.IsEmpty()) {
      LibLogInfo("Crash reporter not found.");
      return cmdline;
    }

    // Get process and thread ids.
    int pid = ::GetCurrentProcessId();
    int tid = ::GetCurrentThreadId();

    // Get product version
    CString productVersion = GetProductVersion();

    // Get application name
    CString applicationName = GetAppFileName();

    // Build the command line used to launch the reporter
    cmdline.AppendFormat(_T("\"%s\""), reporterExePath.GetString());
    cmdline.AppendFormat(
      _T(" -" ARG_PRODUCT_NAME " %s"),
      (m_productName.IsEmpty() ? _T(EMPTY_VALUE) : m_productName.GetString()));
    cmdline.AppendFormat(_T(" -" ARG_PRODUCT_VERSION " %s"),
                         (productVersion.IsEmpty()
                            ? _T(EMPTY_VALUE)
                            : productVersion.GetString()));
    cmdline.AppendFormat(_T(" -" ARG_APPLICATION_NAME " %s"),
                         (applicationName.IsEmpty()
                            ? _T(EMPTY_VALUE)
                            : applicationName.GetString()));
    cmdline.AppendFormat(_T(" -" ARG_PROCESS_ID " %x"), pid);
    cmdline.AppendFormat(_T(" -" ARG_THREAD_ID " %x"), tid);
    cmdline.AppendFormat(_T(" -" ARG_EXCEPTION_POINTER " %p"),
                         exceptionPointer);
    cmdline.AppendFormat(_T(" -" ARG_CONTEXT " %p"),
                         exceptionPointer->ContextRecord);
    cmdline.AppendFormat(_T(" -" ARG_CONTEXT_LEN " %x"), sizeof(CONTEXT));

#if defined(_M_IX86) || defined(__i386)
    cmdline.AppendFormat(_T(" -" ARG_XIP " %p"),
                         (void*)(exceptionPointer->ContextRecord->Eip));
    cmdline.AppendFormat(_T(" -" ARG_XBP " %p"),
                         (void*)(exceptionPointer->ContextRecord->Ebp));
    cmdline.AppendFormat(_T(" -" ARG_XSP " %p"),
                         (void*)(exceptionPointer->ContextRecord->Esp));
#elif defined(_M_X64) || defined(__x86_64__)
    cmdline.AppendFormat(_T(" -" ARG_XIP " %p"),
                         (void*)(exceptionPointer->ContextRecord->Rip));
    cmdline.AppendFormat(_T(" -" ARG_XBP " %p"),
                         (void*)(exceptionPointer->ContextRecord->Rbp));
    cmdline.AppendFormat(_T(" -" ARG_XSP " %p"),
                         (void*)(exceptionPointer->ContextRecord->Rsp));
#endif

    // Convert to wstring and return it
    return cmdline;
  }

private:
  /// <summary>
  /// The lock.
  /// </summary>
  CCriticalSection m_lock;

  /// <summary>
  /// Product name.
  /// </summary>
  CString m_productName;

  /// <summary>
  /// Previous handler.
  /// </summary>
  static void* m_previousHandler;

  /// <summary>
  /// Pointer to the unhandled exception handler.
  /// </summary>
  static UnhandledExceptionHandler* m_pThis;
};

void* UnhandledExceptionHandler::m_previousHandler = nullptr;
UnhandledExceptionHandler* UnhandledExceptionHandler::m_pThis = nullptr;
}

bool
InitializeCrashReporter(LPCTSTR productName)
{
  static Details::UnhandledExceptionHandler ueh;
  return ueh.Initialize(productName);
}
}

#endif
