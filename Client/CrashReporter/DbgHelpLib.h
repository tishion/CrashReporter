#ifndef DBG_HELP_LIB_H
#define DBG_HELP_LIB_H
#pragma once

#include <Windows.h>
#pragma warning(push)
#pragma warning(disable : 4091)
#include <DbgHelp.h>
#pragma warning(pop)

namespace CrashReporter {
/// <summary>
/// The wrapper class for DbgHlep functions.
/// </summary>
class DbgHelpLib
{
public:
  /// <summary>
  /// Constructor.
  /// </summary>
  DbgHelpLib();

  /// <summary>
  /// Destructor.
  /// </summary>
  ~DbgHelpLib();

  /// <summary>
  /// Initializes the module.
  /// </summary>
  /// <returns>True if successful; otherwise false.</returns>
  BOOL InitializeDbgHelpModule();

  /// <summary>
  /// Releases the module.
  /// </summary>
  void ReleaseDbgHelpModule();

  /// <summary>
  /// Wrapper of SymInitializeW, refer to Win32 API SymInitializeW
  /// (https://msdn.microsoft.com/en-us/library/windows/desktop/ms681351.aspx).
  /// </summary>
  BOOL SymInitializeW(__in HANDLE hProcess,
                      __in_opt PCWSTR UserSearchPath,
                      __in BOOL fInvadeProcess);

  /// <summary>
  /// Wrapper of SymCleanup, refer to Win32 API SymCleanup
  /// (https://msdn.microsoft.com/en-us/library/windows/desktop/ms680696.aspx).
  /// </summary>
  BOOL SymCleanup(__in HANDLE hProcess);

  /// <summary>
  /// Wrapper of SymFromAddrW, refer to Win32 API SymFromAddrW
  /// (https://msdn.microsoft.com/en-us/library/windows/desktop/ms681323.aspx).
  /// </summary>
  BOOL SymFromAddrW(__in HANDLE hProcess,
                    __in DWORD64 Address,
                    __out_opt PDWORD64 Displacement,
                    __inout PSYMBOL_INFOW Symbol);

  /// <summary>
  /// Wrapper of StackWalk64, refer to Win32 API StackWalk64
  /// (https://msdn.microsoft.com/en-us/library/windows/desktop/ms680650.aspx).
  /// </summary>
  BOOL StackWalk64(__in DWORD MachineType,
                   __in HANDLE hProcess,
                   __in HANDLE hThread,
                   __inout LPSTACKFRAME64 StackFrame,
                   __inout PVOID ContextRecord,
                   __in_opt PREAD_PROCESS_MEMORY_ROUTINE64 ReadMemoryRoutine,
                   __in_opt PFUNCTION_TABLE_ACCESS_ROUTINE64
                     FunctionTableAccessRoutine,
                   __in_opt PGET_MODULE_BASE_ROUTINE64 GetModuleBaseRoutine,
                   __in_opt PTRANSLATE_ADDRESS_ROUTINE64 TranslateAddress);

  /// <summary>
  /// Wrapper of MiniDumpWriteDump, refer to Win32 API MiniDumpWriteDump
  /// (https://msdn.microsoft.com/en-us/library/windows/desktop/ms680360.aspx).
  /// </summary>
  BOOL MiniDumpWriteDump(
    __in HANDLE hProcess,
    __in DWORD ProcessId,
    __in HANDLE hFile,
    __in MINIDUMP_TYPE DumpType,
    __in_opt PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
    __in_opt PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
    __in_opt PMINIDUMP_CALLBACK_INFORMATION CallbackParam);

private:
  /// <summary>
  /// Function pointer type of SymInitializeW.
  /// </summary>
  typedef BOOL(WINAPI* Type_SymInitializeW)(HANDLE, PCWSTR, BOOL);

  /// <summary>
  /// Function pointer type of SymCleanup.
  /// </summary>
  typedef BOOL(WINAPI* Type_SymCleanup)(HANDLE);

  /// <summary>
  /// Function pointer type of SymFromAddrW.
  /// </summary>
  typedef BOOL(WINAPI* Type_SymFromAddrW)(HANDLE,
                                          DWORD64,
                                          PDWORD64,
                                          PSYMBOL_INFOW);

  /// <summary>
  /// Function pointer type of StackWalk64.
  /// </summary>
  typedef BOOL(WINAPI* Type_StackWalk64)(DWORD,
                                         HANDLE,
                                         HANDLE,
                                         LPSTACKFRAME64,
                                         PVOID,
                                         PREAD_PROCESS_MEMORY_ROUTINE64,
                                         PFUNCTION_TABLE_ACCESS_ROUTINE64,
                                         PGET_MODULE_BASE_ROUTINE64,
                                         PTRANSLATE_ADDRESS_ROUTINE64);

  /// <summary>
  /// Function pointer type of MiniDumpWriteDump.
  /// </summary>
  typedef BOOL(WINAPI* Type_MiniDumpWriteDump)(
    HANDLE,
    DWORD,
    HANDLE,
    MINIDUMP_TYPE,
    PMINIDUMP_EXCEPTION_INFORMATION,
    PMINIDUMP_USER_STREAM_INFORMATION,
    PMINIDUMP_CALLBACK_INFORMATION);

private:
  /// <summary>
  /// Module handle.
  /// </summary>
  HMODULE m_hModule;

  /// <summary>
  /// Function pointer of SymInitializeW.
  /// </summary>
  Type_SymInitializeW m_apiSymInitializeW;

  /// <summary>
  /// Function pointer of SymCleanup.
  /// </summary>
  Type_SymCleanup m_apiSymCleanup;

  /// <summary>
  /// Function pointer of SymFromAddrW.
  /// </summary>
  Type_SymFromAddrW m_apiSymFromAddrW;

  /// <summary>
  /// Function pointer of StackWalk64.
  /// </summary>
  Type_StackWalk64 m_apiStackWalk64;

  /// <summary>
  /// Function pointer of MiniDumpWriteDump.
  /// </summary>
  Type_MiniDumpWriteDump m_apiMiniDumpWriteDump;

  /// <summary>
  /// Function pointer of FunctionTableAccessRoutine.
  /// </summary>
  FARPROC m_functionTableAccessRoutine;
};
}
#endif
