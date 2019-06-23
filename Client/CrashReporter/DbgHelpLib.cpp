#include "Log.h"

#include "DbgHelpLib.h"

// DbugHelp module name
#define DBG_HELP_LIB "DbgHelp.dll"

namespace CrashReporter {
DbgHelpLib::DbgHelpLib()
{
  // Reset all members
  m_hModule = nullptr;
  m_apiSymInitializeW = nullptr;
  m_apiSymCleanup = nullptr;
  m_apiSymFromAddrW = nullptr;
  m_apiStackWalk64 = nullptr;
  m_apiMiniDumpWriteDump = nullptr;
  m_functionTableAccessRoutine = nullptr;
}

DbgHelpLib::~DbgHelpLib() {}

BOOL
DbgHelpLib::InitializeDbgHelpModule()
{
  // If the module was loaded then return false
  if (nullptr == m_hModule) {
    // Load library
    m_hModule = ::LoadLibraryA(DBG_HELP_LIB);

    // Check the result of LoadLibrary
    if (nullptr == m_hModule) {
      // Failed, reset all members and return false
      m_apiSymInitializeW = nullptr;
      m_apiSymCleanup = nullptr;
      m_apiSymFromAddrW = nullptr;
      m_apiStackWalk64 = nullptr;
      m_apiMiniDumpWriteDump = nullptr;
      LogError("Failed to load DbgHelp.dll");
      return FALSE;
    }

    // Get all the function addresses
    m_apiSymInitializeW =
      (Type_SymInitializeW)::GetProcAddress(m_hModule, "SymInitializeW");
    m_apiSymCleanup =
      (Type_SymCleanup)::GetProcAddress(m_hModule, "SymCleanup");
    m_apiSymFromAddrW =
      (Type_SymFromAddrW)::GetProcAddress(m_hModule, "SymFromAddrW");
    m_apiStackWalk64 =
      (Type_StackWalk64)::GetProcAddress(m_hModule, "StackWalk64");
    m_apiMiniDumpWriteDump =
      (Type_MiniDumpWriteDump)::GetProcAddress(m_hModule, "MiniDumpWriteDump");
    m_functionTableAccessRoutine =
      ::GetProcAddress(m_hModule, "SymFunctionTableAccess64");
    return TRUE;
  }

  // Reloading is not allowed
  return FALSE;
}

void
DbgHelpLib::ReleaseDbgHelpModule()
{
  // If the module was loaded
  if (m_hModule) {
    // Unload the module
    ::FreeLibrary(m_hModule);

    // Reset all members
    m_apiSymInitializeW = nullptr;
    m_apiSymCleanup = nullptr;
    m_apiSymFromAddrW = nullptr;
    m_apiStackWalk64 = nullptr;
    m_apiMiniDumpWriteDump = nullptr;
  }
}

BOOL
DbgHelpLib::SymInitializeW(__in HANDLE hProcess,
                           __in_opt PCWSTR UserSearchPath,
                           __in BOOL fInvadeProcess)
{
  // Call the original function
  if (m_apiSymInitializeW)
    return m_apiSymInitializeW(hProcess, UserSearchPath, fInvadeProcess);

  // Invalid function pointer, log and return false
  LogError("Invalid function pointer.");
  return FALSE;
}

BOOL
DbgHelpLib::SymCleanup(__in HANDLE hProcess)
{
  // Call the original function
  if (m_apiSymCleanup)
    return m_apiSymCleanup(hProcess);

  // Invalid function pointer, log and return false
  LogError("Invalid function pointer.");
  return FALSE;
}

BOOL
DbgHelpLib::SymFromAddrW(__in HANDLE hProcess,
                         __in DWORD64 Address,
                         __out_opt PDWORD64 Displacement,
                         __inout PSYMBOL_INFOW Symbol)
{
  // Call the original function
  if (m_apiSymFromAddrW)
    return m_apiSymFromAddrW(hProcess, Address, Displacement, Symbol);

  // Invalid function pointer, log and return false
  LogError("Invalid function pointer.");
  return FALSE;
}

BOOL
DbgHelpLib::StackWalk64(
  __in DWORD MachineType,
  __in HANDLE hProcess,
  __in HANDLE hThread,
  __inout LPSTACKFRAME64 StackFrame,
  __inout PVOID ContextRecord,
  __in_opt PREAD_PROCESS_MEMORY_ROUTINE64 ReadMemoryRoutine,
  __in_opt PFUNCTION_TABLE_ACCESS_ROUTINE64 FunctionTableAccessRoutine,
  __in_opt PGET_MODULE_BASE_ROUTINE64 GetModuleBaseRoutine,
  __in_opt PTRANSLATE_ADDRESS_ROUTINE64 TranslateAddress)
{
  // Call the original function
  if (m_apiStackWalk64) {
    // If the input FunctionTableAccessRoutine is null then try to get the
    // default one
    if (nullptr == FunctionTableAccessRoutine)
      FunctionTableAccessRoutine =
        (PFUNCTION_TABLE_ACCESS_ROUTINE64)m_functionTableAccessRoutine;
    return m_apiStackWalk64(MachineType,
                            hProcess,
                            hThread,
                            StackFrame,
                            ContextRecord,
                            ReadMemoryRoutine,
                            FunctionTableAccessRoutine,
                            GetModuleBaseRoutine,
                            TranslateAddress);
  }

  // Invalid function pointer, log and return false
  LogError("Invalid function pointer.");
  return FALSE;
}

BOOL
DbgHelpLib::MiniDumpWriteDump(
  __in HANDLE hProcess,
  __in DWORD ProcessId,
  __in HANDLE hFile,
  __in MINIDUMP_TYPE DumpType,
  __in_opt PMINIDUMP_EXCEPTION_INFORMATION ExceptionParam,
  __in_opt PMINIDUMP_USER_STREAM_INFORMATION UserStreamParam,
  __in_opt PMINIDUMP_CALLBACK_INFORMATION CallbackParam)
{
  // Call the original function
  if (m_apiMiniDumpWriteDump)
    return m_apiMiniDumpWriteDump(hProcess,
                                  ProcessId,
                                  hFile,
                                  DumpType,
                                  ExceptionParam,
                                  UserStreamParam,
                                  CallbackParam);

  // Invalid function pointer, log and return false
  LogError("Invalid function pointer.");
  return FALSE;
}
}
