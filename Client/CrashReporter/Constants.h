#pragma once

// Crash report base URI
#if defined(DEBUG) || defined(_DEBUG)
#define BASE_URI "http://localhost:6507"
#else
#define BASE_URI "http://www.xxxx.com"
#endif

// Crash report property names
#define PROPERTY_SIGNATURE "Signature"
#define PROPERTY_PRODUCT_NAME "ProductName"
#define PROPERTY_PRODUCT_VERSION "ProductVersion"
#define PROPERTY_OS_VERSION "OSVersion"
#define PROPERTY_MODULE_NAME "Module"
#define PROPERTY_ADDRESS "Address"
#define PROPERTY_CALLSTACK "CallStack"
#define PROPERTY_APPLICATIONNAME "ApplicationName"
#define PROPERTY_EXCEPTIONADDRESS "ExceptionAddress"
#define PROPERTY_EXCEPTIONMODULE "ExceptionModule"
#define PROPERTY_IPADDRESS "IPAddress"
#define PROPERTY_MACHINEID "MachineId"
#define PROPERTY_DETAIL "Detail"
#define PROPERTY_REPORTLOG "CrashReportLog"

// Response property names
#define PROPERTY_UPLOADTOKEN "token"
#define PROPERTY_SUCCESS "success"
#define PROPERTY_FILENAME "filename"

// Path for report or upload
#define REPORT_PATH "api/crashreport/reportlog"
#define UPLOAD_PATH "api/crashreport/reportdetail"

// Dump folder name
#define DUMP_FOLDER_NAME "AppCrashDumps"
#define DUMP_FOLDER_NAMEW L"AppCrashDumps"
#define TEMP_FOLDER_NAMEW L"Temp"

// Unknown value
#define UNKNOWN_VALUE "Unknown"

// String format
#define TIME_FORMAT "%Y%m%d%H%M%S"
#define DUMP_FILE_NAME_FORMAT "%s_%s.dmp"
#define SUMMARY_FILE_NAME_FORMAT "%s_%s.txt"
#define ZIP_FILE_NAME_FORMAT "%s_%s.zip"
#define MANAGEDCRASHINFOR_FILE_EXTENSION L".mci";

// String used in the summary data file
#define WCHARSTRING(x) L#x
#define CRASH_SIGNATURE "Crash Signature:"
#define CALL_STACK "Call stack:"
#define NEW_LINE "\r\n"
#define MODULE_LISTW L"Module list:"
#define NEW_LINEW L"\r\n"

#define CRASH_REPORTER_EXE_BUILD
#include "CrashReporter.hpp"
