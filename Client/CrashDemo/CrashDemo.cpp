// CrashDemo.cpp : This file contains the 'main' function. Program execution
// begins and ends there.
//

#include <windows.h>
#include <tchar.h>

#include <iostream>

#include "../CrashReporter/CrashReporter.hpp"

int
main()
{
  CrashReporter::InitializeCrashReporter(_T("CrashDemo"));

  *(int*)0 = 0;
  std::cout << "Hello World!\n";

  return 0;
}
