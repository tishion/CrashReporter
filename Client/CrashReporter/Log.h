#ifndef LOG_H_
#define LOG_H_
#pragma once

// Logger replacement
class LoggerReplacement
{
public:
  template<typename T>
  LoggerReplacement& operator<<(T value)
  {
    return *this;
  }
};
extern LoggerReplacement loggerReplacement;

// Replace the log macros with the replacement
#define LogError(x) loggerReplacement << x
#define LogInfo(x) loggerReplacement << x

#endif
