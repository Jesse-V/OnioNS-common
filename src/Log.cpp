
#include "Log.hpp"
#include <stdexcept>
#include <ctime>
#include <iostream>

std::string Log::logPath_;
bool Log::verbosity_ = false;

Log::Log()
{
  if (logPath_.empty())
    return;  // don't open file

  fout_.open(logPath_, std::fstream::out | std::fstream::app);

  if (fout_.is_open())
  {
    notice("Successfully opened log file.");
    std::cout << "Opened log file, further output will be there." << std::endl;
  }
  else
  {
    std::cout << "Error opening file";
  }
}



void Log::debug(const std::string& str)
{
  if (verbosity_)
    log("debug ", str);
}



void Log::notice(const std::string& str)
{
  log("notice", str);
}



void Log::warn(const std::string& str)
{
  log("warn  ", str);
}



void Log::error(const std::string& str)
{
  log("error ", str);
  exit(1);
}



void Log::log(const std::string& type, const std::string& str)
{
  mutex_.lock();  // stops interlacing output

  std::time_t t = std::time(NULL);
  char tStr[100];
  std::strftime(tStr, sizeof(tStr), "%H:%M:%S", std::localtime(&t));

  if (fout_.is_open() || !logPath_.empty())
    fout_ << "[" << type << " | " << tStr << "] " << str << std::endl;
  else
    std::cout << "[" << type << " | " << tStr << "] " << str << std::endl;

  mutex_.unlock();
}



void Log::setLogPath(const std::string& logPath)
{
  get().notice("Log path set to " + logPath_);
  logPath_ = logPath;
}



void Log::setVerbosity(bool v)
{
  if (v)
    get().warn("Verbosity is enabled. Use caution when sharing debug output!");
  verbosity_ = v;
}
