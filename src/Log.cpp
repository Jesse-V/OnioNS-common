
#include "Log.hpp"
#include <stdexcept>
#include <iostream>

std::string Log::logPath_;


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
  throw std::runtime_error(str);
}



void Log::log(const std::string& type, const std::string& str)
{
  if (fout_.is_open() || !logPath_.empty())
  {
    fout_ << "[" << type << "] " << str << std::endl;
    fout_.flush();
  }
  else
  {
    std::cout << "[" << type << "] " << str << std::endl;
    std::cout.flush();
  }
}



void Log::setLogPath(const std::string& logPath)
{
  logPath_ = logPath;
}
