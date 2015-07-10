
#include "Log.hpp"
#include <stdexcept>
#include <iostream>


Log::Log()
{
  fout.open("Browser/TorBrowser/OnioNS/events.log",
            std::fstream::out | std::fstream::app);

  if (fout.is_open())
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
  log("warn", str);
}



void Log::error(const std::string& str)
{
  log("error", str);
  throw std::runtime_error(str);
}



void Log::log(const std::string& type, const std::string& str)
{
  if (fout.is_open())
    fout << "[" << type << "] " << str << std::endl;
  else
    std::cout << "[" << type << "] " << str << std::endl;
}



/*
Log::Notice& Log::Notice::operator<<(int i)
{
  std::cout << i << std::endl;
  return *this;
}


Env::Notice& Env::Notice::operator>>(std::string& str)
{
  return *this;
}*/
