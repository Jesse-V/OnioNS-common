
#include "Log.hpp"
#include <stdexcept>
#include <iostream>


Log::Log()
{
  fout.open("Browser/TorBrowser/OnioNS/events.log",
            std::fstream::out | std::fstream::app);
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
  fout << "[" << type << "] " << str << std::endl;
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
