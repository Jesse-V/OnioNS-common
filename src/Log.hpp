
#ifndef LOG_HPP
#define LOG_HPP

#include <fstream>
#include <string>

class Log
{
 public:
  static Log& get()
  {
    static Log instance;
    return instance;
  }

  void notice(const std::string&);
  void warn(const std::string&);
  void error(const std::string&);

 private:
  Log();
  Log(Log const&) = delete;
  void operator=(Log const&) = delete;

  void log(const std::string&, const std::string&);
  std::fstream fout;
};

// Log::Notice& operator<<(Log::Notice&, int);

#endif
