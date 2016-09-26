
#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <string>
#include <jsoncpp/json/json.h>

class Config
{  // should be Singleton?

 public:
  static Json::Value loadFile(const std::string&);
};

#endif
