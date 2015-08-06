
#ifndef CONFIG_HPP
#define CONFIG_HPP

#include <string>
#include <json/json.h>

class Config
{
 public:
  static Json::Value getQuorumNode();
  static Json::Value getMirror();

 private:
  static Json::Value loadFile(const std::string&);
};

#endif
