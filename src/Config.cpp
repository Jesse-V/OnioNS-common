
#include "Config.hpp"
#include <fstream>


Json::Value Config::getAuthority()
{
  return loadFile("/var/lib/tor-onions/authority.json");
}



Json::Value Config::getMirror()
{
  return loadFile("/var/lib/tor-onions/mirrors.json");
}



Json::Value Config::loadFile(const std::string& path)
{
  Json::Value value;
  std::ifstream file(path, std::ifstream::binary);
  file >> value;
  return value;
}
