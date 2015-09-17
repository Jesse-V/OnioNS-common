
#include "Config.hpp"
#include <fstream>


#ifndef INSTALL_PREFIX
#error CMake has not defined INSTALL_PREFIX!
#endif


Json::Value Config::getQuorumNode()
{
  return loadFile(INSTALL_PREFIX + "/lib/tor-onions/quorum.json");
}



Json::Value Config::getMirror()
{
  return loadFile(INSTALL_PREFIX + "/lib/tor-onions/mirrors.json");
}



Json::Value Config::loadFile(const std::string& path)
{
  Json::Value value;
  std::ifstream file(path, std::ifstream::binary);
  file >> value;
  return value;
}
