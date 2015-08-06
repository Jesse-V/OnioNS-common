
#include "Config.hpp"
#include <fstream>


Json::Value Config::getQuorumNode()
{
  return loadFile("/var/lib/tor-onions/quorum.json");
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
