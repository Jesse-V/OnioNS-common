
#ifndef COMMON_HPP
#define COMMON_HPP

#include "containers/records/Record.hpp"
#include <json/json.h>
#include <memory>

class Common
{
 public:
  static RecordPtr parseRecord(const std::string&);
  static RecordPtr parseRecord(const Json::Value&);
  static Json::Value toJSON(const std::string&);
  static std::string getDestination(const RecordPtr&, const std::string&);
  static uint8_t* computeConsensusHash();

 private:
  static RecordPtr assembleRecord(const Json::Value&);
  static void checkValidity(const RecordPtr&);
};

#endif
