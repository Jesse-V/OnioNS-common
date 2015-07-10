
#ifndef CACHE_HPP
#define CACHE_HPP

#include "records/Record.hpp"
#include <vector>

class Cache
{
 public:
  static bool add(const RecordPtr& record);
  static bool add(const std::vector<RecordPtr>&);
  static std::vector<RecordPtr> getSortedList();
  static RecordPtr get(const std::string&);

 private:
  static std::vector<RecordPtr> records_;
};

#endif
