
#ifndef CACHE_HPP
#define CACHE_HPP

#include "records/Record.hpp"
#include <vector>

class Cache
{
 public:
  bool add(const RecordPtr& record);
  bool add(const std::vector<RecordPtr>&);
  std::vector<RecordPtr> getSortedList();
  RecordPtr get(const std::string&) const;

 private:
  std::vector<RecordPtr> records_;
};

#endif
