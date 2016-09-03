
#ifndef HTTP_GET_HPP
#define HTTP_GET_HPP

#include <curl/curl.h>
#include <string>

class HttpGet
{
 public:
  HttpGet();
  ~HttpGet();
  std::string get(const std::string&);

 private:
  CURL* curl;
};

#endif
