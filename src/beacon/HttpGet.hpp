
#ifndef HTTP_GET_HPP
#define HTTP_GET_HPP

#include <curl/curl.h>
#include <string>

// HMAC_SHA256(BlockHeader concat Hash(BlockHeader), Hash("OnioNS entropy
// extractor"))
// BlockHeader is 640 bits

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
