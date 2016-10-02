
#include "HttpGet.hpp"
#include <sstream>
/*
size_t write_data(void* ptr, size_t size, size_t nmemb, void* stream)
{
  std::string data((const char*)ptr, (size_t)size * nmemb);
  *((std::stringstream*)stream) << data << std::endl;
  return size * nmemb;
}


HttpGet::HttpGet()
{
  curl = curl_easy_init();
}



HttpGet::~HttpGet()
{
  curl_easy_cleanup(curl);
}



std::string HttpGet::get(const std::string& url)
{  // this code is very similar to socks5client.cpp

  // url_easy_setopt(curl, CURLOPT_PROXY,
  //                ("socks5h://" + socksIP + ":" + socksPort)
  //                    .c_str());  // socks5, remote resolving

  curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  // curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1); //Prevent "longjmp causes
  // uninitialized stack frame" bug
  curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "gzip, deflate");
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);

  std::stringstream out;
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &out);

  CURLcode res = curl_easy_perform(curl);

  if (res != CURLE_OK)
  {
    std::stringstream str;
    str << "libcurl error: " << res;

    if (res == 7)
      str << " -> Could not connect to " << url;
    else if (res == 28)
      str << " -> Operation timed out";

    // throw JsonRpcException(Errors::ERROR_CLIENT_CONNECTOR, str.str());
  }

  long http_code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

  if (http_code != 200)
  {
    // throw JsonRpcException(Errors::ERROR_RPC_INTERNAL_ERROR, result);
  }

  return out.str();
}
*/
