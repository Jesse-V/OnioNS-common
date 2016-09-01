/*************************************************************************
 * libjson-rpc-cpp
 *************************************************************************
 * @file    socks5client.cpp
 * @date    2016-08-31
 * @author  Jesse Victors <github@jessevictors.com>
 * @license See attached LICENSE.txt
 ************************************************************************/

#include "socks5client.h"
#include <string>
#include <string.h>
#include <cstdlib>
#include <iostream>

using namespace jsonrpc;

/**
 * taken from
 * http://stackoverflow.com/questions/2329571/c-libcurl-get-output-into-a-string
 */
struct string
{
  char* ptr;
  size_t len;
};

static size_t writefunc(void* ptr, size_t size, size_t nmemb, struct string* s)
{
  size_t new_len = s->len + size * nmemb;
  s->ptr = (char*)realloc(s->ptr, new_len + 1);
  memcpy(s->ptr + s->len, ptr, size * nmemb);
  s->ptr[new_len] = '\0';
  s->len = new_len;
  return size * nmemb;
}

Socks5Client::Socks5Client(
    const std::string& ip,
    const std::string& port,
    const std::string& destination) throw(JsonRpcException)
    : socksIP(ip),
      socksPort(port),
      url(destination),
      timeout(25000)  // todo: should be 10 seconds at most
{
  curl = curl_easy_init();
}

Socks5Client::~Socks5Client()
{
  curl_easy_cleanup(curl);
}

void Socks5Client::SendRPCMessage(const std::string& message,
                                  std::string& result) throw(JsonRpcException)
{
  curl_easy_setopt(curl, CURLOPT_PROXY,
                   ("socks5h://" + socksIP + ":" + socksPort)
                       .c_str());  // socks5, remote resolving
  curl_easy_setopt(curl, CURLOPT_URL, this->url.c_str());
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, writefunc);

  struct string s;
  s.len = 0;
  s.ptr = new char[1];
  s.ptr[0] = '\0';

  curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, message.size());
  curl_easy_setopt(curl, CURLOPT_POSTFIELDS, message.c_str());
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &s);
  curl_easy_setopt(curl, CURLOPT_TIMEOUT_MS, timeout);

  CURLcode res = curl_easy_perform(curl);

  result = s.ptr;
  free(s.ptr);
  if (res != CURLE_OK)
  {
    std::stringstream str;
    str << "libcurl error: " << res;

    if (res == 7)
      str << " -> Could not connect to " << this->url;
    else if (res == 28)
      str << " -> Operation timed out";
    throw JsonRpcException(Errors::ERROR_CLIENT_CONNECTOR, str.str());
  }

  long http_code = 0;
  curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);

  if (http_code != 200)
  {
    throw JsonRpcException(Errors::ERROR_RPC_INTERNAL_ERROR, result);
  }

  // curl_easy_cleanup(curl);
}

void Socks5Client::SetSocksIP(const std::string& ip)
{
  this->socksIP = ip;
}

void Socks5Client::SetSocksPort(const std::string& port)
{
  this->socksPort = port;
}

void Socks5Client::SetSocksDestination(const std::string& url)
{
  this->url = url;
}

void Socks5Client::SetTimeout(long timeout)
{
  this->timeout = timeout;
}
