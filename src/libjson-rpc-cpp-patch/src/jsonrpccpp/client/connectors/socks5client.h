/*************************************************************************
 * libjson-rpc-cpp
 *************************************************************************
 * @file    socks5client.h
 * @date    2016-08-31
 * @author  Jesse Victors <github@jessevictors.com>
 * @license See attached LICENSE.txt
 ************************************************************************/

#ifndef JSONRPC_CPP_SOCKS5CLIENT_H_
#define JSONRPC_CPP_SOCKS5CLIENT_H_

#include "../iclientconnector.h"
#include <jsonrpccpp/common/exception.h>
#include <curl/curl.h>

namespace jsonrpc
{
class Socks5Client : public IClientConnector
{
 public:
  Socks5Client(const std::string& ip,
               const std::string& port,
               const std::string& destination) throw(JsonRpcException);
  virtual ~Socks5Client();
  virtual void SendRPCMessage(const std::string& message,
                              std::string& result) throw(JsonRpcException);

  void SetSocksIP(const std::string& ip);
  void SetSocksPort(const std::string& port);
  void SetSocksDestination(const std::string& dest);
  void SetTimeout(long timeout);

 private:
  std::string socksIP, socksPort, url;

  /**
   * @brief timeout for http request in milliseconds
   */
  long timeout;
  CURL* curl;
};

} /* namespace jsonrpc */
#endif /* JSONRPC_CPP_SOCKS5CLIENT_H_ */
