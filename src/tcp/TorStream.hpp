
#ifndef TOR_STREAM_HPP
#define TOR_STREAM_HPP

#include "socks5/Socks5.hpp"
#include <json/json.h>
#include <string>

class TorStream
{
 public:
  TorStream(const std::string&, ushort, const std::string&, ushort);
  Json::Value sendReceive(const std::string&, const std::string&);

 private:
  bool confirmProtocol();
  void waitUntilReady();

  static void initCallback(Socks5::Error,
                           boost::system::error_code,
                           Socks5::AuthMethod);
  void contactCallback(Socks5::Error, boost::system::error_code, Socks5::Reply);

  boost::asio::io_service ios_;
  boost::asio::ip::tcp::socket socket_;
  std::shared_ptr<Socks5::Socks5> socks_;
  bool ready_;
};

#endif
