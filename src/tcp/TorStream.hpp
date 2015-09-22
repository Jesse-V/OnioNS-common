
#ifndef TOR_STREAM_HPP
#define TOR_STREAM_HPP

#include "socks5/Socks5.hpp"
#include <json/json.h>
#include <string>

typedef std::shared_ptr<boost::asio::ip::tcp::socket> SocketPtr;

class TorStream
{
 public:
  TorStream(const std::string&, ushort, const std::string&, ushort);
  virtual ~TorStream() {}
  virtual Json::Value sendReceive(const std::string&, const std::string&);
  SocketPtr getSocket() const;
  boost::asio::io_service& getIO();

 private:
  bool confirmProtocol();
  void waitUntilReady() const;

  static void initCallback(Socks5::Error,
                           boost::system::error_code,
                           Socks5::AuthMethod);
  void contactCallback(Socks5::Error, boost::system::error_code, Socks5::Reply);

  boost::asio::io_service ios_;
  SocketPtr socket_;
  std::shared_ptr<Socks5::Socks5> socks_;
  bool ready_;
};

#endif
