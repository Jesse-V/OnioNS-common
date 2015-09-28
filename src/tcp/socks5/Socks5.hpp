
#ifndef SOCKS5_HPP
#define SOCKS5_HPP

#include "Request.hpp"
#include "Reply.hpp"
#include "Enums.hpp"
#include <boost/asio.hpp>
#include <cstdint>

namespace Socks5
{
class Socks5
{
 public:
  Socks5(boost::asio::ip::tcp::socket& socket);

  using InitCallback =
      std::function<void(Error, boost::system::error_code, AuthMethod)>;
  using RequestCallback =
      std::function<void(Error, boost::system::error_code, Reply)>;

  void initialize(std::initializer_list<AuthMethod>, InitCallback);
  void request(Request, RequestCallback);

 private:
  void initializeCallback(boost::system::error_code, size_t);
  void initializeReply();
  void initializeReplyCallback(boost::system::error_code, size_t);
  void requestCallback(boost::system::error_code, size_t);
  void requestReply();
  void requestReplyCallback(boost::system::error_code, size_t);

  boost::asio::ip::tcp::socket& socket_;
  InitCallback initializeCallbackFunc_;
  RequestCallback requestCallbackFunc_;

  unsigned char buffer_[255];

  struct initRequest
  {
    const uint8_t version = 0x05;
    size_t nmethods;
    AuthMethod methods[255];
  } initRequest_;

  struct initReply
  {
    const uint8_t version = 0x05;
    AuthMethod method;
  } initReply_;
};
}

#endif
