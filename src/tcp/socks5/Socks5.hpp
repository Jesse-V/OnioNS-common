
#ifndef SOCKS5_HPP
#define SOCKS5_HPP

#include "AuthMethod.hpp"
#include "Command.hpp"
#include "AddressType.hpp"
#include "Request.hpp"
#include "Reply.hpp"
#include "Error.hpp"

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
  void initialize_callback_(boost::system::error_code, size_t);
  void initialize_reply_();
  void initialize_reply_callback_(boost::system::error_code, size_t);
  void request_callback_(boost::system::error_code, size_t);
  void request_reply_();
  void request_reply_callback_(boost::system::error_code, size_t);

  boost::asio::ip::tcp::socket& socket_;
  InitCallback initialize_callback_func_;
  RequestCallback request_callback_func_;
  // bool initialized_;

  unsigned char buffer_[255];

  struct init_request
  {
    const uint8_t version = 0x05;
    uint8_t nmethods;
    AuthMethod methods[255];
  } init_request_;

  struct init_reply
  {
    const uint8_t version = 0x05;
    AuthMethod method;
  } init_reply_;
};
}

#endif
