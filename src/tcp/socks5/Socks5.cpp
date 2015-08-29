
#include "Socks5.hpp"

namespace Socks5
{
Socks5::Socks5(boost::asio::ip::tcp::socket& socket) : socket_(socket)
{
  memset(buffer_, 0, 255);
}



void Socks5::initialize(std::initializer_list<AuthMethod> methods,
                        InitCallback callback)
{
  initializeCallbackFunc_ = callback;

  initRequest_.nmethods = methods.size();
  size_t i = 0;
  for (auto method : methods)
  {
    initRequest_.methods[i] = method;
    ++i;
  }

  using namespace std::placeholders;
  socket_.async_send(boost::asio::buffer(reinterpret_cast<char*>(&initRequest_),
                                         initRequest_.nmethods + 2),
                     std::bind(&Socks5::initializeCallback, this, _1, _2));
}



void Socks5::request(Request req, RequestCallback callback)
{
  requestCallbackFunc_ = callback;

  using namespace std::placeholders;
  boost::asio::mutable_buffers_1 buffer = req.toBuffer();
  socket_.async_send(buffer, std::bind(&Socks5::requestCallback, this, _1, _2));
}



void Socks5::initializeCallback(boost::system::error_code ec, size_t)
{
  if (ec.value() != 0)
    initializeCallbackFunc_(Error::INIT_SEND_ERROR, ec, AuthMethod::NO_METHODS);
  else
    initializeReply();
}



void Socks5::initializeReply()
{
  using namespace std::placeholders;
  socket_.async_receive(
      boost::asio::buffer(reinterpret_cast<char*>(&initReply_),
                          sizeof(initReply_)),
      std::bind(&Socks5::initializeReplyCallback, this, _1, _2));
}



void Socks5::initializeReplyCallback(boost::system::error_code ec, size_t)
{
  if (ec.value() != 0)
    initializeCallbackFunc_(Error::INIT_RECEIVE_ERROR, ec,
                            AuthMethod::NO_METHODS);
  else
    initializeCallbackFunc_(Error::NO_ERROR, ec, initReply_.method);
}



void Socks5::requestCallback(boost::system::error_code ec, size_t)
{
  if (ec.value() != 0)
    requestCallbackFunc_(Error::REQUEST_SEND_ERROR, ec, Reply());
  else
    requestReply();
}



void Socks5::requestReply()
{
  boost::asio::mutable_buffers_1 buffer(buffer_, 255);
  using namespace std::placeholders;
  socket_.async_receive(buffer,
                        std::bind(&Socks5::requestReplyCallback, this, _1, _2));
}



void Socks5::requestReplyCallback(boost::system::error_code ec, size_t bufsize)
{
  if (ec.value() != 0)
  {
    requestCallbackFunc_(Error::REPLY_RECEIVE_ERROR, ec, Reply());
  }
  else
  {
    boost::asio::mutable_buffer buffer(buffer_, bufsize);
    requestCallbackFunc_(Error::NO_ERROR, ec, Reply(buffer));
  }
}
}
