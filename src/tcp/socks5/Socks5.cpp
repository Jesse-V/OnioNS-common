
#include "Socks5.hpp"

namespace Socks5
{
Socks5::Socks5(boost::asio::ip::tcp::socket& socket) : socket_(socket)
{
}

void Socks5::initialize(std::initializer_list<AuthMethod> methods,
                        InitCallback callback)
{
  initialize_callback_func_ = callback;

  init_request_.nmethods = methods.size();
  size_t i = 0;
  for (auto method : methods)
  {
    init_request_.methods[i] = method;
    ++i;
  }

  using namespace std::placeholders;
  socket_.async_send(
      boost::asio::buffer(reinterpret_cast<char*>(&init_request_),
                          init_request_.nmethods + 2),
      std::bind(&Socks5::initialize_callback_, this, _1, _2));
}

void Socks5::request(Request req, RequestCallback callback)
{
  request_callback_func_ = callback;

  using namespace std::placeholders;
  boost::asio::mutable_buffers_1 buffer = req.to_buffer();
  socket_.async_send(buffer,
                     std::bind(&Socks5::request_callback_, this, _1, _2));
}

void Socks5::initialize_callback_(boost::system::error_code ec, size_t)
{
  if (ec.value() != 0)
  {
    initialize_callback_func_(Error::init_send_error, ec,
                              AuthMethod::no_methods);
  }
  else
  {
    initialize_reply_();
  }
}

void Socks5::initialize_reply_()
{
  using namespace std::placeholders;
  socket_.async_receive(
      boost::asio::buffer(reinterpret_cast<char*>(&init_reply_),
                          sizeof(init_reply_)),
      std::bind(&Socks5::initialize_reply_callback_, this, _1, _2));
}

void Socks5::initialize_reply_callback_(boost::system::error_code ec, size_t)
{
  if (ec.value() != 0)
  {
    initialize_callback_func_(Error::init_receive_error, ec,
                              AuthMethod::no_methods);
  }
  else
  {
    initialize_callback_func_(Error::no_error, ec, init_reply_.method);
  }
}

void Socks5::request_callback_(boost::system::error_code ec, size_t)
{
  if (ec.value() != 0)
  {
    request_callback_func_(Error::request_send_error, ec, Reply());
  }
  else
  {
    request_reply_();
  }
}

void Socks5::request_reply_()
{
  boost::asio::mutable_buffers_1 buffer(buffer_, 255);
  using namespace std::placeholders;
  socket_.async_receive(
      buffer, std::bind(&Socks5::request_reply_callback_, this, _1, _2));
}

void Socks5::request_reply_callback_(boost::system::error_code ec,
                                     size_t bufsize)
{
  if (ec.value() != 0)
  {
    request_callback_func_(Error::reply_receive_error, ec, Reply());
  }
  else
  {
    boost::asio::mutable_buffer buffer(buffer_, bufsize);
    request_callback_func_(Error::no_error, ec, Reply(buffer));
  }
}
}
