
#include "TorStream.hpp"
#include "../Log.hpp"
#include <chrono>
#include <thread>


TorStream::TorStream(const std::string& socksHost,
                     ushort socksPort,
                     const std::string& remoteHost,
                     ushort remotePort)
    : socket_(std::make_shared<boost::asio::ip::tcp::socket>(ios_)),
      socks_(std::make_shared<Socks5::Socks5>(*socket_)),
      ready_(false)
{
  boost::asio::ip::tcp::resolver resolver(ios_);
  boost::asio::ip::tcp::endpoint endpoint =
      *resolver.resolve({socksHost, std::to_string(socksPort)});
  socket_->connect(endpoint);

  socks_->initialize({Socks5::AuthMethod::NO_AUTHENTICATION},
                     [&](Socks5::Error err, boost::system::error_code ec,
                         Socks5::AuthMethod method)
                     {
                       // notify callback
                       TorStream::initCallback(err, ec, method);

                       // connect to remote host
                       Socks5::Request request(Socks5::Command::CONNECT,
                                               Socks5::AddressType::DOMAIN_NAME,
                                               remoteHost, remotePort);

                       // send request, call TorStream's contact callback
                       socks_->request(
                           request,  // https://ideone.com/jdlQoe
                           [this](Socks5::Error e, boost::system::error_code c,
                                  Socks5::Reply r)
                           {
                             this->contactCallback(e, c, r);
                           });
                     });

  ios_.run();
}



Json::Value TorStream::sendReceive(const std::string& type,
                                   const std::string& msg)
{
  if (!ready_)
  {
    Log::get().warn("Stream not ready. Waiting for connection to remote host.");
    waitUntilReady();
  }

  Json::Value outVal;
  outVal["type"] = type;
  outVal["value"] = msg;
  Json::FastWriter writer;
  boost::asio::write(*socket_, boost::asio::buffer(writer.write(outVal)));

  // read from socket until newline
  Log::get().notice("Receiving response from remote host... ");
  boost::asio::streambuf response;
  boost::asio::read_until(*socket_, response, "\n");

  // convert to string
  std::istream is(&response);
  std::string responseStr((std::istreambuf_iterator<char>(is)),
                          std::istreambuf_iterator<char>());

  // parse into JSON object
  Json::Reader reader;
  Json::Value responseVal;
  if (!reader.parse(responseStr, responseVal))
    responseVal["error"] = "Failed to parse response from server.";

  if (!responseVal.isMember("type") || !responseVal.isMember("value"))
    responseVal["error"] = "Invalid response from server.";

  Log::get().notice("I/O complete.");

  return responseVal;
}



SocketPtr TorStream::getSocket() const
{
  return socket_;
}



boost::asio::io_service& TorStream::getIO()
{
  return ios_;
}



// ************************** PRIVATE METHODS ****************************** //



bool TorStream::confirmProtocol()
{
  auto response = sendReceive("SYN", "");
  if (response["type"] == "success" && response["value"] == "ACK")
  {
    Log::get().notice("Server confirmed up.");
    return true;
  }
  else
  {
    Json::FastWriter writer;
    Log::get().notice(writer.write(response));
    Log::get().error("Server did not return a valid response!");
    return false;
  }
}



void TorStream::initCallback(Socks5::Error err,
                             boost::system::error_code ec,
                             Socks5::AuthMethod)
{
  if (err == Socks5::Error::NO_ERROR)
    Log::get().notice("Successfully connected to Tor's Socks5 port.");
  else if (err == Socks5::Error::INIT_SEND_ERROR)
    Log::get().error("Socks5 send error: " + ec.message());
  else if (err == Socks5::Error::INIT_RECEIVE_ERROR)
    Log::get().error("Socks5 receive error: " + ec.message());
  else
    Log::get().warn("Unexpected Socks5 response from Tor.");
}



void TorStream::contactCallback(Socks5::Error err,
                                boost::system::error_code,
                                Socks5::Reply reply)
{
  if (err == Socks5::Error::NO_ERROR &&
      reply.getReply() == Socks5::ReplyCode::SUCCEEDED)
  {
    // Log::get().notice("Stream established with remote host.");
    ready_ = true;
    if (!confirmProtocol())
      ready_ = false;
  }
  else
  {
    Log::get().warn("Could not establish a connection with remote host.");

    if (err == Socks5::Error::REQUEST_SEND_ERROR)
      Log::get().warn("Socks5 send issue.");
    else if (err == Socks5::Error::REPLY_RECEIVE_ERROR)
      Log::get().warn("Socks5 receive issue.");

    if (reply.getReply() == Socks5::ReplyCode::GENERAL_SOCKS_FAILURE)
      Log::get().error("Socks5 response: General SOCKS failure.");
    else if (reply.getReply() ==
             Socks5::ReplyCode::CONNECTION_NOT_ALLOWED_RULESET)
      Log::get().error("Socks5 response: Connection not allowed.");
    else if (reply.getReply() == Socks5::ReplyCode::NETWORK_UNREACHABLE)
      Log::get().error("Socks5 response: Network unreachable.");
    else if (reply.getReply() == Socks5::ReplyCode::HOST_UNREACHABLE)
      Log::get().error("Socks5 response: General SOCKS failure");
    else if (reply.getReply() == Socks5::ReplyCode::CONNECTION_REFUSED)
      Log::get().error("Socks5 response: Connection refused.");
    else if (reply.getReply() == Socks5::ReplyCode::TTL_EXPIRED)
      Log::get().error("Socks5 response: TTL expired.");
    else if (reply.getReply() == Socks5::ReplyCode::ADDRESS_TYPE_NOT_SUPPORTED)
      Log::get().error("Socks5 response: Address type not supported.");
  }
}



void TorStream::waitUntilReady() const
{
  std::chrono::milliseconds time(50);
  while (!ready_)
    std::this_thread::sleep_for(time);
}
