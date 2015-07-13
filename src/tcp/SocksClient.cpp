
#include "SocksClient.hpp"
#include "SocksRequest.hpp"
#include "SocksReply.hpp"
#include "../Constants.hpp"
#include "../Log.hpp"

using boost::asio::ip::tcp;


SocksClient::SocksClient(const std::string& socksIP, short socksPort)
    : ios_(std::make_shared<boost::asio::io_service>()),
      socket_(*ios_),
      resolver_(*ios_)
{
  Log::get().notice("Connecting to Tor's SOCKS...");
  tcp::resolver::query socks_query(socksIP, std::to_string(socksPort));
  tcp::resolver::iterator endpoint_iterator = resolver_.resolve(socks_query);
  boost::asio::connect(socket_, endpoint_iterator);
}



std::shared_ptr<SocksClient> SocksClient::getCircuitTo(const std::string& host,
                                                       short port,
                                                       short localSOCKS)
{
  try
  {
    // connect over Tor to remote resolver
    Log::get().notice("Testing for Tor...");
    auto socks = std::make_shared<SocksClient>("localhost", localSOCKS);
    socks->connectTo(host, port);
    Log::get().notice("Tor appears to be running.");

    Log::get().notice("Testing connection to the server...");
    auto r = socks->sendReceive("ping", "");
    if (r == "pong")
    {
      Log::get().notice("Server confirmed up.");
      return socks;
    }
    else
    {
      Log::get().warn(r.asString());
      Log::get().warn("Server did not return a valid response!");
      return nullptr;
    }
  }
  catch (boost::system::system_error const& ex)
  {
    Log::get().warn(ex.what());
    Log::get().warn("Test failed. Cannot continue.");
    return nullptr;
  }
}



Json::Value SocksClient::sendReceive(const std::string& type,
                                     const std::string& msg)
{
  Log::get().notice("Sending... ");

  // send as JSON
  Json::Value outVal;
  outVal["command"] = type;
  outVal["value"] = msg;
  Json::FastWriter writer;
  boost::asio::write(socket_, boost::asio::buffer(writer.write(outVal)));

  // read from socket until newline
  Log::get().notice("receiving... ");
  boost::asio::streambuf response;
  boost::asio::read_until(socket_, response, "\n");

  // convert to string
  std::string responseStr;
  std::istream is(&response);
  is >> responseStr;

  // parse into JSON object
  Json::Reader reader;
  Json::Value responseVal;
  if (!reader.parse(responseStr, responseVal))
    responseVal["error"] = "Failed to parse response from server.";

  if (!responseVal.isMember("error") && !responseVal.isMember("response"))
    responseVal["error"] = "Invalid response from server.";

  Log::get().notice("done.");

  return responseVal;
}



// ***************************** PRIVATE METHODS *****************************



void SocksClient::connectTo(const std::string& host, short port)
{
  Log::get().notice("Connecting to remote host...");
  tcp::resolver::query query(tcp::v4(), host, std::to_string(port));
  endpoint_ = *resolver_.resolve(query);

  if (!checkConnection())
    Log::get().error("Remote host refused connection.");
}



bool SocksClient::checkConnection()
{
  Log::get().notice("Connecting over Tor...");

  SocksRequest sreq(SocksRequest::connect, endpoint_, "OnioNS");
  boost::asio::write(socket_, sreq.buffers());

  SocksReply srep;
  boost::asio::read(socket_, srep.buffers());

  if (!srep.success())
  {
    Log::get().notice("Connection failed.");
    return false;
  }

  return true;
}
