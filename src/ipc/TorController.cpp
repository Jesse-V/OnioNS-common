
#include "TorController.hpp"
#include "../Log.hpp"
#include "../Utils.hpp"
#include <botan/hex_filt.h>
#include <botan/pipe.h>
#include <thread>
#include <chrono>


TorController::TorController(const std::string& host, short controlPort)
    : socket_(std::make_shared<ClientSocket>(host, controlPort))
{
}



bool TorController::connect()
{
  try
  {
    socket_->open();
    return true;
  }
  catch (const jsonrpc::JsonRpcException& ex)
  {
    Log::get().debug(ex.what());
    return false;
  }
}


bool TorController::authenticateToTor(bool usePassword)
{
  std::string auth =
      usePassword ? getPassword() : getCookieHash(getCookiePath());

  Log::get().debug("Read Tor authentication.");

  bool success;
  if (usePassword)
    success = command("AUTHENTICATE \"" + auth + "\"");
  else
    success = command("AUTHENTICATE " + auth);

  if (success)
    Log::get().notice("Successfully authenticated to Tor.");
  else
    Log::get().error("Failed to authenticate to Tor.");

  return success;
}



void TorController::waitForBootstrap()
{
  std::string response;
  const std::string readyState = "BOOTSTRAP PROGRESS=100";
  Log::get().debug("Waiting for Tor to bootstrap...");

  while (response.find(readyState) == std::string::npos)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    response = writeRead("GETINFO status/bootstrap-phase");
  }

  Log::get().debug("Bootstrap complete.");
  if (socket_->readLine() != "250 OK")
    Log::get().warn("Expected \"250 OK\" after bootstrap status!");
}



bool TorController::setSetting(const std::string& variable,
                               const std::string& value)
{
  if (command("SETCONF " + variable + "=" + value))
    return true;
  else
  {
    Log::get().debug("Failed setting \"" + variable + "\" = \"" + value + "\"");
    Log::get().warn("Issue applying Tor configuration setting!");
    return false;
  }
}



bool TorController::reloadSettings()
{
  return command("SIGNAL RELOAD");
}



std::string TorController::getSetting(const std::string& variable)
{
  std::string response = writeRead("GETCONF " + variable);
  Log::get().debug("Tor conf for \"" + variable + "\" is \"" + response + "\"");

  if (socket_->readLine() != "250 OK")
    Log::get().warn("Expected \"250 OK\" after GETCONF!");

  auto words = Utils::split(response.c_str());
  if (words[0] != "250")
  {
    Log::get().warn("Unexpected response to GETINFO! " + response);
    return "";
  }

  return response.substr(0, response.size() - 2);  // cut out /r/n
}



std::string TorController::getCookiePath()
{
  try
  {
    Log::get().debug("Getting path to Tor's auth cookie...");

    if (writeRead("protocolinfo") != "250-PROTOCOLINFO 1")
      Log::get().error("Unexpected ProtocolInfo header!");

    std::string cookieStr = socket_->readLine();
    std::string needle = "COOKIEFILE=";
    auto pos = cookieStr.find(needle);
    if (pos == std::string::npos)
      Log::get().error("Unexpected response from Tor! \"" + cookieStr + "\"");

    Log::get().debug("Cookie file: " + cookieStr);

    socket_->readLine();  // pop version
    if (socket_->readLine() != "250 OK")
      Log::get().error("Expected 250 OK after protocolInfo!");

    std::size_t pathBegin = pos + needle.size() + 1;
    std::size_t pathEnd = cookieStr.find("\"", pathBegin);
    return cookieStr.substr(pathBegin, pathEnd - pathBegin);
  }
  catch (std::runtime_error& e)
  {
    Log::get().warn("Could not connect to Tor's control port! " +
                    std::string(e.what()));
  }

  return "";
}



std::string TorController::getCookieHash(const std::string& path)
{
  Log::get().debug("Reading cookie file " + path);

  // https://stackoverflow.com/questions/2602013/
  std::ifstream authFile(path);
  if (!authFile)
    Log::get().error("Unable to open cookie file!");

  std::string authBin((std::istreambuf_iterator<char>(authFile)),
                      std::istreambuf_iterator<char>());

  Botan::Pipe pipe(new Botan::Hex_Encoder(Botan::Hex_Encoder::Lowercase));
  pipe.process_msg(authBin);
  return pipe.read_all_as_string();
}



std::string TorController::getPassword()
{
  Log::get().debug("Reading Tor auth password...");

  std::string path = Utils::getWorkingDirectory() + "control.auth_pw";
  Log::get().notice("Reading controller password from " + path);

  std::ifstream pwFile(path);
  if (!pwFile)
    Log::get().error("Unable to open controller password!");

  std::string pw;
  pwFile >> pw;
  Log::get().debug("Read " + pw);
  return pw;
}



bool TorController::command(const std::string& command)
{
  Log::get().debug("Command " + command);
  if (writeRead(command) != "250 OK")
  {
    Log::get().warn("Command failed: " + command);
    return false;
  }

  Log::get().debug("Command complete.");
  return true;
}



std::string TorController::writeRead(const std::string& command)
{
  socketMutex_.lock();
  socket_->writeLine(command);
  std::string response = socket_->readLine();
  socketMutex_.unlock();
  return response;
}



std::shared_ptr<ClientSocket> TorController::getClientSocket() const
{
  return socket_;
}
