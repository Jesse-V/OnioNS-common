
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



bool TorController::authenticateToTor(bool usePassword)
{
  std::string auth =
      usePassword ? getPassword() : getCookieHash(getCookiePath());

  bool success;
  if (usePassword)
    success = command("AUTHENTICATE \"" + auth + "\"");
  else
    success = command("AUTHENTICATE " + auth);

  if (success)
    Log::get().notice("Successfully authenticated to Tor.");
  else
    Log::get().warn("Failed to authenticate to Tor.");

  return success;
}



void TorController::waitForBootstrap()
{
  std::string response;
  const std::string readyState = "BOOTSTRAP PROGRESS=100";

  while (response.find(readyState) == std::string::npos)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    socket_->writeLine("GETINFO status/bootstrap-phase");
    response = socket_->readLine();
  }
}



bool TorController::setSetting(const std::string& variable,
                               const std::string& value)
{
  if (command("SETCONF " + variable + "=" + value))
    return true;
  else
  {
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
  socket_->writeLine("GETCONF " + variable);
  std::string response = socket_->readLine();

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
    socket_->writeLine("protocolinfo");

    std::string protocolInfo = socket_->readLine();
    if (protocolInfo != "250-PROTOCOLINFO 1")
      Log::get().error("Expected ProtocolInfo, read \"" + protocolInfo + "\"");

    std::string cookieStr = socket_->readLine();
    std::string needle = "COOKIEFILE=";
    std::size_t pos = cookieStr.find(needle);
    if (pos == std::string::npos)
      Log::get().error("Unexpected response from Tor! \"" + cookieStr + "\"");

    socket_->readLine();  // pop version
    if (socket_->readLine() != "250 OK")
      Log::get().error("Expected 250 OK!");
    ;  // read "250 OK"

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
  Log::get().notice("Reading cookie file " + path);

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
  std::string path = Utils::getWorkingDirectory() + "control.auth_pw";
  Log::get().notice("Reading controller password from " + path);

  std::ifstream pwFile(path);
  if (!pwFile)
    Log::get().error("Unable to open controller password!");

  std::string pw;
  pwFile >> pw;
  return pw;
}



bool TorController::command(const std::string& command)
{
  socket_->writeLine(command);
  if (socket_->readLine() != "250 OK")
  {
    Log::get().warn("Command failed: " + command);
    return false;
  }

  return true;
}



std::shared_ptr<ClientSocket> TorController::getClientSocket() const
{
  return socket_;
}
