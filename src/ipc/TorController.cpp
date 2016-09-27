
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

  if (usePassword)
    *socket_ << "AUTHENTICATE \"" + auth + "\"\r\n";
  else
    *socket_ << "AUTHENTICATE " + auth + "\r\n";

  std::string response;
  *socket_ >> response;

  if (response == "250 OK\r\n")
  {
    Log::get().notice("Successfully authenticated to Tor.");
    return true;
  }
  else
  {
    Log::get().notice("Tor replied: " + response);
    Log::get().warn("Unexpected answer from Tor!");
    return false;
  }
}



void TorController::waitForBootstrap()
{
  std::string response;
  const std::string readyState = "BOOTSTRAP PROGRESS=100";

  while (response.find(readyState) == std::string::npos)
  {
    std::this_thread::sleep_for(std::chrono::milliseconds(250));
    *socket_ << "GETINFO status/bootstrap-phase\r\n";
    *socket_ >> response;
  }
}



bool TorController::setSetting(const std::string& variable,
                               const std::string& value)
{
  std::string response;
  *socket_ << "SETCONF " << variable << "=" << value << "\r\n";
  *socket_ >> response;

  if (response != "250 OK\r\n")
  {
    Log::get().warn("Issue applying Tor configuration setting! " + response);
    return false;
  }

  return true;
}



bool TorController::reloadSettings()
{
  std::string response;
  *socket_ << "SIGNAL RELOAD\r\n";
  *socket_ >> response;

  if (response != "250 OK\r\n")
  {
    Log::get().warn("Unexpected response to RELOAD! " + response);
    return false;
  }

  return true;
}



std::string TorController::getSetting(const std::string& variable)
{
  std::string response;
  *socket_ << "GETCONF " << variable << "\r\n";
  *socket_ >> response;

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
    *socket_ << "protocolinfo\r\n";

    std::string response;
    *socket_ >> response;

    std::string needle = "COOKIEFILE=";
    std::size_t pos = response.find(needle);
    if (pos == std::string::npos)
      Log::get().error("Unexpected response from Tor!");

    std::size_t pathBegin = pos + needle.size() + 1;
    std::size_t pathEnd = response.find("\"", pathBegin);
    return response.substr(pathBegin, pathEnd - pathBegin);
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



std::shared_ptr<ClientSocket> TorController::getClientSocket() const
{
  return socket_;
}
