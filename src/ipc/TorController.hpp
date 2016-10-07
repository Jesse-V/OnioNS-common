
#ifndef TOR_CONTROLLER_HPP
#define TOR_CONTROLLER_HPP

#include "ClientSocket.hpp"
#include <memory>
#include <string>

class TorController
{
 public:
  TorController(const std::string&, short);

  bool authenticateToTor(bool usePassword = false);
  void waitForBootstrap();
  bool reloadSettings();
  bool setSetting(const std::string&, const std::string&);
  std::string getSetting(const std::string&);
  std::string getCookiePath();
  std::shared_ptr<ClientSocket> getClientSocket() const;
  std::string getPassword();
  bool command(const std::string&);

 private:
  std::string getCookieHash(const std::string&);
  std::shared_ptr<ClientSocket> socket_;
};

#endif
