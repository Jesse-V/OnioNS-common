
#ifndef TOR_CONTROLLER_HPP
#define TOR_CONTROLLER_HPP

#include "jsonrpccpp/client/connectors/tcpsocketclient.h"
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
  std::shared_ptr<jsonrpc::TcpSocketClient> getClientSocket() const;
  std::string getPassword();

 private:
  std::string getCookieHash(const std::string&);
  std::shared_ptr<jsonrpc::TcpSocketClient> client_;
};

#endif
