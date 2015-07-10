
#include "Flags.hpp"
#include "utils.hpp"
#include <tclap/CmdLine.h>
#include <stdexcept>


bool Flags::parse(int argc, char** argv)
{
  if (argc <= 1)
    return false;

  TCLAP::CmdLine cmd(R".(Examples:
      onions-hs --hskey=<keypath>
      ).",
                     '=', "<unknown>");

  TCLAP::SwitchArg licenseFlag("l", "license",
                               "Prints license information and exits.", false);

  TCLAP::ValueArg<std::string> keyPath(
      "k", "hskey", "The path to the private hidden service RSA key.", false,
      "/var/lib/tor-onions/example.key", "keypath");

  cmd.add(licenseFlag);
  cmd.add(keyPath);

  cmd.parse(argc, argv);

  if (licenseFlag.isSet())
  {
    std::cout << "Modified/New BSD License" << std::endl;
    return false;
  }

  if (!keyPath.isSet())
  {
    std::cerr << "HS mode, but missing path to key! Specify with --hskey\n";
    return false;
  }

  keyPath_ = keyPath.getValue();

  return true;
}



std::string Flags::getKeyPath() const
{
  return keyPath_;
}
