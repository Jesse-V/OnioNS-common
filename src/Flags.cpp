
#include "Flags.hpp"
//#include "utils.hpp"
//#include <stdexcept>
#include <stdio.h>
#include <stdlib.h>
#include <popt.h>


bool Flags::parse(int argc, char** argv)
{
  /*
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

  return true;*/

  // values for optiona, optionb, optionc, flag1, flag2
  // These values will be updated by popt
  int optiona = -1, optionb = -1, optionc = -1;
  int flag1 = 0, flag2 = 0;

  // options a, b, c take integer arguments
  // options f and g take no arguments
  poptContext pc;
  struct poptOption po[] = {
      {"optiona",
       'a',
       POPT_ARG_INT,
       &optiona,
       11001,
       "descrip1",
       "argDescrip1"},
      {"optionb",
       'b',
       POPT_ARG_INT,
       &optionb,
       11002,
       "descrip2",
       "argDescrip2"},
      {"optionc",
       'c',
       POPT_ARG_INT,
       &optionc,
       11003,
       "descrip3",
       "argDescrip3"},
      {"flag1", 'f', POPT_ARG_NONE, &flag1, 11004, "descrip4", "argDescrip4"},
      {"flag2", 'g', POPT_ARG_NONE, &flag2, 11005, "descrip5", "argDescrip5"},
      POPT_AUTOHELP{NULL}};

  // pc is the context for all popt-related functions
  pc = poptGetContext(NULL, argc, (const char**)argv, po, 0);
  poptSetOtherOptionHelp(pc, "[ARG...]");
  if (argc < 2)
  {
    poptPrintUsage(pc, stderr, 0);
    exit(1);
  }

  // process options and handle each val returned
  int val;
  while ((val = poptGetNextOpt(pc)) >= 0)
  {
    printf("poptGetNextOpt returned val %d\n", val);
  }

  // poptGetNextOpt returns -1 when the final argument has been parsed
  // otherwise an error occured
  if (val != -1)
  {
    // handle error
    switch (val)
    {
      case POPT_ERROR_NOARG:
        printf("Argument missing for an option\n");
        exit(1);
      case POPT_ERROR_BADOPT:
        printf("Option's argument could not be parsed\n");
        exit(1);
      case POPT_ERROR_BADNUMBER:
      case POPT_ERROR_OVERFLOW:
        printf("Option could not be converted to number\n");
        exit(1);
      default:
        printf("Unknown error in option processing\n");
        exit(1);
    }
  }

  // Handle ARG... part of commandline
  while (poptPeekArg(pc) != NULL)
  {
    char* arg = (char*)poptGetArg(pc);
    printf("poptGetArg returned arg: \"%s\"\n", arg);
  }

  // Done. Print final result.
  printf("--- end of popt_basic ---\n");
  printf("final value of optiona: %d\n", optiona);
  printf("final value of optionb: %d\n", optionb);
  printf("final value of optionc: %d\n", optionc);
  printf("final value of flag1: %d\n", flag1);
  printf("final value of flag2: %d\n", flag2);

  return true;
}



std::string Flags::getKeyPath() const
{
  return keyPath_;
}
