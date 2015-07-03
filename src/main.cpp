

#include "Flags.hpp"

int main(int argc, char** argv)
{
  if (!Flags::get().parse(argc, argv))
    return EXIT_FAILURE;

  return EXIT_SUCCESS;
}
