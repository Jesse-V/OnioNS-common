
#include <botan/botan.h>
#include <iostream>

void ED25519_FN(ed25519_randombytes_unsafe)(void* p, size_t len)
{
  std::cout << "heyrand\n";
  Botan::AutoSeeded_RNG rng;
  rng.randomize((unsigned char*)p, len);
}
