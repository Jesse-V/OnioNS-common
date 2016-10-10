
#include <botan/botan.h>

void ED25519_FN(ed25519_randombytes_unsafe)(void* p, size_t len)
{
  static Botan::AutoSeeded_RNG rng;
  rng.randomize((unsigned char*)p, len);
}
