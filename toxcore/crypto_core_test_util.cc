#include "crypto_core_test_util.hh"

#include <cstring>
#include <iomanip>

#include "crypto_core.h"
#include "test_util.hh"

PublicKey random_pk(const Random *rng)
{
    PublicKey pk;
    random_bytes(rng, pk.data(), pk.size());
    return pk;
}

std::ostream &operator<<(std::ostream &out, PublicKey const &pk)
{
    out << '"';
    for (uint8_t byte : pk) {
        out << std::setw(2) << std::setfill('0') << std::hex << uint32_t(byte);
    }
    out << '"';
    return out;
}
