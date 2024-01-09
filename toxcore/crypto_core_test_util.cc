#include "crypto_core_test_util.hh"

#include <cstring>
#include <iomanip>

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

static uint64_t simple_rng(uint64_t &seed)
{
    // https://nuclear.llnl.gov/CNP/rng/rngman/node4.html
    seed = 2862933555777941757LL * seed + 3037000493LL;
    return seed;
}

static void test_random_bytes(void *obj, uint8_t *bytes, size_t length)
{
    Test_Random *self = static_cast<Test_Random *>(obj);

    if (length >= sizeof(uint64_t)) {
        for (size_t i = 0; i < length - sizeof(uint64_t) + 1; i += sizeof(uint64_t)) {
            uint64_t const num = simple_rng(self->seed);
            std::memcpy(&bytes[i], &num, sizeof(uint64_t));
        }
    }

    size_t const rem = length % sizeof(uint64_t);
    if (rem != 0) {
        uint64_t const num = simple_rng(self->seed);
        std::memcpy(&bytes[length - rem], &num, rem);
    }
}

static uint32_t test_random_uniform(void *obj, uint32_t upper_bound)
{
    Test_Random *self = static_cast<Test_Random *>(obj);
    return static_cast<uint32_t>(simple_rng(self->seed)) % upper_bound;
}

Random_Funcs const Test_Random::vtable = {
    test_random_bytes,
    test_random_uniform,
};

Test_Random::Test_Random()
    : self{&vtable, this}
{
}

Test_Random::operator Random const *() const { return &self; }
