#include "../doubles/fake_random.hh"

#include <algorithm>

#include "../../../toxcore/tox_random_impl.h"

namespace tox::test {

// --- Trampolines for Tox_Random_Funcs ---

static const Tox_Random_Funcs kFakeRandomVtable = {
    .bytes_callback
    = [](void *obj, uint8_t *bytes,
          uint32_t length) { static_cast<FakeRandom *>(obj)->bytes(bytes, length); },
    .uniform_callback
    = [](void *obj,
          uint32_t upper_bound) { return static_cast<FakeRandom *>(obj)->uniform(upper_bound); },
};

FakeRandom::FakeRandom(uint64_t seed)
    : rng_(seed)
{
}

void FakeRandom::set_entropy_source(EntropySource source) { entropy_source_ = std::move(source); }

void FakeRandom::set_observer(Observer observer) { observer_ = std::move(observer); }

uint32_t FakeRandom::uniform(uint32_t upper_bound)
{
    if (upper_bound == 0) {
        return 0;
    }

    // If we are recording (observer set) or replaying (entropy source set),
    // we want consistency. Legacy behavior derived uniform from bytes.
    if (entropy_source_ || observer_) {
        uint32_t raw_val = 0;
        bytes(reinterpret_cast<uint8_t *>(&raw_val), sizeof(raw_val));
        return raw_val % upper_bound;
    }

    std::uniform_int_distribution<uint32_t> dist(0, upper_bound - 1);
    return dist(rng_);
}

void FakeRandom::bytes(uint8_t *out, size_t count)
{
    if (entropy_source_) {
        entropy_source_(out, count);
    } else {
        std::uniform_int_distribution<uint16_t> dist(0, 255);
        std::generate_n(out, count, [&]() { return static_cast<uint8_t>(dist(rng_)); });
    }

    if (observer_) {
        observer_(out, count);
    }
}

struct Tox_Random FakeRandom::get_c_random() { return Tox_Random{&kFakeRandomVtable, this}; }

}  // namespace tox::test
