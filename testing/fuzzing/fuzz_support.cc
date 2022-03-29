#include "fuzz_support.h"

#include <memory>

#include "../../toxcore/network.h"
#include "../../toxcore/tox_private.h"

std::unique_ptr<Tox_System> fuzz_system(uint64_t *clock)
{
    auto sys = std::make_unique<Tox_System>();
    sys->mono_time_callback = [](void *user_data) { return *static_cast<uint64_t *>(user_data); };
    sys->mono_time_user_data = clock;
    sys->ns = system_network(); // TODO(iphydf): Put fuzz_network here.
    return sys;
}
