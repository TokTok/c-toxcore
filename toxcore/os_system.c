#include "os_system.h"

#include "ccompat.h"
#include "os_memory.h"
#include "os_network.h"
#include "os_random.h"
#include "tox_system_impl.h"

Tox_System os_system(const Tox_Memory *mem, const Tox_Network *ns, const Tox_Random *rng, const Tox_Time *tm)
{
    Tox_System sys = {
        mem != nullptr ? mem : os_memory(),
        ns != nullptr ? ns : os_network(),
        rng != nullptr ? rng : os_random(),
        tm, // no os_time, mono_time has it.
    };

    return sys;
}
