#include "tox_system.h"

#include "ccompat.h"
#include "tox_system_impl.h"

Tox_System *tox_system_new(const Tox_Memory *mem, const Tox_Network *ns, const Tox_Random *rng, const Tox_Time *tm)
{
    Tox_System *sys = (Tox_System *)tox_memory_calloc(mem, 1, sizeof(Tox_System));

    if (sys == nullptr) {
        return nullptr;
    }

    sys->mem = mem;
    sys->ns = ns;
    sys->rng = rng;
    sys->tm = tm;

    return sys;
}

void tox_system_free(Tox_System *sys)
{
    tox_memory_dealloc(sys->mem, sys);
}
