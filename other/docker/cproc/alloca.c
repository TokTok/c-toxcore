#include <stdlib.h>

void *alloca(size_t size)
{
    return malloc(size);
}
