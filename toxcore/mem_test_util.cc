#include "mem_test_util.hh"

#include <cstdlib>

Tox_Memory_Funcs const Memory_Class::vtable = {
    Method<tox_memory_malloc_cb, Memory_Class>::invoke<&Memory_Class::malloc>,
    Method<tox_memory_realloc_cb, Memory_Class>::invoke<&Memory_Class::realloc>,
    Method<tox_memory_dealloc_cb, Memory_Class>::invoke<&Memory_Class::dealloc>,
};

Memory_Class::~Memory_Class() = default;

void *Test_Memory::malloc(void *obj, uint32_t size) { return mem->funcs->malloc_callback(mem->user_data, size); }

void *Test_Memory::realloc(void *obj, void *ptr, uint32_t size)
{
    return mem->funcs->realloc_callback(mem->user_data, ptr, size);
}

void Test_Memory::dealloc(void *obj, void *ptr) { return mem->funcs->dealloc_callback(mem->user_data, ptr); }
