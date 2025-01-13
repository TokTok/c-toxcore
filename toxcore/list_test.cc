#include "list.h"

#include <gtest/gtest.h>

#include "mem.h"

namespace {

TEST(List, CreateAndDestroyWithNonZeroSize)
{
    const Memory *mem = os_memory();
    BS_List list;
    bs_list_init(&list, mem, sizeof(int), 10, memcmp);
    bs_list_free(&list);
}

TEST(List, CreateAndDestroyWithZeroSize)
{
    const Memory *mem = os_memory();
    BS_List list;
    bs_list_init(&list, mem, sizeof(int), 0, memcmp);
    bs_list_free(&list);
}

TEST(List, DeleteFromEmptyList)
{
    const Memory *mem = os_memory();
    BS_List list;
    bs_list_init(&list, mem, sizeof(int), 0, memcmp);
    const uint8_t data[sizeof(int)] = {0};
    bs_list_remove(&list, data, 0);
    bs_list_free(&list);
}

}  // namespace
