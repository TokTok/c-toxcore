#include "list.h"

#include <gtest/gtest.h>

#include "os_memory.h"

namespace {

struct List : ::testing::Test {
protected:
    const Memory *mem_ = os_memory();
};

TEST_F(List, CreateAndDestroyWithNonZeroSize)
{
    BS_List list;
    bs_list_init(&list, sizeof(int), 10, mem_);
    bs_list_free(&list);
}

TEST_F(List, CreateAndDestroyWithZeroSize)
{
    BS_List list;
    bs_list_init(&list, sizeof(int), 0, mem_);
    bs_list_free(&list);
}

TEST_F(List, DeleteFromEmptyList)
{
    BS_List list;
    bs_list_init(&list, sizeof(int), 0, mem_);
    const uint8_t data[sizeof(int)] = {0};
    bs_list_remove(&list, data, 0);
    bs_list_free(&list);
}

}  // namespace
