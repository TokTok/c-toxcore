#include "os_secure_memory.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdint>
#include <cstring>

#include "attributes.h"
#include "mem.h"

namespace {

TEST(OsSecureMemory, AlignsAllocationsOfAnySize)
{
    const Memory *_Nonnull mem = os_secure_memory();

    for (std::uint32_t size = 1; size <= 100; ++size) {
        void *const ptr = mem_balloc(mem, size);
        ASSERT_NE(ptr, nullptr);
        EXPECT_EQ(reinterpret_cast<std::uintptr_t>(ptr) % alignof(std::max_align_t), 0) << size;
        std::memset(ptr, 0xaa, size);
        mem_delete(mem, ptr);
    }
}

}  // namespace
