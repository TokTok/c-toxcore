#include "toxav.h"

#include <gtest/gtest.h>

#include "../toxcore/tox.h"

namespace {

TEST(ToxAV, OneSessionPerTox)
{
    Tox *tox = tox_new(nullptr, nullptr);
    ASSERT_NE(tox, nullptr);

    ToxAV *av = toxav_new(tox, nullptr);
    ASSERT_NE(av, nullptr);

    Toxav_Err_New err;
    EXPECT_EQ(toxav_new(tox, &err), nullptr);
    EXPECT_EQ(err, TOXAV_ERR_NEW_MULTIPLE);

    // Once the first one is gone, a new one can take its place.
    toxav_kill(av);
    av = toxav_new(tox, &err);
    EXPECT_NE(av, nullptr);
    EXPECT_EQ(err, TOXAV_ERR_NEW_OK);

    toxav_kill(av);
    tox_kill(tox);
}

}  // namespace
