#ifndef C_TOXCORE_TESTING_NETPROF_UI_TEST_SUPPORT_H
#define C_TOXCORE_TESTING_NETPROF_UI_TEST_SUPPORT_H

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <ftxui/dom/elements.hpp>
#include <ftxui/screen/screen.hpp>

#include "ui.hh"

namespace ftxui {
void PrintTo(const Screen &screen, std::ostream *os);
}  // namespace ftxui

namespace tox::netprof {

MATCHER_P5(MatchesRect, x, y, w, h, expected_lines,
    "matches rectangle at (" + std::to_string(x) + "," + std::to_string(y) + ") with size "
        + std::to_string(w) + "x" + std::to_string(h))
{
    const ftxui::Screen &screen = arg;

    std::string expected;
    for (size_t i = 0; i < static_cast<size_t>(expected_lines.size()); ++i) {
        expected += expected_lines[i];
        if (i < static_cast<size_t>(expected_lines.size()) - 1)
            expected += "\n";
    }

    std::string actual;
    for (int j = y; j < y + h; ++j) {
        for (int i = x; i < x + w; ++i) {
            std::string cell = screen.at(i, j);
            actual += cell.empty() ? " " : cell;
        }
        if (j < y + h - 1)
            actual += "\n";
    }

    if (actual == expected)
        return true;

    *result_listener << "\nActual area:\n[" << actual << "]\nExpected area:\n[" << expected << "]";
    return false;
}

class NetProfUITest : public ::testing::Test {
protected:
    NetProfUITest();
    ~NetProfUITest() override;

    NetProfUI ui_;
    UICommand last_command_;
};

}  // namespace tox::netprof

#endif  // C_TOXCORE_TESTING_NETPROF_UI_TEST_SUPPORT_H
