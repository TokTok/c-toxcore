#include "ui_test_support.hh"

#include <ftxui/screen/screen.hpp>

namespace ftxui {
void PrintTo(const Screen &screen, std::ostream *os) { *os << "\n" << screen.ToString(); }
}  // namespace ftxui

namespace tox::netprof {

NetProfUITest::NetProfUITest()
    : ui_([this](UICommand cmd) { last_command_ = cmd; })
{
}

NetProfUITest::~NetProfUITest() = default;

}  // namespace tox::netprof
