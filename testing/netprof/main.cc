#include <iostream>
#include <string>

#include "app.hh"

using namespace tox::netprof;

int main(int argc, char **argv)
{
    bool verbose = false;
    bool headless = false;
    uint64_t seed = 12345;
    std::string load_path;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--headless") {
            headless = true;
        } else if (arg == "--verbose") {
            verbose = true;
        } else if (arg == "--seed" && i + 1 < argc) {
            seed = std::stoull(argv[++i]);
        } else if (arg == "--load" && i + 1 < argc) {
            load_path = argv[++i];
        }
    }

    NetProfApp app(seed, verbose);
    app.run(headless, load_path);

    return 0;
}
