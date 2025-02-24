#include "TCP_server.h"

#include <stdio.h>

#include <cassert>
#include <cstring>
#include <functional>
#include <memory>
#include <optional>

#include "../testing/fuzzing/fuzz_support.hh"
#include "../testing/fuzzing/fuzz_tox.hh"
#include "c-toxcore/toxcore/logger.h"

namespace {

std::optional<std::tuple<IP_Port, uint8_t>> prepare(Fuzz_Data &input)
{
    IP_Port ipp;
    ip_init(&ipp.ip, true);
    ipp.port = 33445;

    CONSUME_OR_RETURN_VAL(const uint8_t *iterations_packed, input, 1, std::nullopt);
    const uint8_t iterations = *iterations_packed;

    return {{ipp, iterations}};
}

void TestTcpServer(Fuzz_Data &input)
{
    const auto prep = prepare(input);
    if (!prep.has_value()) {
        return;
    }
    const auto [ipp, iterations] = prep.value();

    // rest of the fuzz data is input for network
    Null_System null_sys;
    Fuzz_System sys(input);

    const Ptr<Logger> logger(logger_new(sys.mem.get()), logger_kill);
    if (logger == nullptr) {
        return;
    }

#if 1
    logger_callback_log(
        logger.get(),
        [](void *context, Logger_Level level, const char *file, uint32_t line, const char *func,
            const char *message, void *userdata) {
            if (level <= LOGGER_LEVEL_DEBUG) {
                return;
            }
            fprintf(stderr, "[%s] %s\n", logger_level_to_string(level), message);
        },
        nullptr, nullptr);
#endif

    const std::unique_ptr<Mono_Time, std::function<void(Mono_Time *)>> mono_time(
        mono_time_new(
            sys.mem.get(), [](void *user_data) { return *static_cast<uint64_t *>(user_data); },
            &sys.clock),
        [mem = sys.mem.get()](Mono_Time *ptr) { mono_time_free(mem, ptr); });
    if (mono_time == nullptr) {
        return;
    }

    const uint8_t secret_key[CRYPTO_SECRET_KEY_SIZE] = {0};
    const Ptr<TCP_Server> tcp_server(
        new_tcp_server(logger.get(), null_sys.mem.get(), sys.rng.get(), sys.ns.get(), false, 1,
            &ipp.port, secret_key, nullptr, nullptr),
        kill_tcp_server);
    if (tcp_server == nullptr) {
        abort();
    }

    for (uint8_t i = 0; i < iterations; ++i) {
        do_tcp_server(tcp_server.get(), mono_time.get());
        // "Sleep"
        sys.clock += System::BOOTSTRAP_ITERATION_INTERVAL;

        if (input.empty()) {
            break;
        }
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fuzz_select_target<TestTcpServer>(data, size);
    return 0;
}
