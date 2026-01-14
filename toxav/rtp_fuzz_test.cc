#include "rtp.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <vector>

#include "../testing/support/public/fuzz_data.hh"
#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/os_memory.h"

namespace {

using tox::test::Fuzz_Data;

struct MockSessionData { };

static int mock_send_packet(
    void * /*user_data*/, const std::uint8_t * /*data*/, std::uint16_t /*length*/)
{
    return 0;
}

static int mock_m_cb(const Mono_Time * /*mono_time*/, void * /*cs*/, RTPMessage *msg)
{
    std::free(msg);
    return 0;
}

void fuzz_rtp_receive(Fuzz_Data &input)
{
    const Memory *mem = os_memory();
    struct LoggerDeleter {
        void operator()(Logger *l) { logger_kill(l); }
    };
    std::unique_ptr<Logger, LoggerDeleter> log(logger_new(mem));

    auto time_cb = [](void *) -> std::uint64_t { return 0; };
    struct MonoTimeDeleter {
        const Memory *m;
        void operator()(Mono_Time *t) { mono_time_free(m, t); }
    };
    std::unique_ptr<Mono_Time, MonoTimeDeleter> mono_time(
        mono_time_new(mem, time_cb, nullptr), MonoTimeDeleter{mem});

    MockSessionData sd;

    CONSUME1_OR_RETURN(std::uint8_t, payload_type_byte, input);
    int payload_type = (payload_type_byte % 2 == 0) ? RTP_TYPE_AUDIO : RTP_TYPE_VIDEO;

    struct RtpSessionDeleter {
        Logger *l;
        void operator()(RTPSession *s) { rtp_kill(l, s); }
    };
    std::unique_ptr<RTPSession, RtpSessionDeleter> session(
        rtp_new(log.get(), payload_type, mono_time.get(), mock_send_packet, &sd, nullptr, nullptr,
            nullptr, &sd, mock_m_cb),
        RtpSessionDeleter{log.get()});

    while (!input.empty()) {
        CONSUME1_OR_RETURN(std::uint16_t, len, input);

        if (input.size() < len) {
            len = input.size();
        }

        if (len == 0) {
            break;
        }

        const std::uint8_t *pkt_data = input.consume(__func__, len);
        rtp_receive_packet(session.get(), pkt_data, len);
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size);

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t *data, std::size_t size)
{
    Fuzz_Data input(data, size);
    fuzz_rtp_receive(input);
    return 0;
}
