#include "toxav.h"

#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include "../testing/fuzzing/fuzz_support.hh"

namespace {

constexpr bool kEnableDebug = false;

template <typename... Args>
void fuzz_log(const char *fmt, Args &&...args)
{
    if constexpr (kEnableDebug) {
        fprintf(stderr, fmt, std::forward<Args>(args)...);
    }
}

struct FuzzContext {
    uint64_t current_time_ms = 1000000;
    bool friend_connected = true;
    bool send_success = true;
};

// Mock IO callbacks
static bool mock_send_lossy(
    uint32_t friend_number, const uint8_t *data, size_t length, void *user_data)
{
    return static_cast<FuzzContext *>(user_data)->send_success;
}

static bool mock_send_lossless(
    uint32_t friend_number, const uint8_t *data, size_t length, void *user_data)
{
    return static_cast<FuzzContext *>(user_data)->send_success;
}

static bool mock_friend_exists(uint32_t friend_number, void *user_data) { return true; }

static bool mock_friend_connected(uint32_t friend_number, void *user_data)
{
    return static_cast<FuzzContext *>(user_data)->friend_connected;
}

static uint64_t mock_current_time(void *user_data)
{
    return static_cast<FuzzContext *>(user_data)->current_time_ms;
}

// Callbacks for ToxAV events (just to avoid crashes if they are called)
static void on_call(ToxAV *av, uint32_t friend_number, bool audio, bool video, void *user_data) { }
static void on_call_state(ToxAV *av, uint32_t friend_number, uint32_t state, void *user_data) { }
static void on_audio_frame(ToxAV *av, uint32_t friend_number, const int16_t *pcm,
    size_t sample_count, uint8_t channels, uint32_t sampling_rate, void *user_data)
{
}
static void on_video_frame(ToxAV *av, uint32_t friend_number, uint16_t width, uint16_t height,
    const uint8_t *y, const uint8_t *u, const uint8_t *v, int32_t ystride, int32_t ustride,
    int32_t vstride, void *user_data)
{
}
static void on_audio_bit_rate(
    ToxAV *av, uint32_t friend_number, uint32_t audio_bit_rate, void *user_data)
{
}
static void on_video_bit_rate(
    ToxAV *av, uint32_t friend_number, uint32_t video_bit_rate, void *user_data)
{
}

void fuzz_toxav_custom(Fuzz_Data &input)
{
    FuzzContext ctx;
    CONSUME1_OR_RETURN(uint8_t, mode, input);
    bool multithreaded = mode % 2;

    ToxAV_IO *io = toxav_io_new();
    toxav_io_callback_send_lossy(io, mock_send_lossy);
    toxav_io_callback_send_lossless(io, mock_send_lossless);
    toxav_io_callback_friend_exists(io, mock_friend_exists);
    toxav_io_callback_friend_connected(io, mock_friend_connected);
    toxav_io_callback_time_current(io, mock_current_time);

    Toxav_Err_New err_new;
    struct ToxAVDeleter {
        void operator()(ToxAV *av) { toxav_kill(av); }
    };
    std::unique_ptr<ToxAV, ToxAVDeleter> av(toxav_new_custom(io, &ctx, &err_new));
    toxav_io_kill(io);

    if (err_new != TOXAV_ERR_NEW_OK) {
        return;
    }

    // Register callbacks
    toxav_callback_call(av.get(), on_call, nullptr);
    toxav_callback_call_state(av.get(), on_call_state, nullptr);
    toxav_callback_audio_receive_frame(av.get(), on_audio_frame, nullptr);
    toxav_callback_video_receive_frame(av.get(), on_video_frame, nullptr);
    toxav_callback_audio_bit_rate(av.get(), on_audio_bit_rate, nullptr);
    toxav_callback_video_bit_rate(av.get(), on_video_bit_rate, nullptr);

    fuzz_log("Starting fuzz_toxav_custom (size=%zu, mode=%s)\n", input.size(),
        multithreaded ? "MT" : "ST");

    while (!input.empty()) {
        CONSUME1_OR_RETURN(uint8_t, action, input);
        action %= 12;

        switch (action) {
        case 0: {  // iterate
            fuzz_log("iterate\n");
            if (multithreaded) {
                toxav_audio_iterate(av.get());
                toxav_video_iterate(av.get());
            } else {
                toxav_iterate(av.get());
            }
            break;
        }
        case 1: {  // call
            CONSUME1_OR_RETURN(uint8_t, friend_number, input);
            CONSUME1_OR_RETURN(uint32_t, audio_br, input);
            CONSUME1_OR_RETURN(uint32_t, video_br, input);
            fuzz_log("call(friend=%d, abr=%u, vbr=%u)\n", friend_number, audio_br, video_br);
            Toxav_Err_Call err;
            toxav_call(av.get(), friend_number, audio_br, video_br, &err);
            break;
        }
        case 2: {  // answer
            CONSUME1_OR_RETURN(uint8_t, friend_number, input);
            CONSUME1_OR_RETURN(uint32_t, audio_br, input);
            CONSUME1_OR_RETURN(uint32_t, video_br, input);
            fuzz_log("answer(friend=%d, abr=%u, vbr=%u)\n", friend_number, audio_br, video_br);
            Toxav_Err_Answer err;
            toxav_answer(av.get(), friend_number, audio_br, video_br, &err);
            break;
        }
        case 3: {  // call_control
            CONSUME1_OR_RETURN(uint8_t, friend_number, input);
            CONSUME1_OR_RETURN(uint8_t, control_val, input);
            Toxav_Call_Control control = static_cast<Toxav_Call_Control>(control_val % 7);
            fuzz_log("call_control(friend=%d, ctrl=%d)\n", friend_number, control);
            Toxav_Err_Call_Control err;
            toxav_call_control(av.get(), friend_number, control, &err);
            break;
        }
        case 4: {  // audio_send_frame
            CONSUME1_OR_RETURN(uint8_t, friend_number, input);
            CONSUME1_OR_RETURN(uint16_t, sample_count, input);
            CONSUME1_OR_RETURN(uint8_t, channels, input);
            CONSUME1_OR_RETURN(uint32_t, sampling_rate, input);

            // Limit allocation size to prevent OOM in fuzzer
            if (sample_count > 5760 || channels > 2)
                break;

            size_t size = static_cast<size_t>(sample_count) * channels;
            if (input.size() < size * sizeof(int16_t))
                break;

            std::vector<int16_t> pcm(size);
            for (size_t i = 0; i < size; ++i) {
                pcm[i] = input.consume1("pcm");
            }

            fuzz_log("audio_send_frame(friend=%d, samples=%u)\n", friend_number, sample_count);

            Toxav_Err_Send_Frame err;
            toxav_audio_send_frame(
                av.get(), friend_number, pcm.data(), sample_count, channels, sampling_rate, &err);
            break;
        }
        case 5: {  // video_send_frame
            CONSUME1_OR_RETURN(uint8_t, friend_number, input);
            CONSUME1_OR_RETURN(uint16_t, width, input);
            CONSUME1_OR_RETURN(uint16_t, height, input);

            // Limit dimensions
            if (width > 1280 || height > 720)
                break;

            size_t y_size = static_cast<size_t>(width) * height;
            size_t u_size = static_cast<size_t>(width / 2) * (height / 2);
            size_t v_size = u_size;

            if (input.size() < y_size + u_size + v_size)
                break;

            // We'll just point to fuzzer data if possible to avoid copy, but api takes const
            // uint8_t* so we can consume directly.
            const uint8_t *y = input.consume("y", y_size);
            const uint8_t *u = input.consume("u", u_size);
            const uint8_t *v = input.consume("v", v_size);

            fuzz_log("video_send_frame(friend=%d, %dx%d)\n", friend_number, width, height);

            Toxav_Err_Send_Frame err;
            toxav_video_send_frame(av.get(), friend_number, width, height, y, u, v, &err);
            break;
        }
        case 6: {  // receive_packet
            CONSUME1_OR_RETURN(uint8_t, friend_number, input);
            CONSUME1_OR_RETURN(uint16_t, len, input);
            CONSUME1_OR_RETURN(uint8_t, bias, input);

            if (input.size() < len)
                len = input.size();

            if (len == 0)
                break;

            const uint8_t *data = input.consume("packet", len);
            std::vector<uint8_t> packet(data, data + len);

            if (bias < 4) {
                static const uint8_t ids[] = {69, 192, 193, 196};
                packet[0] = ids[bias];
            }

            fuzz_log("receive_packet(friend=%d, len=%u, bias=%d)\n", friend_number, len, bias);

            toxav_receive_packet(av.get(), friend_number, packet.data(), len);
            break;
        }
        case 7: {  // set_audio_bit_rate
            CONSUME1_OR_RETURN(uint8_t, friend_number, input);
            CONSUME1_OR_RETURN(uint32_t, br, input);
            fuzz_log("set_audio_bit_rate(friend=%d, br=%u)\n", friend_number, br);
            Toxav_Err_Bit_Rate_Set err;
            toxav_audio_set_bit_rate(av.get(), friend_number, br, &err);
            break;
        }
        case 8: {  // set_video_bit_rate
            CONSUME1_OR_RETURN(uint8_t, friend_number, input);
            CONSUME1_OR_RETURN(uint32_t, br, input);
            fuzz_log("set_video_bit_rate(friend=%d, br=%u)\n", friend_number, br);
            Toxav_Err_Bit_Rate_Set err;
            toxav_video_set_bit_rate(av.get(), friend_number, br, &err);
            break;
        }
        case 9: {  // advance time
            CONSUME1_OR_RETURN(uint16_t, inc, input);
            fuzz_log("advance_time(inc=%u)\n", inc);
            ctx.current_time_ms += inc;
            break;
        }
        case 10: {  // toggle connected
            fuzz_log("toggle_connected\n");
            ctx.friend_connected = !ctx.friend_connected;
            break;
        }
        case 11: {  // toggle send success
            fuzz_log("toggle_send_success\n");
            ctx.send_success = !ctx.send_success;
            break;
        }
        }
    }
    fuzz_log("Finished fuzz_toxav_custom\n");
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    Fuzz_Data input(data, size);
    fuzz_toxav_custom(input);
    return 0;
}
