#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

// Helper to construct fuzzer input
class SeedBuilder {
    std::vector<uint8_t> data;

public:
    void add_byte(uint8_t b) { data.push_back(b); }

    void add_u16(uint16_t v)
    {
        data.push_back(v & 0xFF);
        data.push_back((v >> 8) & 0xFF);
    }

    void add_u32(uint32_t v)
    {
        data.push_back(v & 0xFF);
        data.push_back((v >> 8) & 0xFF);
        data.push_back((v >> 16) & 0xFF);
        data.push_back((v >> 24) & 0xFF);
    }

    void add_bytes(const void *ptr, size_t size)
    {
        const uint8_t *p = static_cast<const uint8_t *>(ptr);
        data.insert(data.end(), p, p + size);
    }

    void add_zeros(size_t count) { data.insert(data.end(), count, 0); }

    void save(const std::string &filename)
    {
        std::string path = filename;
        const char *workspace_dir = std::getenv("BUILD_WORKSPACE_DIRECTORY");
        if (workspace_dir) {
            path = std::string(workspace_dir) + "/" + filename;
        }
        std::ofstream out(path, std::ios::binary);
        if (out) {
            out.write(reinterpret_cast<const char *>(data.data()), data.size());
            std::cout << "Generated seed file: " << path << " (" << data.size() << " bytes)"
                      << std::endl;
        } else {
            std::cerr << "Failed to write to " << path << std::endl;
        }
    }

    // Actions matching toxav_fuzz_test.cc

    void set_header(uint8_t mode)
    {
        // First byte is mode (multithreaded if % 2 != 0)
        add_byte(mode);
    }

    void iterate() { add_byte(0); }

    void call(uint8_t friend_num, uint32_t audio_br, uint32_t video_br)
    {
        add_byte(1);
        add_byte(friend_num);
        add_u32(audio_br);
        add_u32(video_br);
    }

    void answer(uint8_t friend_num, uint32_t audio_br, uint32_t video_br)
    {
        add_byte(2);
        add_byte(friend_num);
        add_u32(audio_br);
        add_u32(video_br);
    }

    void call_control(uint8_t friend_num, uint8_t control)
    {
        add_byte(3);
        add_byte(friend_num);
        add_byte(control);
    }

    void audio_send_frame(uint8_t friend_num, uint16_t samples, uint8_t channels, uint32_t rate)
    {
        add_byte(4);
        add_byte(friend_num);
        add_u16(samples);
        add_byte(channels);
        add_u32(rate);
        // data needs to be added manually or zeros
        size_t pcm_size = samples * channels * sizeof(int16_t);
        add_zeros(pcm_size);
    }

    void video_send_frame(uint8_t friend_num, uint16_t w, uint16_t h)
    {
        add_byte(5);
        add_byte(friend_num);
        add_u16(w);
        add_u16(h);

        size_t y_size = w * h;
        size_t u_size = (w / 2) * (h / 2);
        size_t v_size = u_size;

        add_zeros(y_size + u_size + v_size);
    }

    void receive_packet(uint8_t friend_num, const std::vector<uint8_t> &packet, uint8_t bias)
    {
        add_byte(6);
        add_byte(friend_num);
        add_u16(packet.size());
        add_byte(bias);
        add_bytes(packet.data(), packet.size());
    }

    void set_audio_bit_rate(uint8_t friend_num, uint32_t br)
    {
        add_byte(7);
        add_byte(friend_num);
        add_u32(br);
    }

    void set_video_bit_rate(uint8_t friend_num, uint32_t br)
    {
        add_byte(8);
        add_byte(friend_num);
        add_u32(br);
    }

    void advance_time(uint16_t ms)
    {
        add_byte(9);
        add_u16(ms);
    }

    void toggle_connected() { add_byte(10); }

    void toggle_send_success() { add_byte(11); }
};

int main()
{
    SeedBuilder b;

    // 0 = Single Threaded
    b.set_header(0);

    // Initial state: connected, send success = true

    // 1. Advance time a bit to simulate startup
    b.advance_time(100);
    b.iterate();

    // 2. Start a call to friend 0
    // Audio 48k, Video 0 (Audio only)
    b.call(0, 48, 0);
    b.iterate();

    // 3. Advance time while ringing
    b.advance_time(50);
    b.iterate();

    // 4. Simulate receiving a packet (e.g. MSI or just noise with correct ID)
    // Bias 0 = MSI (69)
    std::vector<uint8_t> dummy_pkt(10, 0xAA);
    b.receive_packet(0, dummy_pkt, 0);
    b.iterate();

    // 5. Send some audio frames
    // 960 samples, 1 channel, 48000 Hz = 20ms
    for (int i = 0; i < 5; ++i) {
        b.audio_send_frame(0, 960, 1, 48000);
        b.advance_time(20);
        b.iterate();
    }

    // 6. Set bitrate
    b.set_audio_bit_rate(0, 64);
    b.iterate();

    // 7. Answer (invalid state since we called, but good for fuzzing coverage)
    b.answer(0, 48, 0);
    b.iterate();

    // 8. Call Control: Pause
    // TOXAV_CALL_CONTROL_PAUSE = 1
    b.call_control(0, 1);
    b.iterate();

    // 9. Advance time
    b.advance_time(1000);
    b.iterate();

    // 10. Resume
    // TOXAV_CALL_CONTROL_RESUME = 0
    b.call_control(0, 0);
    b.iterate();

    // 11. Send Video Frame (even though we didn't enable it, check error handling)
    b.video_send_frame(0, 320, 240);
    b.iterate();

    // 12. Set video bitrate
    b.set_video_bit_rate(0, 1000);
    b.iterate();

    // 13. Toggle connected (simulate disconnect)
    b.toggle_connected();
    b.iterate();
    b.advance_time(50);
    b.iterate();

    // Toggle connected (simulate reconnect)
    b.toggle_connected();
    b.iterate();

    // 14. Toggle send success (simulate send failure)
    b.toggle_send_success();
    // Try sending frame which should fail
    b.audio_send_frame(0, 960, 1, 48000);
    b.iterate();

    // Toggle send success (simulate recovery)
    b.toggle_send_success();
    b.iterate();

    b.save("toxav_call_cycle.bin");

    return 0;
}
