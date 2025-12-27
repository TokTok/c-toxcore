#include "audio.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <vector>

#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/network.h"
#include "../toxcore/os_memory.h"
#include "rtp.h"

namespace {

struct AudioTimeMock {
    uint64_t t;
};

uint64_t audio_mock_time_cb(void *ud) { return static_cast<AudioTimeMock *>(ud)->t; }

struct AudioTestData {
    uint32_t friend_number = 0;
    std::vector<int16_t> last_pcm;
    size_t sample_count = 0;
    uint8_t channels = 0;
    uint32_t sampling_rate = 0;

    static void receive_frame(uint32_t friend_number, const int16_t *pcm, size_t sample_count,
        uint8_t channels, uint32_t sampling_rate, void *user_data)
    {
        auto *self = static_cast<AudioTestData *>(user_data);
        self->friend_number = friend_number;
        self->last_pcm.assign(pcm, pcm + sample_count * channels);
        self->sample_count = sample_count;
        self->channels = channels;
        self->sampling_rate = sampling_rate;
    }
};

struct RtpMock {
    RTPSession *recv_session = nullptr;
    std::vector<std::vector<uint8_t>> captured_packets;
    bool auto_forward = true;

    static int send_packet(void *user_data, const uint8_t *data, uint16_t length)
    {
        auto *self = static_cast<RtpMock *>(user_data);
        self->captured_packets.push_back(std::vector<uint8_t>(data, data + length));
        if (self->auto_forward && self->recv_session) {
            rtp_receive_packet(self->recv_session, data, length);
        }
        return 0;
    }

    static int audio_cb(const Mono_Time *mono_time, void *cs, RTPMessage *msg)
    {
        return ac_queue_message(mono_time, cs, msg);
    }
};

class AudioTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        const Memory *mem = os_memory();
        log = logger_new(mem);
        tm.t = 1000;
        mono_time = mono_time_new(mem, audio_mock_time_cb, &tm);
        mono_time_update(mono_time);
    }

    void TearDown() override
    {
        const Memory *mem = os_memory();
        mono_time_free(mem, mono_time);
        logger_kill(log);
    }

    Logger *log;
    Mono_Time *mono_time;
    AudioTimeMock tm;
};

TEST_F(AudioTest, BasicNewKill)
{
    AudioTestData data;
    ACSession *ac = ac_new(mono_time, log, 123, AudioTestData::receive_frame, &data);
    ASSERT_NE(ac, nullptr);
    ac_kill(ac);
}

TEST_F(AudioTest, EncodeDecodeLoop)
{
    AudioTestData data;
    ACSession *ac = ac_new(mono_time, log, 123, AudioTestData::receive_frame, &data);
    ASSERT_NE(ac, nullptr);

    RtpMock rtp_mock;
    RTPSession *send_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    RTPSession *recv_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    rtp_mock.recv_session = recv_rtp;

    uint32_t sampling_rate = 48000;
    uint8_t channels = 1;
    size_t sample_count = 960;  // 20ms at 48kHz

    // Reconfigure to mono
    ASSERT_EQ(ac_reconfigure_encoder(ac, 48000, sampling_rate, channels), 0);

    std::vector<int16_t> pcm(sample_count * channels);
    for (size_t i = 0; i < pcm.size(); ++i) {
        pcm[i] = static_cast<int16_t>(i * 10);
    }

    std::vector<uint8_t> encoded(2000);
    int encoded_size = ac_encode(ac, pcm.data(), sample_count, encoded.data(), encoded.size());
    ASSERT_GT(encoded_size, 0);

    // Prepare payload: 4 bytes sampling rate + Opus data
    std::vector<uint8_t> payload(4 + static_cast<size_t>(encoded_size));
    uint32_t net_sr = net_htonl(sampling_rate);
    memcpy(payload.data(), &net_sr, 4);
    memcpy(payload.data() + 4, encoded.data(), static_cast<size_t>(encoded_size));

    // Send via RTP
    int rc = rtp_send_data(
        log, send_rtp, payload.data(), static_cast<uint32_t>(payload.size()), false);
    ASSERT_EQ(rc, 0);

    // Decode
    ac_iterate(ac);

    ASSERT_EQ(data.friend_number, 123u);
    ASSERT_EQ(data.sample_count, sample_count);
    ASSERT_EQ(data.channels, channels);
    ASSERT_EQ(data.sampling_rate, sampling_rate);
    ASSERT_EQ(data.last_pcm.size(), pcm.size());

    rtp_kill(log, send_rtp);
    rtp_kill(log, recv_rtp);
    ac_kill(ac);
}

TEST_F(AudioTest, ReconfigureEncoder)
{
    AudioTestData data;
    ACSession *ac = ac_new(mono_time, log, 123, AudioTestData::receive_frame, &data);
    ASSERT_NE(ac, nullptr);

    // Initial state: 48kHz, mono, 48kbps
    // Change to 24kHz, stereo, 32kbps
    int rc = ac_reconfigure_encoder(ac, 32000, 24000, 2);
    ASSERT_EQ(rc, 0);

    size_t sample_count = 480;  // 20ms at 24kHz
    uint8_t channels = 2;
    std::vector<int16_t> pcm(sample_count * channels, 0);

    std::vector<uint8_t> encoded(1000);
    int encoded_size = ac_encode(ac, pcm.data(), sample_count, encoded.data(), encoded.size());
    ASSERT_GT(encoded_size, 0);

    ac_kill(ac);
}

TEST_F(AudioTest, GetFrameDuration)
{
    AudioTestData data;
    ACSession *ac = ac_new(mono_time, log, 123, AudioTestData::receive_frame, &data);
    ASSERT_NE(ac, nullptr);

    // Default duration in audio.c is 120ms (AUDIO_MAX_FRAME_DURATION_MS)
    EXPECT_EQ(ac_get_lp_frame_duration(ac), 120u);

    ac_kill(ac);
}

TEST_F(AudioTest, QueueInvalidMessage)
{
    AudioTestData data;
    ACSession *ac = ac_new(mono_time, log, 123, AudioTestData::receive_frame, &data);
    ASSERT_NE(ac, nullptr);

    RtpMock rtp_mock;
    // Create a video RTP session but try to queue to audio session
    RTPSession *video_rtp = rtp_new(log, RTP_TYPE_VIDEO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    RTPSession *audio_recv_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet,
        &rtp_mock, nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    rtp_mock.recv_session = audio_recv_rtp;

    std::vector<uint8_t> dummy_video(100, 0);
    int rc = rtp_send_data(
        log, video_rtp, dummy_video.data(), static_cast<uint32_t>(dummy_video.size()), true);
    ASSERT_EQ(rc, 0);

    // Iterate should NOT trigger callback because payload type was wrong
    ac_iterate(ac);
    EXPECT_EQ(data.sample_count, 0u);

    rtp_kill(log, video_rtp);
    rtp_kill(log, audio_recv_rtp);
    ac_kill(ac);
}

TEST_F(AudioTest, JitterBufferDuplicate)
{
    AudioTestData data;
    ACSession *ac = ac_new(mono_time, log, 123, AudioTestData::receive_frame, &data);
    ASSERT_NE(ac, nullptr);

    RtpMock rtp_mock;
    rtp_mock.auto_forward = false;
    RTPSession *send_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    RTPSession *recv_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    rtp_mock.recv_session = recv_rtp;

    uint8_t dummy_data[100] = {0};
    uint32_t net_sr = net_htonl(48000);
    memcpy(dummy_data, &net_sr, 4);

    rtp_send_data(log, send_rtp, dummy_data, sizeof(dummy_data), false);
    ASSERT_EQ(rtp_mock.captured_packets.size(), 1u);

    // Feed the same packet twice
    rtp_receive_packet(
        recv_rtp, rtp_mock.captured_packets[0].data(), rtp_mock.captured_packets[0].size());
    rtp_receive_packet(
        recv_rtp, rtp_mock.captured_packets[0].data(), rtp_mock.captured_packets[0].size());

    // First iterate should process the packet
    ac_iterate(ac);
    EXPECT_GT(data.sample_count, 0u);
    data.sample_count = 0;

    // Second iterate should NOT process anything (duplicate was dropped in queue)
    ac_iterate(ac);
    EXPECT_EQ(data.sample_count, 0u);

    rtp_kill(log, send_rtp);
    rtp_kill(log, recv_rtp);
    ac_kill(ac);
}

TEST_F(AudioTest, JitterBufferOutOfOrder)
{
    AudioTestData data;
    ACSession *ac = ac_new(mono_time, log, 123, AudioTestData::receive_frame, &data);
    ASSERT_NE(ac, nullptr);

    RtpMock rtp_mock;
    rtp_mock.auto_forward = false;
    RTPSession *send_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    RTPSession *recv_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    rtp_mock.recv_session = recv_rtp;

    uint8_t dummy_data[100] = {0};
    uint32_t net_sr = net_htonl(48000);
    memcpy(dummy_data, &net_sr, 4);

    // Capture 3 packets
    rtp_send_data(log, send_rtp, dummy_data, sizeof(dummy_data), false);
    rtp_send_data(log, send_rtp, dummy_data, sizeof(dummy_data), false);
    rtp_send_data(log, send_rtp, dummy_data, sizeof(dummy_data), false);
    ASSERT_EQ(rtp_mock.captured_packets.size(), 3u);

    // Receive in order 0, 2, 1
    rtp_receive_packet(
        recv_rtp, rtp_mock.captured_packets[0].data(), rtp_mock.captured_packets[0].size());
    rtp_receive_packet(
        recv_rtp, rtp_mock.captured_packets[2].data(), rtp_mock.captured_packets[2].size());
    rtp_receive_packet(
        recv_rtp, rtp_mock.captured_packets[1].data(), rtp_mock.captured_packets[1].size());

    // Iterate once, should process all 3 packets (because ac_iterate now loops)
    data.sample_count = 0;
    ac_iterate(ac);
    EXPECT_GT(data.sample_count, 0u);

    // Subsequent iterate should find nothing
    data.sample_count = 0;
    ac_iterate(ac);
    EXPECT_EQ(data.sample_count, 0u);

    rtp_kill(log, send_rtp);
    rtp_kill(log, recv_rtp);
    ac_kill(ac);
}

TEST_F(AudioTest, PacketLossConcealment)
{
    AudioTestData data;
    ACSession *ac = ac_new(mono_time, log, 123, AudioTestData::receive_frame, &data);
    ASSERT_NE(ac, nullptr);

    RtpMock rtp_mock;
    rtp_mock.auto_forward = false;
    RTPSession *send_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    RTPSession *recv_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    rtp_mock.recv_session = recv_rtp;

    uint8_t dummy_data[100] = {0};
    uint32_t net_sr = net_htonl(48000);
    memcpy(dummy_data, &net_sr, 4);

    // Send packet 0 and deliver it immediately.
    rtp_send_data(log, send_rtp, dummy_data, sizeof(dummy_data), false);
    rtp_receive_packet(
        recv_rtp, rtp_mock.captured_packets[0].data(), rtp_mock.captured_packets[0].size());
    ac_iterate(ac);
    EXPECT_GT(data.sample_count, 0u);
    data.sample_count = 0;

    // Send packets 1 through 5 but do not deliver them, creating a gap in the sequence.
    for (int i = 0; i < 5; ++i) {
        rtp_send_data(log, send_rtp, dummy_data, sizeof(dummy_data), false);
    }

    // Send and deliver packet 6. The gap (1-5) exceeds the jitter buffer capacity (3).
    rtp_send_data(log, send_rtp, dummy_data, sizeof(dummy_data), false);
    rtp_receive_packet(
        recv_rtp, rtp_mock.captured_packets[6].data(), rtp_mock.captured_packets[6].size());

    // The next iteration should trigger Packet Loss Concealment (PLC) for the missing packets.
    // In audio.c, a return code of 2 from jbuf_read indicates that PLC should be performed.
    ac_iterate(ac);
    EXPECT_GT(data.sample_count, 0u);

    rtp_kill(log, send_rtp);
    rtp_kill(log, recv_rtp);
    ac_kill(ac);
}

TEST_F(AudioTest, JitterBufferReset)
{
    AudioTestData data;
    ACSession *ac = ac_new(mono_time, log, 123, AudioTestData::receive_frame, &data);
    ASSERT_NE(ac, nullptr);

    RtpMock rtp_mock;
    rtp_mock.auto_forward = false;
    RTPSession *send_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    RTPSession *recv_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    rtp_mock.recv_session = recv_rtp;

    uint8_t dummy_data[100] = {0};
    uint32_t net_sr = net_htonl(48000);
    memcpy(dummy_data, &net_sr, 4);

    rtp_send_data(log, send_rtp, dummy_data, sizeof(dummy_data), false);
    rtp_receive_packet(
        recv_rtp, rtp_mock.captured_packets[0].data(), rtp_mock.captured_packets[0].size());
    ac_iterate(ac);

    // The jitter buffer size is (capacity * 4) rounded up to the next power of 2.
    // With AUDIO_JITTERBUFFER_COUNT = 3, the size is 16.
    // A jump in sequence number greater than the buffer size triggers a full reset of the jitter
    // buffer.
    for (int i = 0; i < 20; ++i) {
        rtp_send_data(log, send_rtp, dummy_data, sizeof(dummy_data), false);
    }

    // Deliver the latest packet, which is well beyond the current window.
    rtp_receive_packet(
        recv_rtp, rtp_mock.captured_packets.back().data(), rtp_mock.captured_packets.back().size());

    // The session should recover after the reset and process the new packet normally.
    data.sample_count = 0;
    ac_iterate(ac);
    EXPECT_GT(data.sample_count, 0u);

    rtp_kill(log, send_rtp);
    rtp_kill(log, recv_rtp);
    ac_kill(ac);
}

TEST_F(AudioTest, DecoderReconfigureCooldown)
{
    AudioTestData data;
    ACSession *ac = ac_new(mono_time, log, 123, AudioTestData::receive_frame, &data);
    ASSERT_NE(ac, nullptr);

    RtpMock rtp_mock;
    rtp_mock.auto_forward = false;
    RTPSession *send_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    RTPSession *recv_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    rtp_mock.recv_session = recv_rtp;

    uint8_t dummy_data[100] = {0};
    uint32_t net_sr_48 = net_htonl(48000);
    uint32_t net_sr_24 = net_htonl(24000);

    // 1. Reconfigure to 24kHz. The initial sampling rate is 48kHz.
    memcpy(dummy_data, &net_sr_24, 4);
    rtp_send_data(log, send_rtp, dummy_data, sizeof(dummy_data), false);
    rtp_receive_packet(
        recv_rtp, rtp_mock.captured_packets.back().data(), rtp_mock.captured_packets.back().size());
    ac_iterate(ac);
    EXPECT_EQ(data.sampling_rate, 24000u);
    data.sampling_rate = 0;

    // 2. Advance time by only 100ms. This is less than the 500ms cooldown required for decoder
    // reconfiguration.
    tm.t += 100;
    mono_time_update(mono_time);

    // 3. Attempt to reconfigure back to 48kHz.
    memcpy(dummy_data, &net_sr_48, 4);
    rtp_send_data(log, send_rtp, dummy_data, sizeof(dummy_data), false);
    rtp_receive_packet(
        recv_rtp, rtp_mock.captured_packets.back().data(), rtp_mock.captured_packets.back().size());

    // Reconfiguration should be rejected due to the cooldown, so the callback should not be
    // invoked.
    ac_iterate(ac);
    EXPECT_EQ(data.sampling_rate, 0u);

    // 4. Advance time beyond the 500ms cooldown period (measured from the first reconfiguration).
    tm.t += 500;
    mono_time_update(mono_time);

    // 5. Attempt reconfiguration to 48kHz again.
    rtp_send_data(log, send_rtp, dummy_data, sizeof(dummy_data), false);
    rtp_receive_packet(
        recv_rtp, rtp_mock.captured_packets.back().data(), rtp_mock.captured_packets.back().size());

    // Reconfiguration should now succeed.
    ac_iterate(ac);
    EXPECT_EQ(data.sampling_rate, 48000u);

    rtp_kill(log, send_rtp);
    rtp_kill(log, recv_rtp);
    ac_kill(ac);
}

TEST_F(AudioTest, QueueDummyMessage)
{
    AudioTestData data;
    ACSession *ac = ac_new(mono_time, log, 123, AudioTestData::receive_frame, &data);
    ASSERT_NE(ac, nullptr);

    RtpMock rtp_mock;
    // RTP_TYPE_AUDIO + 2 is the dummy type
    RTPSession *dummy_rtp = rtp_new(log, RTP_TYPE_AUDIO + 2, mono_time, RtpMock::send_packet,
        &rtp_mock, nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    RTPSession *audio_recv_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet,
        &rtp_mock, nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    rtp_mock.recv_session = audio_recv_rtp;

    std::vector<uint8_t> dummy_payload(100, 0);
    int rc = rtp_send_data(
        log, dummy_rtp, dummy_payload.data(), static_cast<uint32_t>(dummy_payload.size()), false);
    ASSERT_EQ(rc, 0);

    // Iterate should NOT trigger callback because it was a dummy packet
    ac_iterate(ac);
    EXPECT_EQ(data.sample_count, 0u);

    rtp_kill(log, dummy_rtp);
    rtp_kill(log, audio_recv_rtp);
    ac_kill(ac);
}

TEST_F(AudioTest, LatePacketReset)
{
    AudioTestData data;
    ACSession *ac = ac_new(mono_time, log, 123, AudioTestData::receive_frame, &data);
    ASSERT_NE(ac, nullptr);

    RtpMock rtp_mock;
    rtp_mock.auto_forward = false;
    RTPSession *send_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    RTPSession *recv_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    rtp_mock.recv_session = recv_rtp;

    uint8_t dummy_data[100] = {0};
    uint32_t net_sr = net_htonl(48000);
    memcpy(dummy_data, &net_sr, 4);

    // 1. Send and process the first packet.
    rtp_send_data(log, send_rtp, dummy_data, sizeof(dummy_data), false);  // seq 0
    rtp_receive_packet(
        recv_rtp, rtp_mock.captured_packets[0].data(), rtp_mock.captured_packets[0].size());
    ac_iterate(ac);
    ASSERT_GT(data.sample_count, 0u);
    data.sample_count = 0;

    // 2. Buffer another packet with a different sampling rate (24kHz) but don't process it yet.
    uint32_t net_sr_24 = net_htonl(24000);
    memcpy(dummy_data, &net_sr_24, 4);
    rtp_send_data(log, send_rtp, dummy_data, sizeof(dummy_data), false);  // seq 1
    rtp_receive_packet(
        recv_rtp, rtp_mock.captured_packets[1].data(), rtp_mock.captured_packets[1].size());

    // 3. Receive the late packet (seq 0) again.
    // This triggers the bug: (uint32_t)(0 - 1) > 16, causing a full jitter buffer reset.
    rtp_receive_packet(
        recv_rtp, rtp_mock.captured_packets[0].data(), rtp_mock.captured_packets[0].size());

    // 4. Try to process the next packet.
    // Due to the bug, packet 1 was cleared. We will likely get PLC (48kHz) instead of packet 1
    // (24kHz).
    ac_iterate(ac);

    // If the bug is present, sampling_rate will be 48000 (from PLC) instead of 24000.
    EXPECT_EQ(data.sampling_rate, 24000u);

    rtp_kill(log, send_rtp);
    rtp_kill(log, recv_rtp);
    ac_kill(ac);
}

TEST_F(AudioTest, InvalidSamplingRate)
{
    AudioTestData data;
    ACSession *ac = ac_new(mono_time, log, 123, AudioTestData::receive_frame, &data);
    ASSERT_NE(ac, nullptr);

    RtpMock rtp_mock;
    rtp_mock.auto_forward = false;
    RTPSession *send_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    RTPSession *recv_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    rtp_mock.recv_session = recv_rtp;

    // 1. Send a packet with an absurdly large sampling rate.
    uint8_t malicious_data[100] = {0};
    uint32_t net_sr = net_htonl(1000000000);  // 1 GHz
    memcpy(malicious_data, &net_sr, 4);
    // Add some dummy Opus data so it's not too short
    malicious_data[4] = 0x08;

    rtp_send_data(log, send_rtp, malicious_data, sizeof(malicious_data), false);
    rtp_receive_packet(
        recv_rtp, rtp_mock.captured_packets.back().data(), rtp_mock.captured_packets.back().size());

    // This packet should fail reconfiguration and be discarded.
    ac_iterate(ac);
    EXPECT_EQ(data.sample_count, 0u);

    // 2. Trigger PLC. It should NOT use the malicious sampling rate.
    // Send 5 packets to create a gap.
    for (int i = 0; i < 5; ++i) {
        rtp_send_data(log, send_rtp, malicious_data, sizeof(malicious_data), false);
    }
    // Deliver the next one.
    rtp_send_data(log, send_rtp, malicious_data, sizeof(malicious_data), false);
    rtp_receive_packet(
        recv_rtp, rtp_mock.captured_packets.back().data(), rtp_mock.captured_packets.back().size());

    // Next iterate triggers PLC. If it uses 1GHz, it might overflow/crash.
    ac_iterate(ac);

    rtp_kill(log, send_rtp);
    rtp_kill(log, recv_rtp);
    ac_kill(ac);
}

TEST_F(AudioTest, ShortPacket)
{
    AudioTestData data;
    ACSession *ac = ac_new(mono_time, log, 123, AudioTestData::receive_frame, &data);
    ASSERT_NE(ac, nullptr);

    RtpMock rtp_mock;
    rtp_mock.auto_forward = false;
    RTPSession *send_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    RTPSession *recv_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    rtp_mock.recv_session = recv_rtp;

    // 1. Send a packet that is too short (only sampling rate, no Opus data).
    // The protocol requires 4 bytes SR + at least 1 byte Opus data.
    uint8_t short_data[4] = {0, 0, 0xBB, 0x80};  // 48000

    // rtp_send_data might not like 4 bytes if it expects more, but let's see.
    rtp_send_data(log, send_rtp, short_data, sizeof(short_data), false);
    rtp_receive_packet(
        recv_rtp, rtp_mock.captured_packets.back().data(), rtp_mock.captured_packets.back().size());

    // This should not crash. In debug it might hit an assert.
    // In production it might do an OOB read.
    ac_iterate(ac);

    rtp_kill(log, send_rtp);
    rtp_kill(log, recv_rtp);
    ac_kill(ac);
}

TEST_F(AudioTest, JitterBufferWrapAround)
{
    AudioTestData data;
    ACSession *ac = ac_new(mono_time, log, 123, AudioTestData::receive_frame, &data);
    ASSERT_NE(ac, nullptr);

    RtpMock rtp_mock;
    rtp_mock.auto_forward = false;
    RTPSession *send_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    RTPSession *recv_rtp = rtp_new(log, RTP_TYPE_AUDIO, mono_time, RtpMock::send_packet, &rtp_mock,
        nullptr, nullptr, nullptr, ac, RtpMock::audio_cb);
    rtp_mock.recv_session = recv_rtp;

    uint8_t dummy_data[100] = {0};
    uint32_t net_sr = net_htonl(48000);
    memcpy(dummy_data, &net_sr, 4);

    // Send enough packets to reach the sequence number wrap-around point (0xFFFF -> 0x0000).
    // We detect the current sequence number to minimize the number of iterations.
    uint16_t seq = 0;
    {
        rtp_send_data(log, send_rtp, dummy_data, sizeof(dummy_data), false);
        const uint8_t *pkt = rtp_mock.captured_packets.back().data();
        seq = (pkt[3] << 8) | pkt[4];
        rtp_receive_packet(recv_rtp, pkt, rtp_mock.captured_packets.back().size());
        rtp_mock.captured_packets.clear();
        ac_iterate(ac);
    }

    // Aim for sequence number 65532 to be the last processed packet before the gap.
    int to_send = (65532 - seq + 65536) % 65536;
    for (int i = 0; i < to_send; ++i) {
        rtp_send_data(log, send_rtp, dummy_data, sizeof(dummy_data), false);
        const uint8_t *pkt = rtp_mock.captured_packets.back().data();
        rtp_receive_packet(recv_rtp, pkt, rtp_mock.captured_packets.back().size());
        rtp_mock.captured_packets.clear();
        ac_iterate(ac);
    }

    // Now 'bottom' should be at 65533 (next expected).
    data.sample_count = 0;

    // Create a gap of 2 missing packets: 65533, 65534.
    // Packet 65535 is delivered. Gap is 2. Capacity is 3. Should NOT trigger PLC.
    rtp_send_data(log, send_rtp, dummy_data, sizeof(dummy_data), false);  // 65533 (dropped)
    rtp_send_data(log, send_rtp, dummy_data, sizeof(dummy_data), false);  // 65534 (dropped)
    rtp_send_data(log, send_rtp, dummy_data, sizeof(dummy_data), false);  // 65535 (delivered)
    rtp_receive_packet(
        recv_rtp, rtp_mock.captured_packets.back().data(), rtp_mock.captured_packets.back().size());

    // Iteration should result in no frames processed because the gap is within capacity.
    // If there is a bug in wrap-around distance calculation, it will trigger PLC here.
    ac_iterate(ac);
    EXPECT_EQ(data.sample_count, 0u);

    rtp_kill(log, send_rtp);
    rtp_kill(log, recv_rtp);
    ac_kill(ac);
}

}  // namespace
