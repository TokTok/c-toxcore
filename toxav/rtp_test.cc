#include "rtp.h"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <vector>

#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/net_crypto.h"
#include "../toxcore/os_memory.h"

namespace {

struct MockSessionData {
    MockSessionData();
    ~MockSessionData();

    std::vector<std::vector<uint8_t>> sent_packets;
    std::vector<std::vector<uint8_t>> received_frames;
    std::vector<uint16_t> received_frame_lengths;
    std::vector<uint32_t> received_full_lengths;
    std::vector<uint16_t> received_sequnums;
    std::vector<uint8_t> received_pts;
    std::vector<uint64_t> received_flags;

    uint32_t total_bytes_received = 0;
    uint32_t total_bytes_lost = 0;
};

MockSessionData::MockSessionData() = default;
MockSessionData::~MockSessionData() = default;

static int mock_send_packet(void *user_data, const uint8_t *data, uint16_t length)
{
    auto *sd = static_cast<MockSessionData *>(user_data);
    sd->sent_packets.emplace_back(data, data + length);
    return 0;
}

static int mock_m_cb(const Mono_Time * /*mono_time*/, void *cs, RTPMessage *msg)
{
    auto *sd = static_cast<MockSessionData *>(cs);

    sd->received_pts.push_back(rtp_message_pt(msg));
    sd->received_flags.push_back(rtp_message_flags(msg));

    const uint8_t *data = rtp_message_data(msg);
    uint16_t len = rtp_message_len(msg);
    uint32_t full_len = rtp_message_data_length_full(msg);

    // If full_len is not set (old protocol), use len
    uint32_t actual_len = (full_len > 0) ? full_len : len;

    sd->received_frames.emplace_back(data, data + actual_len);
    sd->received_frame_lengths.push_back(len);
    sd->received_full_lengths.push_back(full_len);
    sd->received_sequnums.push_back(rtp_message_sequnum(msg));

    std::free(msg);
    return 0;
}

static void mock_add_recv(void *user_data, uint32_t bytes)
{
    auto *sd = static_cast<MockSessionData *>(user_data);
    sd->total_bytes_received += bytes;
}

static void mock_add_lost(void *user_data, uint32_t bytes)
{
    auto *sd = static_cast<MockSessionData *>(user_data);
    sd->total_bytes_lost += bytes;
}

class RtpPublicTest : public ::testing::Test {
protected:
    void SetUp() override
    {
        const Memory *mem = os_memory();
        log = logger_new(mem);
        mono_time = mono_time_new(mem, nullptr, nullptr);
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
};

TEST_F(RtpPublicTest, BasicAudioSendReceive)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_AUDIO, mono_time, mock_send_packet, &sd,
        mock_add_recv, mock_add_lost, &sd, &sd, mock_m_cb);
    ASSERT_NE(session, nullptr);

    uint8_t data[] = "Hello RTP";
    rtp_send_data(log, session, data, sizeof(data), false);

    ASSERT_EQ(sd.sent_packets.size(), 1);
    EXPECT_EQ(sd.sent_packets[0][0], RTP_TYPE_AUDIO);

    rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());

    ASSERT_EQ(sd.received_frames.size(), 1);
    EXPECT_EQ(sd.received_frames[0].size(), sizeof(data));
    EXPECT_STREQ(reinterpret_cast<const char *>(sd.received_frames[0].data()), "Hello RTP");
    EXPECT_EQ(sd.received_pts[0], RTP_TYPE_AUDIO % 128);
    EXPECT_EQ(sd.received_flags[0], 0);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, LargeVideoFrameFragmentation)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_VIDEO, mono_time, mock_send_packet, &sd,
        mock_add_recv, mock_add_lost, &sd, &sd, mock_m_cb);

    // Frame larger than MAX_CRYPTO_DATA_SIZE
    const uint32_t frame_size = MAX_CRYPTO_DATA_SIZE + 500;
    std::vector<uint8_t> data(frame_size);
    for (uint32_t i = 0; i < frame_size; ++i)
        data[i] = i & 0xFF;

    rtp_send_data(log, session, data.data(), frame_size, true);

    // Should be at least 2 packets
    ASSERT_GE(sd.sent_packets.size(), 2);

    // Receive packets in order
    for (const auto &pkt : sd.sent_packets) {
        rtp_receive_packet(session, pkt.data(), pkt.size());
    }

    ASSERT_EQ(sd.received_frames.size(), 1);
    EXPECT_EQ(sd.received_frames[0], data);
    EXPECT_EQ(sd.received_pts[0], RTP_TYPE_VIDEO % 128);
    EXPECT_TRUE(sd.received_flags[0] & RTP_KEY_FRAME);
    EXPECT_TRUE(sd.received_flags[0] & RTP_LARGE_FRAME);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, OutOfOrderVideoPackets)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_VIDEO, mono_time, mock_send_packet, &sd,
        mock_add_recv, mock_add_lost, &sd, &sd, mock_m_cb);

    const uint32_t frame_size = MAX_CRYPTO_DATA_SIZE + 100;
    std::vector<uint8_t> data(frame_size, 0x55);
    rtp_send_data(log, session, data.data(), frame_size, false);

    ASSERT_EQ(sd.sent_packets.size(), 2);

    // Receive last packet first
    rtp_receive_packet(session, sd.sent_packets[1].data(), sd.sent_packets[1].size());
    EXPECT_EQ(sd.received_frames.size(), 0);

    // Receive first packet
    rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());
    ASSERT_EQ(sd.received_frames.size(), 1);
    EXPECT_EQ(sd.received_frames[0].size(), frame_size);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, HandlingInvalidPackets)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_AUDIO, mono_time, mock_send_packet, &sd,
        mock_add_recv, mock_add_lost, &sd, &sd, mock_m_cb);

    // Packet too short to even contain the Tox packet ID
    rtp_receive_packet(session, nullptr, 0);

    // Packet too short (less than RTP_HEADER_SIZE + 1)
    uint8_t short_pkt[10] = {RTP_TYPE_AUDIO};
    rtp_receive_packet(session, short_pkt, sizeof(short_pkt));

    // Wrong packet ID (Tox level)
    uint8_t wrong_id[RTP_HEADER_SIZE + 10];
    std::memset(wrong_id, 0, sizeof(wrong_id));
    wrong_id[0] = RTP_TYPE_VIDEO;  // Session expects AUDIO
    rtp_receive_packet(session, wrong_id, sizeof(wrong_id));

    EXPECT_EQ(sd.received_frames.size(), 0);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, ReceiveActiveToggle)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_AUDIO, mono_time, mock_send_packet, &sd,
        mock_add_recv, mock_add_lost, &sd, &sd, mock_m_cb);

    EXPECT_TRUE(rtp_session_is_receiving_active(session));

    rtp_stop_receiving_mark(session);
    EXPECT_FALSE(rtp_session_is_receiving_active(session));

    rtp_allow_receiving_mark(session);
    EXPECT_TRUE(rtp_session_is_receiving_active(session));

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, SsrcAccessors)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_VIDEO, mono_time, mock_send_packet, &sd,
        mock_add_recv, mock_add_lost, &sd, &sd, mock_m_cb);

    rtp_session_set_ssrc(session, 0x12345678);
    EXPECT_EQ(rtp_session_get_ssrc(session), 0x12345678);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, LargeAudioFragmentationOldProtocol)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_AUDIO, mono_time, mock_send_packet, &sd,
        mock_add_recv, mock_add_lost, &sd, &sd, mock_m_cb);

    // Audio doesn't use RTP_LARGE_FRAME, so it uses the old 16-bit offset/length fields
    const uint32_t frame_size = MAX_CRYPTO_DATA_SIZE + 500;
    std::vector<uint8_t> data(frame_size, 0x44);

    rtp_send_data(log, session, data.data(), frame_size, false);

    ASSERT_GE(sd.sent_packets.size(), 2);

    for (const auto &pkt : sd.sent_packets) {
        rtp_receive_packet(session, pkt.data(), pkt.size());
    }

    ASSERT_EQ(sd.received_frames.size(), 1);
    EXPECT_EQ(sd.received_frames[0].size(), frame_size);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, WorkBufferEvictionAndKeyframePreservation)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_VIDEO, mono_time, mock_send_packet, &sd,
        mock_add_recv, mock_add_lost, &sd, &sd, mock_m_cb);

    struct TimeMock {
        uint64_t t;
    } tm = {1000};

    auto time_cb = [](void *ud) -> uint64_t { return static_cast<TimeMock *>(ud)->t; };
    mono_time_set_current_time_callback(mono_time, time_cb, &tm);
    mono_time_update(mono_time);

    // USED_RTP_WORKBUFFER_COUNT is 3.
    // 1. Start a keyframe (frame 0) but don't finish it.
    const uint32_t frame_size = MAX_CRYPTO_DATA_SIZE + 100;
    std::vector<uint8_t> kf_data(frame_size, 0x11);
    rtp_send_data(log, session, kf_data.data(), frame_size, true);
    rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());
    sd.sent_packets.clear();

    // 2. Start two interframes (frames 1 and 2) but don't finish them.
    for (int i = 0; i < 2; ++i) {
        tm.t += 1;
        mono_time_update(mono_time);
        std::vector<uint8_t> if_data(frame_size, 0x20 + i);
        rtp_send_data(log, session, if_data.data(), frame_size, false);
        rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());
        sd.sent_packets.clear();
    }

    // Now work buffer has 3 slots: [KF(part), IF1(part), IF2(part)]
    EXPECT_EQ(sd.received_frames.size(), 0);

    // 3. Start another interframe (frame 3).
    // Since slot 0 is a KEYFRAME and it's not old yet (tm.t=1002, KF.t=1000, age=2ms < 15ms),
    // and it's not finished, it should be kept.
    // The new IF should be DROPPED because there's no space and slot 0 is a protected KF.
    tm.t += 1;
    mono_time_update(mono_time);
    std::vector<uint8_t> if3_data(frame_size, 0x33);
    rtp_send_data(log, session, if3_data.data(), frame_size, false);
    rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());
    sd.sent_packets.clear();

    EXPECT_EQ(sd.received_frames.size(), 0);

    // 4. Advance time by 20ms (> VIDEO_KEEP_KEYFRAME_IN_BUFFER_FOR_MS = 15).
    // Now slot 0 (the KF) is old relative to the new incoming frame's timestamp.
    tm.t += 20;
    mono_time_update(mono_time);

    // 5. Start another frame (frame 4).
    // Now the old KF should be evicted and processed (sent to callback), making room.
    std::vector<uint8_t> if4_data(frame_size, 0x44);
    rtp_send_data(log, session, if4_data.data(), frame_size, false);
    rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());

    // We expect the KF to have been delivered now.
    ASSERT_GE(sd.received_frames.size(), 1);
    EXPECT_EQ(sd.received_frames[0][0], 0x11);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, BwcReporting)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_VIDEO, mono_time, mock_send_packet, &sd,
        mock_add_recv, mock_add_lost, &sd, &sd, mock_m_cb);

    uint8_t data[] = "test";
    // DISMISS_FIRST_LOST_VIDEO_PACKET_COUNT is 10.
    // Packets 1-9 are dismissed. Packet 10 is reported.
    for (int i = 0; i < 10; ++i) {
        sd.sent_packets.clear();
        rtp_send_data(log, session, data, sizeof(data), false);
        rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());
    }

    // Packet 10 should have been the first one reported.
    EXPECT_EQ(sd.total_bytes_received, sizeof(data));
    EXPECT_EQ(sd.total_bytes_lost, 0);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, OldProtocolEdgeCases)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_AUDIO, mono_time, mock_send_packet, &sd, nullptr,
        nullptr, nullptr, &sd, mock_m_cb);

    // 1. Multipart message interrupted by a newer message.
    const uint32_t large_size = 5000;
    std::vector<uint8_t> data(large_size, 0xAA);
    rtp_send_data(log, session, data.data(), large_size, false);

    ASSERT_GE(sd.sent_packets.size(), 2);
    // Receive only the first part of the first message
    rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());
    EXPECT_EQ(sd.received_frames.size(), 0);

    // Send a second message (newer)
    std::vector<uint8_t> data2 = {0x1, 0x2, 0x3};
    rtp_send_data(log, session, data2.data(), data2.size(), false);
    // The second message is the last one in sent_packets.
    rtp_receive_packet(session, sd.sent_packets.back().data(), sd.sent_packets.back().size());

    // The first (incomplete) message should have been pushed to mcb when the second one arrived.
    ASSERT_EQ(sd.received_frames.size(), 2);
    EXPECT_LT(sd.received_frame_lengths[0], large_size);
    EXPECT_EQ(sd.received_pts[0], RTP_TYPE_AUDIO % 128);
    EXPECT_EQ(sd.received_frame_lengths[1], static_cast<uint16_t>(data2.size()));

    // 2. Discarding old message part
    sd.received_frames.clear();
    sd.received_frame_lengths.clear();
    sd.received_full_lengths.clear();
    sd.received_pts.clear();

    // Send a very new message.
    std::vector<uint8_t> data3 = {0xDE, 0xAD};
    rtp_send_data(log, session, data3.data(), data3.size(), false);
    rtp_receive_packet(session, sd.sent_packets.back().data(), sd.sent_packets.back().size());
    EXPECT_EQ(sd.received_frames.size(), 1);

    // Now try to "receive" an old part of message 1 (Index 1)
    rtp_receive_packet(session, sd.sent_packets[1].data(), sd.sent_packets[1].size());
    // It should be discarded because it's older than the current session state.
    EXPECT_EQ(sd.received_frames.size(), 1);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, MoreInvalidPackets)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_VIDEO, mono_time, mock_send_packet, &sd, nullptr,
        nullptr, nullptr, &sd, mock_m_cb);

    // Get a valid packet to start with
    uint8_t data[] = "test";
    rtp_send_data(log, session, data, sizeof(data), false);
    std::vector<uint8_t> valid_pkt = sd.sent_packets[0];
    sd.sent_packets.clear();

    // 1. RTPHeader packet type and Tox protocol packet type do not agree
    std::vector<uint8_t> bad_pkt_1 = valid_pkt;
    bad_pkt_1[0] = RTP_TYPE_AUDIO;  // Tox ID says AUDIO, but header (byte 2) still says VIDEO
    rtp_receive_packet(session, bad_pkt_1.data(), bad_pkt_1.size());
    EXPECT_EQ(sd.received_frames.size(), 0);

    // 2. RTPHeader packet type does not match session payload type
    // Create an AUDIO session and send it the valid VIDEO packet
    RTPSession *session_audio = rtp_new(log, RTP_TYPE_AUDIO, mono_time, mock_send_packet, &sd,
        nullptr, nullptr, nullptr, &sd, mock_m_cb);
    rtp_receive_packet(session_audio, valid_pkt.data(), valid_pkt.size());
    EXPECT_EQ(sd.received_frames.size(), 0);
    rtp_kill(log, session_audio);

    // 3. Invalid video packet: offset >= length
    // From rtp.c, offset_full is at byte 20 and data_length_full at byte 24 of the RTP header.
    // The RTP header starts at index 1 of the packet.
    std::vector<uint8_t> bad_pkt_3 = valid_pkt;
    // Set offset (bytes 21-24) to be equal to length (bytes 25-28)
    // For a small packet, both are usually 0 and sizeof(data) respectively.
    // Let's just make offset very large.
    bad_pkt_3[1 + 20] = 0xFF;
    bad_pkt_3[1 + 21] = 0xFF;

    rtp_receive_packet(session, bad_pkt_3.data(), bad_pkt_3.size());
    EXPECT_EQ(sd.received_frames.size(), 0);

    // 4. Invalid old protocol packet: offset >= length
    // offset_lower is at byte 76, data_length_lower at byte 78 of the RTP header.
    RTPSession *session_audio2 = rtp_new(log, RTP_TYPE_AUDIO, mono_time, mock_send_packet, &sd,
        nullptr, nullptr, nullptr, &sd, mock_m_cb);

    rtp_send_data(log, session_audio2, data, sizeof(data), false);
    std::vector<uint8_t> audio_pkt = sd.sent_packets[0];
    sd.sent_packets.clear();

    std::vector<uint8_t> bad_pkt_4 = audio_pkt;
    // Set offset_lower (byte 1 + 76) > data_length_lower (byte 1 + 78)
    bad_pkt_4[1 + 76] = 0x01;  // offset = 256
    bad_pkt_4[1 + 77] = 0x00;
    bad_pkt_4[1 + 78] = 0x00;  // length = 10
    bad_pkt_4[1 + 79] = 0x0A;

    rtp_receive_packet(session_audio2, bad_pkt_4.data(), bad_pkt_4.size());
    EXPECT_EQ(sd.received_frames.size(), 0);
    rtp_kill(log, session_audio2);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, VideoJitterBufferEdgeCases)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_VIDEO, mono_time, mock_send_packet, &sd, nullptr,
        nullptr, nullptr, &sd, mock_m_cb);

    // Use a large frame size to force fragmentation and keep slots occupied
    const uint32_t frame_size = MAX_CRYPTO_DATA_SIZE + 100;
    std::vector<uint8_t> data(frame_size, 0);

    // Advancing time for subsequent frames
    struct TimeMock {
        uint64_t t;
    } tm = {1000};
    auto time_cb = [](void *ud) -> uint64_t { return static_cast<TimeMock *>(ud)->t; };
    mono_time_set_current_time_callback(mono_time, time_cb, &tm);
    mono_time_update(mono_time);

    // 1. Packet too old for work buffer
    rtp_send_data(log, session, data.data(), frame_size, false);  // Time 1000ms
    std::vector<uint8_t> old_pkt = sd.sent_packets[0];
    // Receive only first part to keep slot occupied
    rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());
    EXPECT_EQ(sd.received_frames.size(), 0);
    sd.sent_packets.clear();

    // Send a newer frame by advancing time
    tm.t = 2000;
    mono_time_update(mono_time);
    rtp_send_data(log, session, data.data(), frame_size, false);  // Time 2000ms
    // Receive first part of this one too. Now we have two slots occupied.
    rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());
    EXPECT_EQ(sd.received_frames.size(), 0);
    sd.sent_packets.clear();

    // Now try to send the old packet again. It should be rejected because
    // it's older than the most recent frame in the buffer.
    rtp_receive_packet(session, old_pkt.data(), old_pkt.size());
    EXPECT_EQ(sd.received_frames.size(), 0);

    // 2. Interframe waiting for keyframe in slot 0
    rtp_kill(log, session);
    sd.received_frames.clear();
    session = rtp_new(log, RTP_TYPE_VIDEO, mono_time, mock_send_packet, &sd, nullptr, nullptr,
        nullptr, &sd, mock_m_cb);

    // Fill slot 0 with an incomplete Keyframe
    std::vector<uint8_t> kf_data(frame_size, 0x11);
    tm.t = 3000;
    mono_time_update(mono_time);
    rtp_send_data(log, session, kf_data.data(), frame_size, true);
    // Receive only first part
    rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());
    sd.sent_packets.clear();

    // Now send a complete Interframe
    std::vector<uint8_t> if_data(10, 0x22);
    tm.t += 1;
    mono_time_update(mono_time);
    rtp_send_data(log, session, if_data.data(), if_data.size(), false);
    rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());

    // The interframe should be in slot 1, but NOT processed because slot 0 is an incomplete KF
    EXPECT_EQ(sd.received_frames.size(), 0);

    rtp_kill(log, session);
}

TEST_F(RtpPublicTest, OldProtocolCorruption)
{
    MockSessionData sd;
    RTPSession *session = rtp_new(log, RTP_TYPE_AUDIO, mono_time, mock_send_packet, &sd, nullptr,
        nullptr, nullptr, &sd, mock_m_cb);

    // 1. Packet claiming a smaller length than its payload.
    // This triggers the condition that previously caused a DoS crash via
    // an assertion failure in new_message().
    uint8_t data[10] = {0};
    rtp_send_data(log, session, data, sizeof(data), false);
    std::vector<uint8_t> pkt = sd.sent_packets[0];
    sd.sent_packets.clear();

    // Modify data_length_lower (byte 1 + 78) to be 2, while payload is 10.
    pkt[1 + 78] = 0x00;
    pkt[1 + 79] = 0x02;

    // This used to trigger an assertion failure (crash). Now it should return nullptr.
    rtp_receive_packet(session, pkt.data(), pkt.size());
    EXPECT_EQ(sd.received_frames.size(), 0);

    // 2. Corruption check for an EXISTING multipart message.
    const uint32_t multipart_size = 5000;
    std::vector<uint8_t> multipart_data(multipart_size, 0xBB);
    rtp_send_data(log, session, multipart_data.data(), multipart_size, false);

    // Receive the first part
    rtp_receive_packet(session, sd.sent_packets[0].data(), sd.sent_packets[0].size());
    EXPECT_EQ(sd.received_frames.size(), 0);

    // Now receive a corrupted second part that claims a weird offset
    std::vector<uint8_t> corrupted_part = sd.sent_packets[1];
    // offset_lower is at byte 76. Set it beyond data_length_lower.
    corrupted_part[1 + 76] = 0xFF;
    corrupted_part[1 + 77] = 0xFF;

    rtp_receive_packet(session, corrupted_part.data(), corrupted_part.size());
    // It should return early without pushing the message.
    EXPECT_EQ(sd.received_frames.size(), 0);

    rtp_kill(log, session);
}

}  // namespace
