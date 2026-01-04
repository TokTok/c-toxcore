#include "toxav.h"

#include <gtest/gtest.h>

#include <cstring>
#include <deque>
#include <mutex>
#include <vector>

#include "av_test_support.hh"

class VirtualNetwork {
public:
    void connect(ToxAV *alice, ToxAV *bob)
    {
        alice_ = alice;
        bob_ = bob;
    }

    static bool alice_send_lossy_cb(
        uint32_t friend_number, const uint8_t *data, size_t length, void *user_data)
    {
        return static_cast<VirtualNetwork *>(user_data)->send(true, data, length);
    }
    static bool alice_send_lossless_cb(
        uint32_t friend_number, const uint8_t *data, size_t length, void *user_data)
    {
        return static_cast<VirtualNetwork *>(user_data)->send(true, data, length);
    }

    static bool bob_send_lossy_cb(
        uint32_t friend_number, const uint8_t *data, size_t length, void *user_data)
    {
        return static_cast<VirtualNetwork *>(user_data)->send(false, data, length);
    }
    static bool bob_send_lossless_cb(
        uint32_t friend_number, const uint8_t *data, size_t length, void *user_data)
    {
        return static_cast<VirtualNetwork *>(user_data)->send(false, data, length);
    }

    static bool friend_exists_cb(uint32_t friend_number, void *user_data) { return true; }
    static bool friend_connected_cb(uint32_t friend_number, void *user_data) { return true; }

    void process()
    {
        while (true) {
            QueuedPacket pkt;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                if (queue_.empty())
                    break;
                pkt = queue_.front();
                queue_.pop_front();
            }
            ToxAV *target = pkt.from_alice ? bob_ : alice_;
            if (target) {
                toxav_receive_packet(target, 0, pkt.data.data(), pkt.data.size());
            }
        }
    }

private:
    struct QueuedPacket {
        bool from_alice;
        std::vector<uint8_t> data;
    };

    bool send(bool from_alice, const uint8_t *data, size_t length)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        QueuedPacket pkt;
        pkt.from_alice = from_alice;
        pkt.data.assign(data, data + length);
        queue_.push_back(pkt);
        return true;
    }

    ToxAV *alice_ = nullptr;
    ToxAV *bob_ = nullptr;
    std::deque<QueuedPacket> queue_;
    std::mutex mutex_;
};

class ToxAVCustomTest : public ::testing::Test {
protected:
    ToxAV *alice = nullptr;
    ToxAV *bob = nullptr;
    VirtualNetwork network;
    ToxAV_IO *alice_io = nullptr;
    ToxAV_IO *bob_io = nullptr;

    bool bob_invited = false;
    uint32_t alice_state = 0;
    uint32_t bob_state = 0;
    int bob_audio_frames = 0;
    int bob_video_frames = 0;
    int alice_audio_frames = 0;
    int alice_video_frames = 0;

    static void on_call(ToxAV *av, uint32_t friend_number, bool audio, bool video, void *user_data)
    {
        static_cast<ToxAVCustomTest *>(user_data)->bob_invited = true;
    }

    static void on_call_state(ToxAV *av, uint32_t friend_number, uint32_t state, void *user_data)
    {
        ToxAVCustomTest *test = static_cast<ToxAVCustomTest *>(user_data);
        if (av == test->alice)
            test->alice_state = state;
        if (av == test->bob)
            test->bob_state = state;
    }

    static void on_audio_frame(ToxAV *av, uint32_t friend_number, const int16_t *pcm,
        size_t sample_count, uint8_t channels, uint32_t sampling_rate, void *user_data)
    {
        ToxAVCustomTest *test = static_cast<ToxAVCustomTest *>(user_data);
        if (av == test->bob)
            test->bob_audio_frames++;
        if (av == test->alice)
            test->alice_audio_frames++;
    }

    static void on_video_frame(ToxAV *av, uint32_t friend_number, uint16_t width, uint16_t height,
        const uint8_t *y, const uint8_t *u, const uint8_t *v, int32_t ystride, int32_t ustride,
        int32_t vstride, void *user_data)
    {
        ToxAVCustomTest *test = static_cast<ToxAVCustomTest *>(user_data);
        if (av == test->bob)
            test->bob_video_frames++;
        if (av == test->alice)
            test->alice_video_frames++;
    }

    void SetUp() override;
    void TearDown() override;
};

void ToxAVCustomTest::SetUp()
{
    alice_io = toxav_io_new();
    toxav_io_callback_send_lossy(alice_io, VirtualNetwork::alice_send_lossy_cb);
    toxav_io_callback_send_lossless(alice_io, VirtualNetwork::alice_send_lossless_cb);
    toxav_io_callback_friend_exists(alice_io, VirtualNetwork::friend_exists_cb);
    toxav_io_callback_friend_connected(alice_io, VirtualNetwork::friend_connected_cb);

    bob_io = toxav_io_new();
    toxav_io_callback_send_lossy(bob_io, VirtualNetwork::bob_send_lossy_cb);
    toxav_io_callback_send_lossless(bob_io, VirtualNetwork::bob_send_lossless_cb);
    toxav_io_callback_friend_exists(bob_io, VirtualNetwork::friend_exists_cb);
    toxav_io_callback_friend_connected(bob_io, VirtualNetwork::friend_connected_cb);

    Toxav_Err_New err;
    alice = toxav_new_custom(alice_io, &network, &err);
    ASSERT_EQ(err, TOXAV_ERR_NEW_OK);
    bob = toxav_new_custom(bob_io, &network, &err);
    ASSERT_EQ(err, TOXAV_ERR_NEW_OK);

    toxav_io_kill(alice_io);
    toxav_io_kill(bob_io);

    network.connect(alice, bob);

    toxav_callback_call_state(alice, on_call_state, this);
    toxav_callback_call_state(bob, on_call_state, this);
    toxav_callback_call(bob, on_call, this);
    toxav_callback_audio_receive_frame(bob, on_audio_frame, this);
    toxav_callback_video_receive_frame(bob, on_video_frame, this);
    // Alice needs callbacks too for the call to be established (call_prepare_transmission
    // requirement)
    toxav_callback_audio_receive_frame(alice, on_audio_frame, this);
    toxav_callback_video_receive_frame(alice, on_video_frame, this);
}
void ToxAVCustomTest::TearDown()
{
    if (alice)
        toxav_kill(alice);
    if (bob)
        toxav_kill(bob);
}

TEST_F(ToxAVCustomTest, AudioVideoCall)
{
    Toxav_Err_Call call_err;
    bool res = toxav_call(alice, 0, 48, 1000, &call_err);
    ASSERT_TRUE(res);
    ASSERT_EQ(call_err, TOXAV_ERR_CALL_OK);

    // Process packets to deliver invite
    network.process();
    toxav_iterate(alice);
    toxav_iterate(bob);

    ASSERT_TRUE(bob_invited);

    Toxav_Err_Answer answer_err;
    res = toxav_answer(bob, 0, 48, 1000, &answer_err);
    ASSERT_TRUE(res);
    ASSERT_EQ(answer_err, TOXAV_ERR_ANSWER_OK);

    // Process packets to deliver answer
    network.process();
    toxav_iterate(alice);
    toxav_iterate(bob);

    ASSERT_NE(alice_state, 0) << "Alice call state is 0 (not connected?)";

    // Send Audio
    std::vector<int16_t> pcm(960 * 1);
    fill_audio_frame(48000, 1, 0, 960, pcm);  // 20ms frame
    Toxav_Err_Send_Frame send_err;
    res = toxav_audio_send_frame(alice, 0, pcm.data(), 960, 1, 48000, &send_err);
    ASSERT_TRUE(res) << "toxav_audio_send_frame failed with error: " << send_err;

    // Process packets
    network.process();
    toxav_iterate(alice);
    toxav_iterate(bob);

    ASSERT_GT(bob_audio_frames, 0);

    // Send Video
    std::vector<uint8_t> y, u, v;
    fill_video_frame(640, 480, 0, y, u, v);
    res = toxav_video_send_frame(alice, 0, 640, 480, y.data(), u.data(), v.data(), &send_err);
    ASSERT_TRUE(res);
    ASSERT_EQ(send_err, TOXAV_ERR_SEND_FRAME_OK);

    // Process packets
    network.process();
    toxav_iterate(alice);
    toxav_iterate(bob);

    ASSERT_GT(bob_video_frames, 0);

    // Hangup
    Toxav_Err_Call_Control cc_err;
    toxav_call_control(alice, 0, TOXAV_CALL_CONTROL_CANCEL, &cc_err);
    ASSERT_EQ(cc_err, TOXAV_ERR_CALL_CONTROL_OK);

    network.process();
    toxav_iterate(alice);
    toxav_iterate(bob);

    ASSERT_EQ(bob_state, TOXAV_FRIEND_CALL_STATE_FINISHED);
}

TEST_F(ToxAVCustomTest, BidirectionalCall)
{
    Toxav_Err_Call call_err;
    ASSERT_TRUE(toxav_call(alice, 0, 48, 1000, &call_err));
    ASSERT_EQ(call_err, TOXAV_ERR_CALL_OK);

    network.process();
    toxav_iterate(alice);
    toxav_iterate(bob);

    ASSERT_TRUE(bob_invited);

    Toxav_Err_Answer answer_err;
    ASSERT_TRUE(toxav_answer(bob, 0, 48, 1000, &answer_err));
    ASSERT_EQ(answer_err, TOXAV_ERR_ANSWER_OK);

    network.process();
    toxav_iterate(alice);
    toxav_iterate(bob);

    // Process potentially queued state changes
    network.process();
    toxav_iterate(alice);
    toxav_iterate(bob);

    ASSERT_NE(alice_state, 0);

    // Alice -> Bob Audio
    std::vector<int16_t> pcm(960 * 1);
    fill_audio_frame(48000, 1, 0, 960, pcm);
    Toxav_Err_Send_Frame send_err;
    ASSERT_TRUE(toxav_audio_send_frame(alice, 0, pcm.data(), 960, 1, 48000, &send_err));

    // Bob -> Alice Audio
    ASSERT_TRUE(toxav_audio_send_frame(bob, 0, pcm.data(), 960, 1, 48000, &send_err));

    network.process();
    toxav_iterate(alice);
    toxav_iterate(bob);

    ASSERT_GT(bob_audio_frames, 0);
    ASSERT_GT(alice_audio_frames, 0);

    // Alice -> Bob Video
    std::vector<uint8_t> y, u, v;
    fill_video_frame(640, 480, 0, y, u, v);
    ASSERT_TRUE(
        toxav_video_send_frame(alice, 0, 640, 480, y.data(), u.data(), v.data(), &send_err));

    // Bob -> Alice Video
    ASSERT_TRUE(toxav_video_send_frame(bob, 0, 640, 480, y.data(), u.data(), v.data(), &send_err));

    network.process();
    toxav_iterate(alice);
    toxav_iterate(bob);

    ASSERT_GT(bob_video_frames, 0);
    ASSERT_GT(alice_video_frames, 0);
}

TEST_F(ToxAVCustomTest, BobMutesAlice)
{
    Toxav_Err_Call call_err;
    ASSERT_TRUE(toxav_call(alice, 0, 48, 1000, &call_err));
    network.process();
    toxav_iterate(alice);
    toxav_iterate(bob);

    Toxav_Err_Answer answer_err;
    ASSERT_TRUE(toxav_answer(bob, 0, 48, 1000, &answer_err));
    network.process();
    toxav_iterate(alice);
    toxav_iterate(bob);

    // Extra process for state
    network.process();
    toxav_iterate(alice);
    toxav_iterate(bob);

    // Initial Send
    std::vector<int16_t> pcm(960 * 1);
    fill_audio_frame(48000, 1, 0, 960, pcm);
    Toxav_Err_Send_Frame send_err;
    ASSERT_TRUE(toxav_audio_send_frame(alice, 0, pcm.data(), 960, 1, 48000, &send_err));

    network.process();
    toxav_iterate(alice);
    toxav_iterate(bob);

    ASSERT_EQ(bob_audio_frames, 1);

    // Bob Mutes Alice
    Toxav_Err_Call_Control cc_err;
    ASSERT_TRUE(toxav_call_control(bob, 0, TOXAV_CALL_CONTROL_MUTE_AUDIO, &cc_err));
    ASSERT_EQ(cc_err, TOXAV_ERR_CALL_CONTROL_OK);

    network.process();
    toxav_iterate(alice);
    toxav_iterate(bob);

    // Alice sends again
    bool res = toxav_audio_send_frame(alice, 0, pcm.data(), 960, 1, 48000, &send_err);
    if (!res) {
        ASSERT_EQ(send_err, TOXAV_ERR_SEND_FRAME_PAYLOAD_TYPE_DISABLED);
    } else {
        network.process();
        toxav_iterate(alice);
        toxav_iterate(bob);

        // Should still be 1
        ASSERT_EQ(bob_audio_frames, 1);
    }
}

TEST(ToxAVManualTest, CallInsertionInMiddle)
{
    ToxAV_IO *io = toxav_io_new();
    toxav_io_callback_friend_exists(io, [](uint32_t, void *) { return true; });
    toxav_io_callback_friend_connected(io, [](uint32_t, void *) { return true; });
    toxav_io_callback_time_current(io, [](void *) { return static_cast<uint64_t>(1000000); });

    Toxav_Err_New err_new;
    struct ToxAVDeleter {
        void operator()(ToxAV *av) { toxav_kill(av); }
    };
    std::unique_ptr<ToxAV, ToxAVDeleter> av(toxav_new_custom(io, nullptr, &err_new));
    toxav_io_kill(io);

    ASSERT_NE(av, nullptr);
    ASSERT_EQ(err_new, TOXAV_ERR_NEW_OK);

    Toxav_Err_Call err;

    // Create call 10 (Head)
    toxav_call(av.get(), 10, 0, 0, &err);
    ASSERT_EQ(err, TOXAV_ERR_CALL_OK);
    // Create call 30 (Tail)
    toxav_call(av.get(), 30, 0, 0, &err);
    ASSERT_EQ(err, TOXAV_ERR_CALL_OK);

    // Create call 20 (Middle) - This triggers the bug
    toxav_call(av.get(), 20, 0, 0, &err);
    ASSERT_EQ(err, TOXAV_ERR_CALL_OK);
}
