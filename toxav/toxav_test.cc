#include <gtest/gtest.h>

#include <cstring>
#include <deque>
#include <mutex>
#include <vector>

#include "av_test_support.hh"
#include "tox_av.h"

class VirtualNetwork {
public:
    void connect(Tox_Av *alice, Tox_Av *bob)
    {
        alice_ = alice;
        bob_ = bob;
    }

    static bool send_lossy_cb(
        Tox_Av *av, uint32_t friend_number, const uint8_t *data, size_t length, void *user_data)
    {
        return static_cast<VirtualNetwork *>(user_data)->send(av, data, length);
    }
    static bool send_lossless_cb(
        Tox_Av *av, uint32_t friend_number, const uint8_t *data, size_t length, void *user_data)
    {
        return static_cast<VirtualNetwork *>(user_data)->send(av, data, length);
    }

    size_t pending()
    {
        std::lock_guard<std::mutex> lock(mutex_);
        return queue_.size();
    }

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
            Tox_Av *target = pkt.from_alice ? bob_ : alice_;
            if (target) {
                tox_av_receive_packet(target, 0, pkt.data.data(), pkt.data.size());
            }
        }
    }

private:
    struct QueuedPacket {
        bool from_alice;
        std::vector<uint8_t> data;
    };

    bool send(const Tox_Av *from, const uint8_t *data, size_t length)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        QueuedPacket pkt;
        pkt.from_alice = from == alice_;
        pkt.data.assign(data, data + length);
        queue_.push_back(pkt);
        return true;
    }

    Tox_Av *alice_ = nullptr;
    Tox_Av *bob_ = nullptr;
    std::deque<QueuedPacket> queue_;
    std::mutex mutex_;
};

class ToxAvTest : public ::testing::Test {
protected:
    Tox_Av *alice = nullptr;
    Tox_Av *bob = nullptr;
    VirtualNetwork network;

    bool bob_invited = false;
    uint32_t alice_state = 0;
    uint32_t bob_state = 0;
    int bob_audio_frames = 0;
    int bob_video_frames = 0;
    int alice_audio_frames = 0;
    int alice_video_frames = 0;

    static void on_call(Tox_Av *av, uint32_t friend_number, bool audio, bool video, void *user_data)
    {
        static_cast<ToxAvTest *>(user_data)->bob_invited = true;
    }

    static void on_call_state(Tox_Av *av, uint32_t friend_number, uint32_t state, void *user_data)
    {
        ToxAvTest *test = static_cast<ToxAvTest *>(user_data);
        if (av == test->alice)
            test->alice_state = state;
        if (av == test->bob)
            test->bob_state = state;
    }

    static void on_audio_frame(Tox_Av *av, uint32_t friend_number, const int16_t *pcm,
        size_t sample_count, uint8_t channels, uint32_t sampling_rate, void *user_data)
    {
        ToxAvTest *test = static_cast<ToxAvTest *>(user_data);
        if (av == test->bob)
            test->bob_audio_frames++;
        if (av == test->alice)
            test->alice_audio_frames++;
    }

    static void on_video_frame(Tox_Av *av, uint32_t friend_number, uint16_t width, uint16_t height,
        const uint8_t *y, const uint8_t *u, const uint8_t *v, int32_t ystride, int32_t ustride,
        int32_t vstride, void *user_data)
    {
        ToxAvTest *test = static_cast<ToxAvTest *>(user_data);
        if (av == test->bob)
            test->bob_video_frames++;
        if (av == test->alice)
            test->alice_video_frames++;
    }

    /** Sends what each queued, delivers it, and lets each handle it. */
    void step()
    {
        tox_av_iterate(alice);
        tox_av_iterate(bob);
        network.process();
        tox_av_iterate(alice);
        tox_av_iterate(bob);
    }

    void SetUp() override;
    void TearDown() override;
};

void ToxAvTest::SetUp()
{
    Tox_Err_Av_New err;
    alice = tox_av_new(&err);
    ASSERT_EQ(err, TOX_ERR_AV_NEW_OK);
    bob = tox_av_new(&err);
    ASSERT_EQ(err, TOX_ERR_AV_NEW_OK);

    network.connect(alice, bob);

    for (Tox_Av *av : {alice, bob}) {
        tox_av_callback_send_lossy_packet(av, VirtualNetwork::send_lossy_cb, &network);
        tox_av_callback_send_lossless_packet(av, VirtualNetwork::send_lossless_cb, &network);
        tox_av_friend_connection_status(av, 0, true);
    }

    tox_av_callback_call_state(alice, on_call_state, this);
    tox_av_callback_call_state(bob, on_call_state, this);
    tox_av_callback_call(bob, on_call, this);
    tox_av_callback_audio_receive_frame(bob, on_audio_frame, this);
    tox_av_callback_video_receive_frame(bob, on_video_frame, this);
    // Alice needs callbacks too for the call to be established (call_prepare_transmission
    // requirement)
    tox_av_callback_audio_receive_frame(alice, on_audio_frame, this);
    tox_av_callback_video_receive_frame(alice, on_video_frame, this);
}
void ToxAvTest::TearDown()
{
    if (alice)
        tox_av_kill(alice);
    if (bob)
        tox_av_kill(bob);
}

TEST_F(ToxAvTest, AudioVideoCall)
{
    Tox_Err_Av_Call call_err;
    bool res = tox_av_call(alice, 0, 48, 1000, &call_err);
    ASSERT_TRUE(res);
    ASSERT_EQ(call_err, TOX_ERR_AV_CALL_OK);

    // Process packets to deliver invite
    step();

    ASSERT_TRUE(bob_invited);

    Tox_Err_Av_Answer answer_err;
    res = tox_av_answer(bob, 0, 48, 1000, &answer_err);
    ASSERT_TRUE(res);
    ASSERT_EQ(answer_err, TOX_ERR_AV_ANSWER_OK);

    // Process packets to deliver answer
    step();

    ASSERT_NE(alice_state, 0) << "Alice call state is 0 (not connected?)";

    // Send Audio
    std::vector<int16_t> pcm(960 * 1);
    fill_audio_frame(48000, 1, 0, 960, pcm);  // 20ms frame
    Tox_Err_Av_Send_Frame send_err;
    res = tox_av_audio_send_frame(alice, 0, pcm.data(), 960, 1, 48000, &send_err);
    ASSERT_TRUE(res) << "tox_av_audio_send_frame failed with error: " << send_err;

    // Process packets
    step();

    ASSERT_GT(bob_audio_frames, 0);

    // Send Video
    std::vector<uint8_t> y, u, v;
    fill_video_frame(640, 480, 0, y, u, v);
    res = tox_av_video_send_frame(alice, 0, 640, 480, y.data(), u.data(), v.data(), &send_err);
    ASSERT_TRUE(res);
    ASSERT_EQ(send_err, TOX_ERR_AV_SEND_FRAME_OK);

    // Process packets
    step();

    ASSERT_GT(bob_video_frames, 0);

    // Hangup
    Tox_Err_Av_Call_Control cc_err;
    tox_av_call_control(alice, 0, TOX_AV_CALL_CONTROL_CANCEL, &cc_err);
    ASSERT_EQ(cc_err, TOX_ERR_AV_CALL_CONTROL_OK);

    step();

    ASSERT_EQ(bob_state, TOX_AV_FRIEND_CALL_STATE_FINISHED);
}

TEST_F(ToxAvTest, BidirectionalCall)
{
    Tox_Err_Av_Call call_err;
    ASSERT_TRUE(tox_av_call(alice, 0, 48, 1000, &call_err));
    ASSERT_EQ(call_err, TOX_ERR_AV_CALL_OK);

    step();

    ASSERT_TRUE(bob_invited);

    Tox_Err_Av_Answer answer_err;
    ASSERT_TRUE(tox_av_answer(bob, 0, 48, 1000, &answer_err));
    ASSERT_EQ(answer_err, TOX_ERR_AV_ANSWER_OK);

    step();

    // Process potentially queued state changes
    step();

    ASSERT_NE(alice_state, 0);

    // Alice -> Bob Audio
    std::vector<int16_t> pcm(960 * 1);
    fill_audio_frame(48000, 1, 0, 960, pcm);
    Tox_Err_Av_Send_Frame send_err;
    ASSERT_TRUE(tox_av_audio_send_frame(alice, 0, pcm.data(), 960, 1, 48000, &send_err));

    // Bob -> Alice Audio
    ASSERT_TRUE(tox_av_audio_send_frame(bob, 0, pcm.data(), 960, 1, 48000, &send_err));

    step();

    ASSERT_GT(bob_audio_frames, 0);
    ASSERT_GT(alice_audio_frames, 0);

    // Alice -> Bob Video
    std::vector<uint8_t> y, u, v;
    fill_video_frame(640, 480, 0, y, u, v);
    ASSERT_TRUE(
        tox_av_video_send_frame(alice, 0, 640, 480, y.data(), u.data(), v.data(), &send_err));

    // Bob -> Alice Video
    ASSERT_TRUE(tox_av_video_send_frame(bob, 0, 640, 480, y.data(), u.data(), v.data(), &send_err));

    step();

    ASSERT_GT(bob_video_frames, 0);
    ASSERT_GT(alice_video_frames, 0);
}

TEST_F(ToxAvTest, BobMutesAlice)
{
    Tox_Err_Av_Call call_err;
    ASSERT_TRUE(tox_av_call(alice, 0, 48, 1000, &call_err));
    step();

    Tox_Err_Av_Answer answer_err;
    ASSERT_TRUE(tox_av_answer(bob, 0, 48, 1000, &answer_err));
    step();

    // Extra process for state
    step();

    // Initial Send
    std::vector<int16_t> pcm(960 * 1);
    fill_audio_frame(48000, 1, 0, 960, pcm);
    Tox_Err_Av_Send_Frame send_err;
    ASSERT_TRUE(tox_av_audio_send_frame(alice, 0, pcm.data(), 960, 1, 48000, &send_err));

    step();

    ASSERT_EQ(bob_audio_frames, 1);

    // Bob Mutes Alice
    Tox_Err_Av_Call_Control cc_err;
    ASSERT_TRUE(tox_av_call_control(bob, 0, TOX_AV_CALL_CONTROL_MUTE_AUDIO, &cc_err));
    ASSERT_EQ(cc_err, TOX_ERR_AV_CALL_CONTROL_OK);

    step();

    // Alice sends again
    bool res = tox_av_audio_send_frame(alice, 0, pcm.data(), 960, 1, 48000, &send_err);
    if (!res) {
        ASSERT_EQ(send_err, TOX_ERR_AV_SEND_FRAME_PAYLOAD_TYPE_DISABLED);
    } else {
        step();

        // Should still be 1
        ASSERT_EQ(bob_audio_frames, 1);
    }
}

/**
 * Clients iterate as often as tox_av_iteration_interval says, which is about
 * once a second when nothing comes in, so frames can't wait for an iterate.
 */
TEST_F(ToxAvTest, FramesAreSentByTheFrameSend)
{
    Tox_Err_Av_Call call_err;
    ASSERT_TRUE(tox_av_call(alice, 0, 48, 1000, &call_err));
    step();
    Tox_Err_Av_Answer answer_err;
    ASSERT_TRUE(tox_av_answer(bob, 0, 0, 0, &answer_err));  // Bob only listens.
    step();
    step();

    std::vector<int16_t> pcm(960);
    fill_audio_frame(48000, 1, 0, 960, pcm);
    std::vector<uint8_t> y, u, v;
    fill_video_frame(640, 480, 0, y, u, v);
    Tox_Err_Av_Send_Frame send_err;
    size_t before = network.pending();
    ASSERT_TRUE(tox_av_audio_send_frame(alice, 0, pcm.data(), 960, 1, 48000, &send_err));
    EXPECT_GT(network.pending(), before);
    before = network.pending();
    ASSERT_TRUE(
        tox_av_video_send_frame(alice, 0, 640, 480, y.data(), u.data(), v.data(), &send_err));
    EXPECT_GT(network.pending(), before);
}

TEST_F(ToxAvTest, CallToAFriendNotConnectedFails)
{
    tox_av_friend_connection_status(alice, 0, false);

    Tox_Err_Av_Call call_err;
    EXPECT_FALSE(tox_av_call(alice, 0, 48, 0, &call_err));
    EXPECT_EQ(call_err, TOX_ERR_AV_CALL_FRIEND_NOT_CONNECTED);
}

TEST_F(ToxAvTest, CallEndsWhenTheFriendDisconnects)
{
    Tox_Err_Av_Call call_err;
    ASSERT_TRUE(tox_av_call(alice, 0, 48, 0, &call_err));
    step();
    Tox_Err_Av_Answer answer_err;
    ASSERT_TRUE(tox_av_answer(bob, 0, 48, 0, &answer_err));
    step();

    tox_av_friend_connection_status(alice, 0, false);
    tox_av_iterate(alice);
    EXPECT_EQ(alice_state, TOX_AV_FRIEND_CALL_STATE_ERROR);
}

TEST_F(ToxAvTest, AnyFriendNumberWorks)
{
    const uint32_t friend_number = UINT32_MAX - 1;
    tox_av_friend_connection_status(alice, friend_number, true);

    Tox_Err_Av_Call call_err;
    EXPECT_TRUE(tox_av_call(alice, friend_number, 48, 0, &call_err));
    EXPECT_EQ(call_err, TOX_ERR_AV_CALL_OK);
}
