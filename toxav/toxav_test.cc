#include "av_core.h"

#include <gtest/gtest.h>

#include <cstring>
#include <deque>
#include <mutex>
#include <set>
#include <vector>

#include "../toxcore/logger.h"
#include "../toxcore/os_memory.h"
#include "av_test_support.hh"

namespace {

class VirtualNetwork;

/** One side's view of the network: friend 0 is the other side. */
struct Peer {
    VirtualNetwork *network;
    std::set<uint32_t> connected{0};
};

class VirtualNetwork {
public:
    void connect(ToxAV *alice, ToxAV *bob)
    {
        alice_ = alice;
        bob_ = bob;
    }

    static bool send_cb(ToxAV *av, uint32_t friend_number, const uint8_t *data, size_t length, void *user_data)
    {
        return static_cast<Peer *>(user_data)->network->send(av, data, length);
    }

    static bool friend_exists_cb(uint32_t friend_number, void *user_data) { return true; }

    static bool friend_connected_cb(uint32_t friend_number, void *user_data)
    {
        return static_cast<Peer *>(user_data)->connected.count(friend_number) != 0;
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
            ToxAV *target = pkt.from_alice ? bob_ : alice_;
            if (target) {
                av_core_receive_packet(target, 0, pkt.data.data(), pkt.data.size());
            }
        }
    }

private:
    struct QueuedPacket {
        bool from_alice;
        std::vector<uint8_t> data;
    };

    bool send(const ToxAV *from, const uint8_t *data, size_t length)
    {
        std::lock_guard<std::mutex> lock(mutex_);
        QueuedPacket pkt;
        pkt.from_alice = from == alice_;
        pkt.data.assign(data, data + length);
        queue_.push_back(pkt);
        return true;
    }

    ToxAV *alice_ = nullptr;
    ToxAV *bob_ = nullptr;
    std::deque<QueuedPacket> queue_;
    std::mutex mutex_;
};

class ToxAvTest : public ::testing::Test {
protected:
    Logger *log = nullptr;
    VirtualNetwork network;
    Peer alice_peer{&network};
    Peer bob_peer{&network};
    ToxAV *alice = nullptr;
    ToxAV *bob = nullptr;

    bool bob_invited = false;
    uint32_t alice_state = 0;
    uint32_t bob_state = 0;
    int bob_audio_frames = 0;
    int bob_video_frames = 0;
    int alice_audio_frames = 0;
    int alice_video_frames = 0;

    static void on_call(ToxAV *av, uint32_t friend_number, bool audio, bool video, void *user_data)
    {
        static_cast<ToxAvTest *>(user_data)->bob_invited = true;
    }

    static void on_call_state(ToxAV *av, uint32_t friend_number, uint32_t state, void *user_data)
    {
        ToxAvTest *test = static_cast<ToxAvTest *>(user_data);
        if (av == test->alice)
            test->alice_state = state;
        if (av == test->bob)
            test->bob_state = state;
    }

    static void on_audio_frame(ToxAV *av, uint32_t friend_number, const int16_t *pcm,
        size_t sample_count, uint8_t channels, uint32_t sampling_rate, void *user_data)
    {
        ToxAvTest *test = static_cast<ToxAvTest *>(user_data);
        if (av == test->bob)
            test->bob_audio_frames++;
        if (av == test->alice)
            test->alice_audio_frames++;
    }

    static void on_video_frame(ToxAV *av, uint32_t friend_number, uint16_t width, uint16_t height,
        const uint8_t *y, const uint8_t *u, const uint8_t *v, int32_t ystride, int32_t ustride,
        int32_t vstride, void *user_data)
    {
        ToxAvTest *test = static_cast<ToxAvTest *>(user_data);
        if (av == test->bob)
            test->bob_video_frames++;
        if (av == test->alice)
            test->alice_video_frames++;
    }

    ToxAV *make(Peer *peer)
    {
        const Av_Core_Network net = {
            VirtualNetwork::send_cb,
            VirtualNetwork::send_cb,
            VirtualNetwork::friend_exists_cb,
            VirtualNetwork::friend_connected_cb,
            peer,
        };
        return av_core_new(os_memory(), log, nullptr, nullptr, &net);
    }

    /** Sends what each queued, delivers it, and lets each handle it. */
    void step()
    {
        toxav_iterate(alice);
        toxav_iterate(bob);
        network.process();
        toxav_iterate(alice);
        toxav_iterate(bob);
    }

    void SetUp() override;
    void TearDown() override;
};

void ToxAvTest::SetUp()
{
    log = logger_new(os_memory());
    ASSERT_NE(log, nullptr);
    alice = make(&alice_peer);
    ASSERT_NE(alice, nullptr);
    bob = make(&bob_peer);
    ASSERT_NE(bob, nullptr);

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

void ToxAvTest::TearDown()
{
    av_core_kill(alice);
    av_core_kill(bob);
    logger_kill(log);
}

TEST_F(ToxAvTest, AudioVideoCall)
{
    Toxav_Err_Call call_err;
    bool res = toxav_call(alice, 0, 48, 1000, &call_err);
    ASSERT_TRUE(res);
    ASSERT_EQ(call_err, TOXAV_ERR_CALL_OK);

    // Process packets to deliver invite
    step();

    ASSERT_TRUE(bob_invited);

    Toxav_Err_Answer answer_err;
    res = toxav_answer(bob, 0, 48, 1000, &answer_err);
    ASSERT_TRUE(res);
    ASSERT_EQ(answer_err, TOXAV_ERR_ANSWER_OK);

    // Process packets to deliver answer
    step();

    ASSERT_NE(alice_state, 0) << "Alice call state is 0 (not connected?)";

    // Send Audio
    std::vector<int16_t> pcm(960 * 1);
    fill_audio_frame(48000, 1, 0, 960, pcm);  // 20ms frame
    Toxav_Err_Send_Frame send_err;
    res = toxav_audio_send_frame(alice, 0, pcm.data(), 960, 1, 48000, &send_err);
    ASSERT_TRUE(res) << "toxav_audio_send_frame failed with error: " << send_err;

    // Process packets
    step();

    ASSERT_GT(bob_audio_frames, 0);

    // Send Video
    std::vector<uint8_t> y, u, v;
    fill_video_frame(640, 480, 0, y, u, v);
    res = toxav_video_send_frame(alice, 0, 640, 480, y.data(), u.data(), v.data(), &send_err);
    ASSERT_TRUE(res);
    ASSERT_EQ(send_err, TOXAV_ERR_SEND_FRAME_OK);

    // Process packets
    step();

    ASSERT_GT(bob_video_frames, 0);

    // Hangup
    Toxav_Err_Call_Control cc_err;
    toxav_call_control(alice, 0, TOXAV_CALL_CONTROL_CANCEL, &cc_err);
    ASSERT_EQ(cc_err, TOXAV_ERR_CALL_CONTROL_OK);

    step();

    ASSERT_EQ(bob_state, TOXAV_FRIEND_CALL_STATE_FINISHED);
}

TEST_F(ToxAvTest, BidirectionalCall)
{
    Toxav_Err_Call call_err;
    ASSERT_TRUE(toxav_call(alice, 0, 48, 1000, &call_err));
    ASSERT_EQ(call_err, TOXAV_ERR_CALL_OK);

    step();

    ASSERT_TRUE(bob_invited);

    Toxav_Err_Answer answer_err;
    ASSERT_TRUE(toxav_answer(bob, 0, 48, 1000, &answer_err));
    ASSERT_EQ(answer_err, TOXAV_ERR_ANSWER_OK);

    step();

    // Process potentially queued state changes
    step();

    ASSERT_NE(alice_state, 0);

    // Alice -> Bob Audio
    std::vector<int16_t> pcm(960 * 1);
    fill_audio_frame(48000, 1, 0, 960, pcm);
    Toxav_Err_Send_Frame send_err;
    ASSERT_TRUE(toxav_audio_send_frame(alice, 0, pcm.data(), 960, 1, 48000, &send_err));

    // Bob -> Alice Audio
    ASSERT_TRUE(toxav_audio_send_frame(bob, 0, pcm.data(), 960, 1, 48000, &send_err));

    step();

    ASSERT_GT(bob_audio_frames, 0);
    ASSERT_GT(alice_audio_frames, 0);

    // Alice -> Bob Video
    std::vector<uint8_t> y, u, v;
    fill_video_frame(640, 480, 0, y, u, v);
    ASSERT_TRUE(
        toxav_video_send_frame(alice, 0, 640, 480, y.data(), u.data(), v.data(), &send_err));

    // Bob -> Alice Video
    ASSERT_TRUE(toxav_video_send_frame(bob, 0, 640, 480, y.data(), u.data(), v.data(), &send_err));

    step();

    ASSERT_GT(bob_video_frames, 0);
    ASSERT_GT(alice_video_frames, 0);
}

TEST_F(ToxAvTest, BobMutesAlice)
{
    Toxav_Err_Call call_err;
    ASSERT_TRUE(toxav_call(alice, 0, 48, 1000, &call_err));
    step();

    Toxav_Err_Answer answer_err;
    ASSERT_TRUE(toxav_answer(bob, 0, 48, 1000, &answer_err));
    step();

    // Extra process for state
    step();

    // Initial Send
    std::vector<int16_t> pcm(960 * 1);
    fill_audio_frame(48000, 1, 0, 960, pcm);
    Toxav_Err_Send_Frame send_err;
    ASSERT_TRUE(toxav_audio_send_frame(alice, 0, pcm.data(), 960, 1, 48000, &send_err));

    step();

    ASSERT_EQ(bob_audio_frames, 1);

    // Bob Mutes Alice
    Toxav_Err_Call_Control cc_err;
    ASSERT_TRUE(toxav_call_control(bob, 0, TOXAV_CALL_CONTROL_MUTE_AUDIO, &cc_err));
    ASSERT_EQ(cc_err, TOXAV_ERR_CALL_CONTROL_OK);

    step();

    // Alice sends again
    bool res = toxav_audio_send_frame(alice, 0, pcm.data(), 960, 1, 48000, &send_err);
    if (!res) {
        ASSERT_EQ(send_err, TOXAV_ERR_SEND_FRAME_PAYLOAD_TYPE_DISABLED);
    } else {
        step();

        // Should still be 1
        ASSERT_EQ(bob_audio_frames, 1);
    }
}

/**
 * Clients iterate as often as toxav_iteration_interval says, which is about
 * once a second when nothing comes in, so frames can't wait for an iterate.
 */
TEST_F(ToxAvTest, FramesAreSentByTheFrameSend)
{
    Toxav_Err_Call call_err;
    ASSERT_TRUE(toxav_call(alice, 0, 48, 1000, &call_err));
    step();
    Toxav_Err_Answer answer_err;
    ASSERT_TRUE(toxav_answer(bob, 0, 0, 0, &answer_err));  // Bob only listens.
    step();
    step();

    std::vector<int16_t> pcm(960);
    fill_audio_frame(48000, 1, 0, 960, pcm);
    std::vector<uint8_t> y, u, v;
    fill_video_frame(640, 480, 0, y, u, v);
    Toxav_Err_Send_Frame send_err;
    size_t before = network.pending();
    ASSERT_TRUE(toxav_audio_send_frame(alice, 0, pcm.data(), 960, 1, 48000, &send_err));
    EXPECT_GT(network.pending(), before);
    before = network.pending();
    ASSERT_TRUE(
        toxav_video_send_frame(alice, 0, 640, 480, y.data(), u.data(), v.data(), &send_err));
    EXPECT_GT(network.pending(), before);
}

TEST_F(ToxAvTest, CallToAFriendNotConnectedFails)
{
    alice_peer.connected.erase(0);

    Toxav_Err_Call call_err;
    EXPECT_FALSE(toxav_call(alice, 0, 48, 0, &call_err));
    EXPECT_EQ(call_err, TOXAV_ERR_CALL_FRIEND_NOT_CONNECTED);
}

TEST_F(ToxAvTest, CallEndsWhenTheFriendDisconnects)
{
    Toxav_Err_Call call_err;
    ASSERT_TRUE(toxav_call(alice, 0, 48, 0, &call_err));
    step();
    Toxav_Err_Answer answer_err;
    ASSERT_TRUE(toxav_answer(bob, 0, 48, 0, &answer_err));
    step();

    alice_peer.connected.erase(0);
    toxav_iterate(alice);
    EXPECT_EQ(alice_state, TOXAV_FRIEND_CALL_STATE_ERROR);
}

TEST_F(ToxAvTest, AnyFriendNumberWorks)
{
    const uint32_t friend_number = UINT32_MAX - 1;
    alice_peer.connected.insert(friend_number);

    Toxav_Err_Call call_err;
    EXPECT_TRUE(toxav_call(alice, friend_number, 48, 0, &call_err));
    EXPECT_EQ(call_err, TOXAV_ERR_CALL_OK);
}

}  // namespace
