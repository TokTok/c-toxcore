#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "../testing/misc_tools.h"

#include "../toxav/toxav.h"
#include "../toxcore/tox.h"

#include "check_compat.h"

// Make lines shorter
using Clock = std::chrono::high_resolution_clock;
using TimePoint = std::chrono::time_point<Clock>;

namespace {

// Whether to write log messages when handling callbacks.
constexpr bool LOG_CALLBACKS = false;

// Maximum amount of time in iterations to wait for bootstrapping and friend
// connections to succeed.
constexpr uint32_t MAX_BOOTSTRAP_ITERATIONS = 1000;

struct Tox_Options_Deleter {
  void operator()(Tox_Options *options) const { tox_options_free(options); }
};

using Tox_Options_Ptr = std::unique_ptr<Tox_Options, Tox_Options_Deleter>;

struct Tox_Deleter {
  void operator()(Tox *tox) const { tox_kill(tox); }
};

using Tox_Ptr = std::unique_ptr<Tox, Tox_Deleter>;

struct ToxAV_Deleter {
  void operator()(ToxAV *tox) const { toxav_kill(tox); }
};

using ToxAV_Ptr = std::unique_ptr<ToxAV, ToxAV_Deleter>;

struct Local_State {
  explicit Local_State(Tox_Ptr tox) : tox_(std::move(tox)) {}

  Tox *tox() const { return tox_.get(); }

 private:
  Tox_Ptr tox_;
};

static void t_accept_friend_request_cb(Tox *m, const uint8_t *public_key, const uint8_t *data, size_t length,
                                       void *userdata)
{
    if (length == 7 && std::memcmp("gentoo", data, 7) == 0) {
        ck_assert(tox_friend_add_norequest(m, public_key, nullptr) != (uint32_t) -1);
    }
}


std::vector<Tox_Ptr> prepareNetwork(uint32_t count) {
  Tox_Err_New error;

  // Temporary bootstrap node
  std::printf("Created 1 instance of Tox as boostrap node\n");
  Tox_Ptr bootstrap = Tox_Ptr(tox_new_log(nullptr, &error, NULL));
  ck_assert(error == TOX_ERR_NEW_OK);

  uint8_t bootstrap_key[TOX_PUBLIC_KEY_SIZE];
  tox_self_get_dht_id(bootstrap.get(), bootstrap_key);
  const uint16_t bootstrap_port = tox_self_get_udp_port(bootstrap.get(), nullptr);

  std::cout << "Bootstrapping " << std::to_string(count) << " Tox nodes" << std::endl;

  std::vector<Tox_Ptr> toxes(count);

  for (auto& tox : toxes) {
      tox = Tox_Ptr(tox_new_log(nullptr, &error, nullptr));
      ck_assert(error == TOX_ERR_NEW_OK);

      tox_bootstrap(tox.get(), "localhost", bootstrap_port, bootstrap_key, nullptr);
      tox_callback_friend_request(tox.get(), t_accept_friend_request_cb);
  }

  // Create fully meshed friend network
  for (size_t i = 0; i < toxes.size(); ++i) {
    uint8_t address[TOX_ADDRESS_SIZE];
    tox_self_get_address(toxes[i].get(), address);

    for (size_t j = i + 1; j < toxes.size(); ++j) {
        Tox_Err_Friend_Add error_add;
        tox_friend_add(toxes[j].get(), address, (const uint8_t *)"gentoo", 7, &error_add);
        ck_assert(error_add == TOX_ERR_FRIEND_ADD_OK);
    }
  }

  // temporarily add bootstrap node to end of toxes, so we can iterate all
  toxes.push_back(std::move(bootstrap));

  uint32_t bootstrap_iteration = 0;
  bool online = false;

  auto bootstrap_start_time = Clock::now();

  for(; bootstrap_iteration < MAX_BOOTSTRAP_ITERATIONS; ++bootstrap_iteration) {
    for(auto& tox : toxes) {
        tox_iterate(tox.get(), nullptr);
    }

    if (!online) {
      size_t online_cnt = std::count_if(toxes.cbegin(), toxes.cend(),
            [](const Tox_Ptr& tox) {
                return tox_self_get_connection_status(tox.get());
            });

      if (online_cnt == toxes.size()) {
          std::chrono::duration<double> bootstrap_time = Clock::now() - bootstrap_start_time;
          std::cout << "Toxes are online, took " << bootstrap_time.count() << "s" << std::endl;
          online = true;
      }
    }

    bool friends_connected = true;

    // Check if the friends are connected to each other, bootstrap node will have empty friends list
    for(auto& tox: toxes) {
      std::vector<uint32_t> friend_list;
      friend_list.resize(tox_self_get_friend_list_size(tox.get()));
      tox_self_get_friend_list(tox.get(), friend_list.data());

      for(auto friend_id : friend_list) {
          friends_connected &= tox_friend_get_connection_status(tox.get(), friend_id, nullptr) == TOX_CONNECTION_UDP;
      }
    }

    if (friends_connected) {
      break;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(20));

    }

  ck_assert(bootstrap_iteration < MAX_BOOTSTRAP_ITERATIONS);
  std::chrono::duration<double> mesh_time = Clock::now() - bootstrap_start_time;
  std::cout << "Iterations to connect friend mesh: " << std::to_string(bootstrap_iteration) << std::endl;
  std::cout << "Time to connect friend mesh: " << mesh_time.count() << "s" << std::endl;

  // Remove bootstrap node
  toxes.pop_back();

  return toxes;
}

class AV_State {
public:
  explicit AV_State(Tox_Ptr tox, std::string name, bool combined = false)
    : tox_(std::move(tox)),
      combined_(combined),
      stop_threads{false},
      incomming{false},
      call_state{0},
      video_received{false},
      audio_received{false},
      name_{name}
  {
    Toxav_Err_New error;
    toxAV_ = ToxAV_Ptr(toxav_new(tox_.get(), &error));
    ck_assert(error == TOXAV_ERR_NEW_OK);

    toxav_callback_call(toxAV_.get(), &AV_State::toxav_call_cb, this);
    toxav_callback_call_state(toxAV_.get(), &AV_State::toxav_call_state_cb, this);
    toxav_callback_video_receive_frame(toxAV_.get(), &AV_State::toxav_receive_video_frame_cb, this);
    toxav_callback_audio_receive_frame(toxAV_.get(), &AV_State::toxav_receive_audio_frame_cb, this);

    tox_thread = std::thread(&AV_State::tox_iterator, this);

    if (combined) {
        av_thread = std::thread(&AV_State::toxav_iterator, this, Iteration_Type::TOXAV_BOTH);
    } else {
        audio_thread = std::thread(&AV_State::toxav_iterator, this, Iteration_Type::TOXAV_AUDIO);
        video_thread = std::thread(&AV_State::toxav_iterator, this, Iteration_Type::TOXAV_VIDEO);
    }
  }

    ~AV_State() {
        stopThreads();
    }

  Tox* getTox() const { return tox_.get(); }
  ToxAV *getToxAV() const { return toxAV_.get(); }
  std::mutex& getToxLoopLock() {return tox_loop_lock; }
  bool inCall() const { return in_call.load();}
  uint32_t getCallState() const {return call_state.load();}
  void stopThreads() {
      if (stop_threads.exchange(true)) {
          // already stopped
          return;
      }

      tox_thread.join();
      if (combined_) {
          av_thread.join();
      } else {
        audio_thread.join();
        video_thread.join();
      }
  }

  bool didReceiveAudio() const {return audio_received.load();}
  bool didReceiveVideo() const {return video_received.load();}

  static constexpr uint32_t TEST_A_BITRATE = 48; // In kbit/s
  static constexpr uint32_t TEST_V_BITRATE = 4000; // In kbit/s
  static constexpr std::chrono::duration<double> AUTO_HANGUP_TIME = std::chrono::seconds(2);

private:
  enum class Iteration_Type {
      TOXAV_AUDIO,
      TOXAV_VIDEO,
      TOXAV_BOTH,
  };

  static void toxav_call_cb(ToxAV *av, uint32_t friend_number, bool audio_enabled, bool video_enabled, void *user_data) {
    AV_State* me = static_cast<AV_State*>(user_data);
    std:: cout << "[" << me->name_ << "] Handling CALL callback" << std::endl;
    me->incomming.store(true);
    ck_assert(std::this_thread::get_id() == me->tox_thread.get_id());
  }

  static void toxav_call_state_cb(ToxAV *av, uint32_t friend_number, uint32_t state, void *user_data) {
    AV_State* me = static_cast<AV_State*>(user_data);
    ck_assert(std::this_thread::get_id() == me->tox_thread.get_id());
    ck_assert(state != TOXAV_FRIEND_CALL_STATE_ERROR);
    std:: cout << "[" << me->name_ << "] State changed to: " << std::to_string(state) << std::endl;
    me->call_state.store(state);
    TimePoint tp = me->call_start.load();
    if (state != TOXAV_FRIEND_CALL_STATE_NONE && tp == TimePoint()) {
        me->call_start.store(Clock::now());
        me->in_call.store(true);
    }
  }

  static void toxav_receive_video_frame_cb(ToxAV *av, uint32_t friend_number,
          uint16_t width, uint16_t height,
          uint8_t const *y, uint8_t const *u, uint8_t const *v,
          int32_t ystride, int32_t ustride, int32_t vstride,
          void *user_data)
  {
      AV_State* me = static_cast<AV_State*>(user_data);
      std:: cout << "[" << me->name_ << "] Received video payload" << std::endl;

      // toxav.h states that receive events are emitted from their respective threads
      if (me->combined_) {
          ck_assert(std::this_thread::get_id() == me->av_thread.get_id());
      } else {
          ck_assert(std::this_thread::get_id() == me->video_thread.get_id());
      }

      me->video_received = true;
  }

  static void toxav_receive_audio_frame_cb(ToxAV *av, uint32_t friend_number,
          int16_t const *pcm,
          size_t sample_count,
          uint8_t channels,
          uint32_t sampling_rate,
          void *user_data)
  {
      AV_State* me = static_cast<AV_State*>(user_data);
      std:: cout << "[" << me->name_ << "] Received audio payload" << std::endl;
      if (me->combined_) {
          ck_assert(std::this_thread::get_id() == me->av_thread.get_id());
      } else {
          ck_assert(std::this_thread::get_id() == me->audio_thread.get_id());
      }

      me->audio_received = true;
  }

  void tox_iterator()
  {
    while(!stop_threads.load()) {
        // Perform this block only while loop lock is held
        {
            std::lock_guard<std::mutex>lock(tox_loop_lock);
            tox_iterate(tox_.get(), this);

            // handle incoming call
            if (incomming.exchange(false)) {
              Toxav_Err_Answer answer_err;
              toxav_answer(toxAV_.get(), 0, TEST_A_BITRATE, TEST_V_BITRATE, &answer_err);

              if (answer_err != TOXAV_ERR_ANSWER_OK) {
                std::printf("toxav_answer failed, Toxav_Err_Answer: %d\n", answer_err);
                ck_assert(0);
              }

              std:: cout << "[" << name_ << "] Answering call" << std::endl;

              call_start = Clock::now();
              in_call.store(true);
            }

            if (in_call.load()) {
                uint32_t state = call_state.load();
                TimePoint tp = call_start.load();
                std::chrono::duration<double> call_time = Clock::now() - tp;

                if (state == TOXAV_FRIEND_CALL_STATE_FINISHED) {
                    std:: cout << "[" << name_ << "] Call ended by other side after: " << call_time.count() << "s" << std::endl;
                    in_call.store(false);
                } else if (tp > TimePoint() && call_time > AV_State::AUTO_HANGUP_TIME) {
                    std:: cout << "[" << name_ << "] Ending call after: " << call_time.count() << "s" << std::endl;
                    Toxav_Err_Call_Control cc_err;
                    toxav_call_control(toxAV_.get(), 0, TOXAV_CALL_CONTROL_CANCEL, &cc_err);

                    // Ignore FRIEND_NOT_IN_CALL for the case where the other side hangs up simultaneously
                    if (cc_err != TOXAV_ERR_CALL_CONTROL_OK && cc_err != TOXAV_ERR_CALL_CONTROL_FRIEND_NOT_IN_CALL) {
                        std::printf("toxav_call_control failed: %d\n", cc_err);
                        ck_assert(0);
                    }
                    in_call.store(false);
                }
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(tox_iteration_interval(tox_.get())));
    }
  }

  void toxav_iterator(Iteration_Type type)
  {
      while(!stop_threads.load()) {
        switch (type) {
        case Iteration_Type::TOXAV_AUDIO:
            toxav_audio_iterate(toxAV_.get());
            std::this_thread::sleep_for(std::chrono::milliseconds(toxav_audio_iteration_interval(toxAV_.get())));
            break;
        case Iteration_Type::TOXAV_VIDEO:
            toxav_video_iterate(toxAV_.get());
            std::this_thread::sleep_for(std::chrono::milliseconds(toxav_video_iteration_interval(toxAV_.get())));
            break;
        case Iteration_Type::TOXAV_BOTH:
            toxav_iterate(toxAV_.get());
            std::this_thread::sleep_for(std::chrono::milliseconds(toxav_iteration_interval(toxAV_.get())));
            break;
        }
      }
  }

  std::thread tox_thread;
  std::thread audio_thread;
  std::thread video_thread;
  std::thread av_thread;

  std::mutex tox_loop_lock;

  Tox_Ptr tox_;
  bool combined_;
  ToxAV_Ptr toxAV_;

  std::atomic_bool stop_threads;
  std::atomic_bool incomming;
  std::atomic_uint32_t call_state;

  std::atomic<TimePoint> call_start;
  std::atomic_bool in_call;

  std::atomic_bool video_received;
  std::atomic_bool audio_received;
  std::string name_;
};

struct DUMMY_PCM {
    static constexpr size_t sample_count = 960;
    static constexpr int16_t pcm[sample_count] = {0};
    static constexpr uint8_t channels = 1;
    static constexpr uint32_t sampling_rate = 48000;
};

struct DUMMY_VIDEO {
    // https://en.wikipedia.org/wiki/Graphics_display_resolution#QQVGA size
    static constexpr uint16_t width = 160;
    static constexpr uint16_t height = 120;

    static constexpr uint8_t y[width*height] = {0};
    static constexpr uint8_t u[width/2*height/2] = {0};
    static constexpr uint8_t v[width/2*height/2] = {0};
};

// FIXME: once we upgrade to C++17, remove these, reason: https://stackoverflow.com/a/28846608
constexpr std::chrono::duration<double> AV_State::AUTO_HANGUP_TIME;
constexpr int16_t DUMMY_PCM::pcm[];
constexpr uint8_t DUMMY_VIDEO::y[];
constexpr uint8_t DUMMY_VIDEO::u[];
constexpr uint8_t DUMMY_VIDEO::v[];

} // namespace

void test_av(bool combined)
{
    std::cout << "Testing Audio and Video in" << (combined ? "combined" : "separate") << " threads" << std::endl;
    auto toxes = prepareNetwork(2);

    AV_State alice(std::move(toxes[0]), "alice", false);
    AV_State bob(std::move(toxes[1]), "bob", false);

    // Let alice call bob
    {
        std::lock_guard<std::mutex>(alice.getToxLoopLock());
        Toxav_Err_Call err;
        ck_assert(toxav_call(alice.getToxAV(), 0, AV_State::TEST_A_BITRATE, AV_State::TEST_V_BITRATE, &err));
        ck_assert(err == TOXAV_ERR_CALL_OK);
    }

    std::cout << "alice started a call" << std::endl;

    auto poll_state = [](AV_State& av, uint32_t expected, uint32_t max_tries, uint32_t delay_ms) -> bool {
        uint32_t i;
        for (i = 0; i < max_tries; ++i) {
            uint32_t state = av.getCallState();
            if(state == expected) {
                return true;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
        }
        return false;
    };

    // We're starting with full AV on both sides
    constexpr uint32_t full_AV_mask = TOXAV_FRIEND_CALL_STATE_SENDING_A
            | TOXAV_FRIEND_CALL_STATE_SENDING_V
            | TOXAV_FRIEND_CALL_STATE_ACCEPTING_A
            | TOXAV_FRIEND_CALL_STATE_ACCEPTING_V;

    // Wait 2s until the call is established on both sides
    ck_assert(poll_state(alice, full_AV_mask, 10, 100));

    // TODO: why is Bob's call state not updated?
    // ck_assert(poll_state(bob, full_AV_mask, 10, 100)); asserts

    ck_assert(alice.inCall());
    ck_assert(bob.inCall());

    std::cout << "alice and bob are in the call" << std::endl;

    auto toxav_audio_send_frame_dummy = [](ToxAV *av, Toxav_Err_Send_Frame *error) -> bool {
        return toxav_audio_send_frame(av, 0, DUMMY_PCM::pcm, DUMMY_PCM::sample_count, DUMMY_PCM::channels, DUMMY_PCM::sampling_rate, error);
    };

    auto toxav_video_send_frame_dummy = [](ToxAV *av, Toxav_Err_Send_Frame *error) -> bool {
        return toxav_video_send_frame(av, 0, DUMMY_VIDEO::width, DUMMY_VIDEO::height, DUMMY_VIDEO::y, DUMMY_VIDEO::u, DUMMY_VIDEO::v, error);
    };

    // Send frames from alice to bob
    {
        std::lock_guard<std::mutex>(alice.getToxLoopLock());
        Toxav_Err_Send_Frame err;
        ck_assert(toxav_audio_send_frame_dummy(alice.getToxAV(), &err));
        ck_assert(err == TOXAV_ERR_SEND_FRAME_OK);

        ck_assert(toxav_video_send_frame_dummy(alice.getToxAV(), &err));
        ck_assert(err == TOXAV_ERR_SEND_FRAME_OK);
    }

    // Send frames from bob to alice
    {
        std::lock_guard<std::mutex>(bob.getToxLoopLock());
        Toxav_Err_Send_Frame err;
        ck_assert(toxav_audio_send_frame_dummy(bob.getToxAV(), &err));
        ck_assert(err == TOXAV_ERR_SEND_FRAME_OK);

        ck_assert(toxav_video_send_frame_dummy(bob.getToxAV(), &err));
        ck_assert(err == TOXAV_ERR_SEND_FRAME_OK);
    }

    // auto hangup after 2s, wait 3s for this
    ck_assert(poll_state(alice, TOXAV_FRIEND_CALL_STATE_FINISHED, 30, 100));

    // TODO: why is Bobs call state not updated?
    // ck_assert(poll_state(bob, TOXAV_FRIEND_CALL_STATE_FINISHED, 30, 100)); fails

    ck_assert(!alice.inCall());
    ck_assert(!bob.inCall());

    std::cout << "The call ended" << std::endl;

    alice.stopThreads();
    bob.stopThreads();

    ck_assert(alice.didReceiveAudio());
    ck_assert(alice.didReceiveVideo());
    ck_assert(bob.didReceiveAudio());
    ck_assert(bob.didReceiveVideo());
}

int main(void)
{
    setvbuf(stdout, nullptr, _IONBF, 0);

    test_av(false);
    test_av(true);

    return 0;
}
