// clang-format off
#include "../testing/support/public/simulated_environment.hh"
#include "tox.h"
// clang-format on

#include <gtest/gtest.h>

#include <array>
#include <vector>

#include "Messenger.h"
#include "attributes.h"
#include "crypto_core.h"
#include "group.h"
#include "tox_log_level.h"
#include "tox_options.h"
#include "tox_private.h"
#include "tox_struct.h"

namespace {

using tox::test::SimulatedEnvironment;

static void set_random_name_and_status_message(Tox *_Nonnull tox, const Random *_Nonnull rng,
    std::uint8_t *_Nonnull name, std::uint8_t *_Nonnull status_message)
{
    for (std::uint16_t i = 0; i < tox_max_name_length(); ++i) {
        name[i] = random_u08(rng);
    }

    for (std::uint16_t i = 0; i < tox_max_status_message_length(); ++i) {
        status_message[i] = random_u08(rng);
    }
}

TEST(Tox, CurrentVersionIsCompatibleWithItself)
{
    EXPECT_TRUE(
        TOX_VERSION_IS_API_COMPATIBLE(TOX_VERSION_MAJOR, TOX_VERSION_MINOR, TOX_VERSION_PATCH));
    EXPECT_TRUE(TOX_VERSION_IS_ABI_COMPATIBLE());
    EXPECT_TRUE(
        tox_version_is_compatible(tox_version_major(), tox_version_minor(), tox_version_patch()));
}

TEST(Tox, ConstantsAreNonZero)
{
    EXPECT_GT(tox_public_key_size(), 0);
    EXPECT_GT(tox_secret_key_size(), 0);
    EXPECT_GT(tox_conference_id_size(), 0);
    EXPECT_GT(tox_nospam_size(), 0);
    EXPECT_GT(tox_address_size(), 0);
    EXPECT_GT(tox_max_name_length(), 0);
    EXPECT_GT(tox_max_status_message_length(), 0);
    EXPECT_GT(tox_max_friend_request_length(), 0);
    EXPECT_GT(tox_max_message_length(), 0);
    EXPECT_GT(tox_max_custom_packet_size(), 0);
    EXPECT_GT(tox_hash_length(), 0);
    EXPECT_GT(tox_file_id_length(), 0);
    EXPECT_GT(tox_max_filename_length(), 0);
    EXPECT_GT(tox_max_hostname_length(), 0);
    EXPECT_GT(tox_group_max_topic_length(), 0);
    EXPECT_GT(tox_group_max_part_length(), 0);
    EXPECT_GT(tox_group_max_message_length(), 0);
    EXPECT_GT(tox_group_max_custom_lossy_packet_length(), 0);
    EXPECT_GT(tox_group_max_custom_lossless_packet_length(), 0);
    EXPECT_GT(tox_group_max_group_name_length(), 0);
    EXPECT_GT(tox_group_max_password_size(), 0);
    EXPECT_GT(tox_group_chat_id_size(), 0);
    EXPECT_GT(tox_group_peer_public_key_size(), 0);
    EXPECT_GT(tox_dht_node_ip_string_size(), 0);
    EXPECT_GT(tox_dht_node_public_key_size(), 0);
    EXPECT_GT(tox_group_secret_key_size(), 0);
}

TEST(Tox, BootstrapErrorCodes)
{
    Tox *tox = tox_new(nullptr, nullptr);
    ASSERT_NE(tox, nullptr);

    Tox_Err_Bootstrap err;
    std::array<std::uint8_t, TOX_PUBLIC_KEY_SIZE> pk;
    tox_bootstrap(tox, "127.0.0.1", 0, pk.data(), &err);
    EXPECT_EQ(err, TOX_ERR_BOOTSTRAP_BAD_PORT);

    tox_kill(tox);
}

// A conference lossy packet too long to send is rejected before it is put
// together.
TEST(Tox, ConferenceLossyPacketTooLongIsRejected)
{
    SimulatedEnvironment env{12345};
    struct Tox_Options *options = tox_options_new(nullptr);
    ASSERT_NE(options, nullptr);
    auto node = env.create_node(33545);
    Tox_Options_Testing testing_opts = {};
    testing_opts.operating_system = &node->system;
    Tox *tox = tox_new_testing(options, nullptr, &testing_opts, nullptr);
    tox_options_free(options);
    ASSERT_NE(tox, nullptr);

    Tox_Err_Conference_New err;
    const std::uint32_t conference = tox_conference_new(tox, &err);
    ASSERT_EQ(err, TOX_ERR_CONFERENCE_NEW_OK);

    const std::vector<std::uint8_t> data(UINT16_MAX);
    EXPECT_EQ(
        send_group_lossy_packet(tox->m->conferences_object, conference, data.data(), UINT16_MAX),
        -1);

    tox_kill(tox);
}

TEST(Tox, GroupComesBackFromItsKeysAndState)
{
    SimulatedEnvironment env{12345};
    struct Tox_Options *options = tox_options_new(nullptr);
    ASSERT_NE(options, nullptr);
    auto node = env.create_node(33545);
    auto other_node = env.create_node(33546);
    auto third_node = env.create_node(33547);
    Tox_Options_Testing testing_opts = {};
    testing_opts.operating_system = &node->system;
    Tox *tox = tox_new_testing(options, nullptr, &testing_opts, nullptr);
    testing_opts.operating_system = &other_node->system;
    Tox *other = tox_new_testing(options, nullptr, &testing_opts, nullptr);
    testing_opts.operating_system = &third_node->system;
    Tox *third = tox_new_testing(options, nullptr, &testing_opts, nullptr);
    tox_options_free(options);
    ASSERT_NE(tox, nullptr);
    ASSERT_NE(other, nullptr);
    ASSERT_NE(third, nullptr);

    const std::array<std::uint8_t, 3> name{'L', 'a', 'b'};
    const std::array<std::uint8_t, 2> nick{'M', 'e'};
    const std::array<std::uint8_t, 4> password{'p', 'a', 's', 's'};
    const std::array<std::uint8_t, 5> topic{'t', 'o', 'p', 'i', 'c'};
    const std::uint32_t group = tox_group_new(tox, TOX_GROUP_PRIVACY_STATE_PRIVATE, name.data(),
        name.size(), nick.data(), nick.size(), nullptr);
    ASSERT_NE(group, UINT32_MAX);
    ASSERT_TRUE(tox_group_set_password(tox, group, password.data(), password.size(), nullptr));
    ASSERT_TRUE(tox_group_set_peer_limit(tox, group, 7, nullptr));
    ASSERT_TRUE(tox_group_set_topic(tox, group, topic.data(), topic.size(), nullptr));

    std::array<std::uint8_t, TOX_GROUP_CHAT_ID_SIZE> chat_id{};
    ASSERT_TRUE(tox_group_get_chat_id(tox, group, chat_id.data(), nullptr));
    std::array<std::uint8_t, TOX_GROUP_SECRET_KEY_SIZE> self_key{};
    ASSERT_TRUE(tox_group_self_get_secret_key(tox, group, self_key.data(), nullptr));
    std::array<std::uint8_t, TOX_GROUP_SECRET_KEY_SIZE> chat_key{};
    ASSERT_TRUE(tox_group_get_chat_secret_key(tox, group, chat_key.data(), nullptr));

    Tox_Group_State *state = tox_group_get_state(tox, group, nullptr);
    ASSERT_NE(state, nullptr);
    std::vector<std::uint8_t> bytes(tox_group_state_bytes_size(state));
    ASSERT_FALSE(bytes.empty());
    ASSERT_TRUE(tox_group_state_get_bytes(state, bytes.data()));
    tox_group_state_free(state);

    // A modified state fails the signature check.
    Tox_Err_Group_State_Load err_load;
    std::vector<std::uint8_t> forged = bytes;
    forged[forged.size() / 2] ^= 1;
    EXPECT_EQ(
        tox_group_state_load(&node->system, forged.data(), forged.size(), &err_load), nullptr);
    EXPECT_EQ(err_load, TOX_ERR_GROUP_STATE_LOAD_BAD_STATE);
    EXPECT_EQ(
        tox_group_state_load(&node->system, bytes.data(), bytes.size() / 2, &err_load), nullptr);
    EXPECT_EQ(err_load, TOX_ERR_GROUP_STATE_LOAD_BAD_STATE);

    // The loaded state has the same values as the group.
    state = tox_group_state_load(&node->system, bytes.data(), bytes.size(), &err_load);
    ASSERT_EQ(err_load, TOX_ERR_GROUP_STATE_LOAD_OK);
    ASSERT_NE(state, nullptr);

    std::array<std::uint8_t, TOX_GROUP_CHAT_ID_SIZE> state_chat_id{};
    tox_group_state_get_chat_id(state, state_chat_id.data());
    EXPECT_EQ(state_chat_id, chat_id);
    std::array<std::uint8_t, 3> state_name{};
    ASSERT_EQ(tox_group_state_get_name_size(state), name.size());
    tox_group_state_get_name(state, state_name.data());
    EXPECT_EQ(state_name, name);
    std::array<std::uint8_t, 4> state_password{};
    ASSERT_EQ(tox_group_state_get_password_size(state), password.size());
    tox_group_state_get_password(state, state_password.data());
    EXPECT_EQ(state_password, password);
    std::array<std::uint8_t, 5> state_topic{};
    ASSERT_EQ(tox_group_state_get_topic_size(state), topic.size());
    tox_group_state_get_topic(state, state_topic.data());
    EXPECT_EQ(state_topic, topic);
    EXPECT_EQ(tox_group_state_get_privacy_state(state), TOX_GROUP_PRIVACY_STATE_PRIVATE);
    EXPECT_EQ(tox_group_state_get_peer_limit(state), 7);
    EXPECT_EQ(tox_group_state_get_topic_lock(state), tox_group_get_topic_lock(tox, group, nullptr));
    EXPECT_EQ(
        tox_group_state_get_voice_state(state), tox_group_get_voice_state(tox, group, nullptr));

    // We can't join a group we are already in.
    Tox_Err_Group_Join_As err;
    tox_group_join_as(tox, chat_id.data(), TOX_GROUP_PRIVACY_STATE_PRIVATE, self_key.data(),
        nullptr, nick.data(), nick.size(), nullptr, 0, state, &err);
    EXPECT_EQ(err, TOX_ERR_GROUP_JOIN_AS_DUPLICATE);

    std::array<std::uint8_t, TOX_GROUP_CHAT_ID_SIZE> other_chat_id = chat_id;
    other_chat_id[0] ^= 1;
    tox_group_join_as(other, other_chat_id.data(), TOX_GROUP_PRIVACY_STATE_PRIVATE, self_key.data(),
        nullptr, nick.data(), nick.size(), nullptr, 0, state, &err);
    EXPECT_EQ(err, TOX_ERR_GROUP_JOIN_AS_BAD_STATE);

    std::array<std::uint8_t, TOX_GROUP_SECRET_KEY_SIZE> wrong_key = chat_key;
    wrong_key[0] ^= 1;
    tox_group_join_as(other, chat_id.data(), TOX_GROUP_PRIVACY_STATE_PRIVATE, self_key.data(),
        wrong_key.data(), nick.data(), nick.size(), nullptr, 0, state, &err);
    EXPECT_EQ(err, TOX_ERR_GROUP_JOIN_AS_BAD_CHAT_SECRET_KEY);

    // With a state, the settings are available immediately, and the privacy_state argument is
    // ignored.
    const std::uint32_t restored
        = tox_group_join_as(other, chat_id.data(), TOX_GROUP_PRIVACY_STATE_PUBLIC, self_key.data(),
            chat_key.data(), nick.data(), nick.size(), nullptr, 0, state, &err);
    ASSERT_EQ(err, TOX_ERR_GROUP_JOIN_AS_OK);
    EXPECT_EQ(tox_group_get_group_list_size(other), 1);
    EXPECT_EQ(
        tox_group_get_privacy_state(other, restored, nullptr), TOX_GROUP_PRIVACY_STATE_PRIVATE);
    EXPECT_EQ(tox_group_self_get_role(other, restored, nullptr), TOX_GROUP_ROLE_FOUNDER);

    std::array<std::uint8_t, 4> restored_password{};
    ASSERT_EQ(tox_group_get_password_size(other, restored, nullptr), password.size());
    ASSERT_TRUE(tox_group_get_password(other, restored, restored_password.data(), nullptr));
    EXPECT_EQ(restored_password, password);

    // The state of the restored group is identical to the original.
    Tox_Group_State *again = tox_group_get_state(other, restored, nullptr);
    ASSERT_NE(again, nullptr);
    std::vector<std::uint8_t> again_bytes(tox_group_state_bytes_size(again));
    ASSERT_TRUE(tox_group_state_get_bytes(again, again_bytes.data()));
    EXPECT_EQ(again_bytes, bytes);
    tox_group_state_free(again);

    // Without a state, we join as the same peer and have no settings yet.
    const std::uint32_t keys_only
        = tox_group_join_as(third, chat_id.data(), TOX_GROUP_PRIVACY_STATE_PRIVATE, self_key.data(),
            nullptr, nick.data(), nick.size(), password.data(), password.size(), nullptr, &err);
    ASSERT_EQ(err, TOX_ERR_GROUP_JOIN_AS_OK);
    std::array<std::uint8_t, TOX_GROUP_PEER_PUBLIC_KEY_SIZE> self_pk{};
    std::array<std::uint8_t, TOX_GROUP_PEER_PUBLIC_KEY_SIZE> keys_only_pk{};
    ASSERT_TRUE(tox_group_self_get_public_key(tox, group, self_pk.data(), nullptr));
    ASSERT_TRUE(tox_group_self_get_public_key(third, keys_only, keys_only_pk.data(), nullptr));
    EXPECT_EQ(keys_only_pk, self_pk);
    Tox_Err_Group_Get_State err_get;
    EXPECT_EQ(tox_group_get_state(third, keys_only, &err_get), nullptr);
    EXPECT_EQ(err_get, TOX_ERR_GROUP_GET_STATE_NO_STATE);

    tox_group_state_free(state);
    tox_kill(third);
    tox_kill(other);
    tox_kill(tox);
}

// A length too large for the type toxcore keeps it in is rejected, and not
// taken as what is left of it in that type.
TEST(Tox, LengthTooLargeForItsTypeIsRejected)
{
    SimulatedEnvironment env{12345};
    struct Tox_Options *options = tox_options_new(nullptr);
    ASSERT_NE(options, nullptr);
    auto node = env.create_node(33545);
    Tox_Options_Testing testing_opts = {};
    testing_opts.operating_system = &node->system;
    Tox *tox = tox_new_testing(options, nullptr, &testing_opts, nullptr);
    tox_options_free(options);
    ASSERT_NE(tox, nullptr);

    const std::vector<std::uint8_t> data(UINT16_MAX + 4, 'a');

    Tox_Err_Set_Info name_err;
    EXPECT_FALSE(tox_self_set_name(tox, data.data(), data.size(), &name_err));
    EXPECT_EQ(name_err, TOX_ERR_SET_INFO_TOO_LONG);
    EXPECT_EQ(tox_self_get_name_size(tox), 0);

    Tox_Err_Conference_New conference_err;
    const std::uint32_t conference = tox_conference_new(tox, &conference_err);
    ASSERT_EQ(conference_err, TOX_ERR_CONFERENCE_NEW_OK);
    Tox_Err_Conference_Title title_err;
    EXPECT_FALSE(tox_conference_set_title(tox, conference, data.data(), UINT8_MAX + 4, &title_err));
    EXPECT_EQ(title_err, TOX_ERR_CONFERENCE_TITLE_INVALID_LENGTH);

    Tox_Err_Group_New group_err;
    EXPECT_EQ(tox_group_new(tox, TOX_GROUP_PRIVACY_STATE_PRIVATE, data.data(), data.size(),
                  data.data(), 1, &group_err),
        UINT32_MAX);
    EXPECT_EQ(group_err, TOX_ERR_GROUP_NEW_TOO_LONG);

    tox_kill(tox);
}

TEST(Tox, OneTest)
{
    SimulatedEnvironment env{12345};
    struct Tox_Options *options = tox_options_new(nullptr);
    ASSERT_NE(options, nullptr);

    tox_options_set_log_callback(options,
        [](Tox *_Nonnull tox, Tox_Log_Level level, const char *_Nonnull file, std::uint32_t line,
            const char *_Nonnull func, const char *_Nonnull message, void *_Nullable user_data) {
            fprintf(stderr, "[%c] %s:%u(%s): %s\n", tox_log_level_to_string(level)[0], file, line,
                func, message);
        });

    // Higher start/end point here to avoid conflict with the LAN discovery test.
    tox_options_set_start_port(options, 33545);
    tox_options_set_end_port(options, 33545 + 2000);

    std::vector<std::uint8_t> name(tox_max_name_length());
    std::vector<std::uint8_t> status_message(tox_max_status_message_length());

    std::vector<std::uint8_t> name2(tox_max_name_length());
    std::vector<std::uint8_t> status_message2(tox_max_status_message_length());

    auto node1 = env.create_node(33545);
    Tox_Options_Testing testing_opts1 = {};
    testing_opts1.operating_system = &node1->system;

    Tox *tox1 = tox_new_testing(options, nullptr, &testing_opts1, nullptr);
    ASSERT_NE(tox1, nullptr);
    const Random *rng = &node1->c_random;
    set_random_name_and_status_message(tox1, rng, name.data(), status_message.data());

    auto node2 = env.create_node(33546);
    Tox_Options_Testing testing_opts2 = {};
    testing_opts2.operating_system = &node2->system;

    Tox *tox2 = tox_new_testing(options, nullptr, &testing_opts2, nullptr);
    ASSERT_NE(tox2, nullptr);
    set_random_name_and_status_message(tox2, rng, name2.data(), status_message2.data());

    std::array<std::uint8_t, TOX_ADDRESS_SIZE> address;
    tox_self_get_address(tox1, address.data());
    Tox_Err_Friend_Add error;
    std::uint32_t ret = tox_friend_add(
        tox1, address.data(), reinterpret_cast<const std::uint8_t *>("m"), 1, &error);
    EXPECT_EQ(error, TOX_ERR_FRIEND_ADD_OWN_KEY) << "Adding own address worked.";
    EXPECT_EQ(ret, UINT32_MAX);

    tox_self_get_address(tox2, address.data());
    std::vector<std::uint8_t> message(tox_max_friend_request_length() + 1);
    ret = tox_friend_add(tox1, address.data(), message.data(), 0, &error);
    EXPECT_EQ(error, TOX_ERR_FRIEND_ADD_NO_MESSAGE) << "Sending request with no message worked.";
    EXPECT_EQ(ret, UINT32_MAX);
    ret = tox_friend_add(tox1, address.data(), message.data(), message.size(), &error);
    EXPECT_EQ(error, TOX_ERR_FRIEND_ADD_TOO_LONG) << "tox_max_friend_request_length() is too big.";
    EXPECT_EQ(ret, UINT32_MAX);

    address[0]++;
    ret = tox_friend_add(
        tox1, address.data(), reinterpret_cast<const std::uint8_t *>("m"), 1, &error);
    EXPECT_EQ(error, TOX_ERR_FRIEND_ADD_BAD_CHECKSUM) << "Adding address with bad checksum worked.";
    EXPECT_EQ(ret, UINT32_MAX);

    tox_self_get_address(tox2, address.data());
    ret = tox_friend_add(
        tox1, address.data(), message.data(), tox_max_friend_request_length(), &error);
    EXPECT_EQ(error, TOX_ERR_FRIEND_ADD_OK) << "Failed to add friend.";
    EXPECT_EQ(ret, 0);
    ret = tox_friend_add(
        tox1, address.data(), message.data(), tox_max_friend_request_length(), &error);
    EXPECT_EQ(error, TOX_ERR_FRIEND_ADD_ALREADY_SENT) << "Adding friend twice worked.";
    EXPECT_EQ(ret, UINT32_MAX);

    tox_self_set_name(tox1, name.data(), name.size(), nullptr);
    EXPECT_EQ(tox_self_get_name_size(tox1), name.size())
        << "Can't set name of length " << tox_max_name_length();

    tox_self_set_status_message(tox1, status_message.data(), status_message.size(), nullptr);
    EXPECT_EQ(tox_self_get_status_message_size(tox1), status_message.size())
        << "Can't set status message of length " << tox_max_status_message_length();

    tox_self_get_address(tox1, address.data());
    std::vector<std::uint8_t> data(tox_get_savedata_size(tox1));
    tox_get_savedata(tox1, data.data());

    tox_kill(tox2);
    Tox_Err_New err_n;

    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_TOX_SAVE);
    tox_options_set_savedata_data(options, data.data(), data.size());
    tox2 = tox_new_testing(options, &err_n, &testing_opts2, nullptr);
    EXPECT_EQ(err_n, TOX_ERR_NEW_OK) << "Load failed";

    EXPECT_EQ(tox_self_get_name_size(tox2), name.size()) << "Wrong name size.";
    EXPECT_EQ(tox_self_get_status_message_size(tox2), status_message.size())
        << "Wrong status message size";

    std::vector<std::uint8_t> name_loaded(tox_max_name_length());
    tox_self_get_name(tox2, name_loaded.data());
    EXPECT_EQ(name, name_loaded) << "Wrong name.";

    std::vector<std::uint8_t> status_message_loaded(tox_max_status_message_length());
    tox_self_get_status_message(tox2, status_message_loaded.data());
    EXPECT_EQ(status_message, status_message_loaded) << "Wrong status message.";

    std::array<std::uint8_t, TOX_ADDRESS_SIZE> address2;
    tox_self_get_address(tox2, address2.data());
    EXPECT_EQ(address2, address) << "Wrong address.";
    std::vector<std::uint8_t> new_name(tox_max_name_length());
    tox_self_get_name(tox2, new_name.data());
    EXPECT_EQ(name, new_name) << "Wrong name";

    std::array<std::uint8_t, TOX_SECRET_KEY_SIZE> sk;
    tox_self_get_secret_key(tox2, sk.data());
    tox_kill(tox2);

    tox_options_default(options);
    tox_options_set_savedata_type(options, TOX_SAVEDATA_TYPE_SECRET_KEY);
    tox_options_set_savedata_data(options, sk.data(), sk.size());
    tox2 = tox_new_testing(options, &err_n, &testing_opts2, nullptr);
    ASSERT_EQ(err_n, TOX_ERR_NEW_OK) << "Load failed";
    tox_self_set_nospam(tox2, tox_self_get_nospam(tox1));
    std::array<std::uint8_t, TOX_ADDRESS_SIZE> address3;
    tox_self_get_address(tox2, address3.data());
    EXPECT_EQ(address3, address) << "Wrong public key.";
    std::array<std::uint8_t, TOX_PUBLIC_KEY_SIZE> pk;
    tox_self_get_public_key(tox2, pk.data());
    std::array<std::uint8_t, TOX_PUBLIC_KEY_SIZE> pk_from_addr;
    std::copy(address.begin(), address.begin() + TOX_PUBLIC_KEY_SIZE, pk_from_addr.begin());
    EXPECT_EQ(pk, pk_from_addr) << "Wrong public key.";

    tox_options_free(options);
    tox_kill(tox1);
    tox_kill(tox2);
}

}  // namespace
