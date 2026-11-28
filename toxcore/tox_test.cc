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

// As tox.h says: with length 0, the name and status message can be NULL, and
// are set back to empty.
TEST(Tox, NullWithLengthZeroClearsNameAndStatusMessage)
{
    Tox *tox = tox_new(nullptr, nullptr);
    ASSERT_NE(tox, nullptr);

    const std::array<std::uint8_t, 4> text = {'t', 'e', 'x', 't'};
    ASSERT_TRUE(tox_self_set_name(tox, text.data(), text.size(), nullptr));
    ASSERT_TRUE(tox_self_set_status_message(tox, text.data(), text.size(), nullptr));

    Tox_Err_Set_Info err;
    EXPECT_TRUE(tox_self_set_name(tox, nullptr, 0, &err));
    EXPECT_EQ(err, TOX_ERR_SET_INFO_OK);
    EXPECT_EQ(tox_self_get_name_size(tox), 0);

    EXPECT_TRUE(tox_self_set_status_message(tox, nullptr, 0, &err));
    EXPECT_EQ(err, TOX_ERR_SET_INFO_OK);
    EXPECT_EQ(tox_self_get_status_message_size(tox), 0);

    tox_kill(tox);
}

TEST(Tox, FileSendTakesNullFilenameWithLengthZero)
{
    Tox *tox = tox_new(nullptr, nullptr);
    ASSERT_NE(tox, nullptr);

    std::array<std::uint8_t, TOX_PUBLIC_KEY_SIZE> friend_pk;
    friend_pk.fill(0x01);
    const Tox_Friend_Number friend_number = tox_friend_add_norequest(tox, friend_pk.data(), nullptr);
    ASSERT_NE(friend_number, UINT32_MAX);

    // The friend isn't online, so this only gets past the argument checks.
    Tox_Err_File_Send err;
    tox_file_send(tox, friend_number, TOX_FILE_KIND_AVATAR, 0, nullptr, nullptr, 0, &err);
    EXPECT_EQ(err, TOX_ERR_FILE_SEND_FRIEND_NOT_CONNECTED);

    tox_kill(tox);
}

// As tox.h says: these group functions take NULL as they take an empty buffer,
// a NULL topic unsets the topic, and a NULL buffer to write into has no effect.
TEST(Tox, GroupFunctionsTakeNullAsDocumented)
{
    Tox *tox = tox_new(nullptr, nullptr);
    ASSERT_NE(tox, nullptr);

    const std::array<std::uint8_t, 4> text = {'t', 'e', 'x', 't'};
    Tox_Err_Group_New new_err;
    const Tox_Group_Number group = tox_group_new(tox, TOX_GROUP_PRIVACY_STATE_PRIVATE, text.data(),
        text.size(), text.data(), text.size(), &new_err);
    ASSERT_EQ(new_err, TOX_ERR_GROUP_NEW_OK);

    ASSERT_TRUE(tox_group_set_topic(tox, group, text.data(), text.size(), nullptr));
    Tox_Err_Group_Topic_Set topic_err;
    EXPECT_TRUE(tox_group_set_topic(tox, group, nullptr, text.size(), &topic_err));
    EXPECT_EQ(topic_err, TOX_ERR_GROUP_TOPIC_SET_OK);
    EXPECT_EQ(tox_group_get_topic_size(tox, group, nullptr), 0);

    const Tox_Group_Peer_Number self = tox_group_self_get_peer_id(tox, group, nullptr);
    Tox_Err_Group_Peer_Query peer_err;
    EXPECT_TRUE(tox_group_peer_get_public_key(tox, group, self, nullptr, &peer_err));
    EXPECT_EQ(peer_err, TOX_ERR_GROUP_PEER_QUERY_OK);
    EXPECT_TRUE(tox_group_peer_get_name(tox, group, self, nullptr, &peer_err));
    EXPECT_EQ(peer_err, TOX_ERR_GROUP_PEER_QUERY_OK);

    Tox_Err_Group_Self_Query self_err;
    EXPECT_TRUE(tox_group_self_get_name(tox, group, nullptr, &self_err));
    EXPECT_EQ(self_err, TOX_ERR_GROUP_SELF_QUERY_OK);
    EXPECT_TRUE(tox_group_self_get_public_key(tox, group, nullptr, &self_err));
    EXPECT_EQ(self_err, TOX_ERR_GROUP_SELF_QUERY_OK);

    Tox_Err_Group_State_Query state_err;
    EXPECT_TRUE(tox_group_get_name(tox, group, nullptr, &state_err));
    EXPECT_EQ(state_err, TOX_ERR_GROUP_STATE_QUERY_OK);
    EXPECT_TRUE(tox_group_get_chat_id(tox, group, nullptr, &state_err));
    EXPECT_EQ(state_err, TOX_ERR_GROUP_STATE_QUERY_OK);
    EXPECT_TRUE(tox_group_get_password(tox, group, nullptr, &state_err));
    EXPECT_EQ(state_err, TOX_ERR_GROUP_STATE_QUERY_OK);

    Tox_Err_Group_Self_Name_Set name_err;
    EXPECT_FALSE(tox_group_self_set_name(tox, group, nullptr, 0, &name_err));
    EXPECT_EQ(name_err, TOX_ERR_GROUP_SELF_NAME_SET_INVALID);

    Tox_Err_Group_Send_Message message_err;
    tox_group_send_message(tox, group, TOX_MESSAGE_TYPE_NORMAL, nullptr, 0, &message_err);
    EXPECT_EQ(message_err, TOX_ERR_GROUP_SEND_MESSAGE_EMPTY);

    Tox_Err_Group_Send_Private_Message private_err;
    tox_group_send_private_message(
        tox, group, self, TOX_MESSAGE_TYPE_NORMAL, nullptr, 0, &private_err);
    EXPECT_EQ(private_err, TOX_ERR_GROUP_SEND_PRIVATE_MESSAGE_EMPTY);

    Tox_Err_Group_Send_Custom_Packet packet_err;
    tox_group_send_custom_packet(tox, group, true, nullptr, 0, &packet_err);
    EXPECT_EQ(packet_err, TOX_ERR_GROUP_SEND_CUSTOM_PACKET_EMPTY);

    Tox_Err_Group_Send_Custom_Private_Packet private_packet_err;
    tox_group_send_custom_private_packet(tox, group, self, true, nullptr, 0, &private_packet_err);
    EXPECT_EQ(private_packet_err, TOX_ERR_GROUP_SEND_CUSTOM_PRIVATE_PACKET_EMPTY);

    tox_kill(tox);
}

// A NULL public key buffer has no effect, as tox.h says, but the error still
// says whether the friend exists.
TEST(Tox, FriendPublicKeyIntoNullStillSaysWhetherTheFriendExists)
{
    Tox *tox = tox_new(nullptr, nullptr);
    ASSERT_NE(tox, nullptr);

    Tox_Err_Friend_Get_Public_Key err = TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK;
    EXPECT_FALSE(tox_friend_get_public_key(tox, 0, nullptr, &err));
    EXPECT_EQ(err, TOX_ERR_FRIEND_GET_PUBLIC_KEY_FRIEND_NOT_FOUND);

    std::array<std::uint8_t, TOX_PUBLIC_KEY_SIZE> public_key{};
    public_key[0] = 1;
    const Tox_Friend_Number friend_number
        = tox_friend_add_norequest(tox, public_key.data(), nullptr);
    ASSERT_NE(friend_number, UINT32_MAX);

    err = TOX_ERR_FRIEND_GET_PUBLIC_KEY_FRIEND_NOT_FOUND;
    EXPECT_TRUE(tox_friend_get_public_key(tox, friend_number, nullptr, &err));
    EXPECT_EQ(err, TOX_ERR_FRIEND_GET_PUBLIC_KEY_OK);

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
