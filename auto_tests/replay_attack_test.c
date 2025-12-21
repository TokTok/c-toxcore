#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include "auto_test_support.h"
#include "check_compat.h"

#include "../toxcore/Messenger.h"
#include "../toxcore/friend_connection.h"
#include "../toxcore/tox_struct.h"
#include "../toxcore/net_crypto_impl.h"


static void test_replay_attack_callback(AutoTox *toxes)
{
    Tox *tox1 = toxes[0].tox;
    Tox *tox2 = toxes[1].tox;

    // 1. Get Net_Crypto objects and friend connection id.
    Net_Crypto *nc1 = tox1->m->net_crypto;
    Net_Crypto *nc2 = tox2->m->net_crypto;
    uint8_t self_pk[CRYPTO_PUBLIC_KEY_SIZE];
    tox_self_get_public_key(tox2, self_pk);
    int friend_id = getfriend_id(tox1->m, self_pk);
    assert(friend_id != -1);
    int friend_conn_id = getfriendcon_id(tox1->m, friend_id);
    assert(friend_conn_id != -1);
    int conn_id = friend_connection_crypt_connection_id(tox1->m->fr_c, friend_conn_id);
    assert(conn_id != -1);

    // 2. Get the crypto connections.
    Crypto_Connection *conn1 = get_crypto_connection(nc1, conn_id);
    assert(conn1 != NULL);
    Crypto_Connection *conn2 = get_crypto_connection(nc2, conn_id);
    assert(conn2 != NULL);

    // 3. Craft a data packet.
    uint8_t data[] = {PACKET_ID_RANGE_LOSSLESS_START, 1, 2, 3};
    const uint16_t max_length = MAX_CRYPTO_PACKET_SIZE - (1 + sizeof(uint16_t) + CRYPTO_MAC_SIZE);
    assert(sizeof(data) <= max_length);

    const uint16_t packet_size = 1 + sizeof(uint16_t) + sizeof(data) + CRYPTO_MAC_SIZE;
    uint8_t packet[packet_size];
    packet[0] = NET_PACKET_CRYPTO_DATA;
    memcpy(packet + 1, conn1->sent_nonce + (CRYPTO_NONCE_SIZE - sizeof(uint16_t)), sizeof(uint16_t));

    const int len = encrypt_data_symmetric(nc1->mem, conn1->shared_key, conn1->sent_nonce, data, sizeof(data), packet + 1 + sizeof(uint16_t));
    assert(len + 1 + sizeof(uint16_t) == packet_size);
    increment_nonce(conn1->sent_nonce);

    // 4. Handle the packet on the receiver side. It should succeed.
    uint8_t decrypted_data[MAX_CRYPTO_DATA_SIZE];
    int decrypted_len = handle_data_packet(nc2, conn_id, decrypted_data, packet, packet_size);
    assert(decrypted_len > 0);

    // 5. Replay the same packet. It should fail.
    decrypted_len = handle_data_packet(nc2, conn_id, decrypted_data, packet, packet_size);
    assert(decrypted_len == -1);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);

    Run_Auto_Options options = default_run_auto_options();
    run_auto_test(NULL, 2, &test_replay_attack_callback, 0, &options);

    return 0;
}
