#include "DHT.h"

#include <cassert>
#include <cstdlib>
#include <cstring>
#include <vector>

#include "../testing/fuzzing/fuzz_support.hh"
#include "DHT_test_util.hh"

namespace {

void TestHandleRequest(Fuzz_Data &input)
{
    CONSUME_OR_RETURN(const uint8_t *self_public_key, input, CRYPTO_PUBLIC_KEY_SIZE);
    CONSUME_OR_RETURN(const uint8_t *self_secret_key, input, CRYPTO_SECRET_KEY_SIZE);

    uint8_t public_key[CRYPTO_PUBLIC_KEY_SIZE];
    uint8_t request[MAX_CRYPTO_REQUEST_SIZE];
    uint8_t request_id;
    handle_request(self_public_key, self_secret_key, public_key, request, &request_id, input.data(),
        input.size());
}

void TestUnpackNodes(Fuzz_Data &input)
{
    CONSUME1_OR_RETURN(const bool, tcp_enabled, input);

    const uint16_t node_count = 5;
    std::array<Node_format, node_count> nodes;
    uint16_t processed_data_len;
    const int packed_count = unpack_nodes(
        nodes.data(), nodes.size(), &processed_data_len, input.data(), input.size(), tcp_enabled);
    if (packed_count > 0) {
        const Memory *mem = os_memory();
        Logger *logger = logger_new(mem);
        std::vector<uint8_t> packed(packed_count * PACKED_NODE_SIZE_IP6);
        const int packed_size
            = pack_nodes(logger, packed.data(), packed.size(), nodes.data(), packed_count);
        LOGGER_ASSERT(logger, packed_size == processed_data_len,
            "packed size (%d) != unpacked size (%d)", packed_size, processed_data_len);
        logger_kill(logger);

        // Check that packed nodes can be unpacked again and result in the
        // original unpacked nodes.
        std::array<Node_format, node_count> nodes2;
        uint16_t processed_data_len2;
        const int packed_count2 = unpack_nodes(nodes2.data(), nodes2.size(), &processed_data_len2,
            packed.data(), packed.size(), tcp_enabled);
        (void)packed_count2;
#if 0
        assert(processed_data_len2 == processed_data_len);
        assert(packed_count2 == packed_count);
#endif
        assert(std::vector<Node_format>(nodes.begin(), nodes.begin() + packed_count)
            == std::vector<Node_format>(nodes2.begin(), nodes2.begin() + packed_count));
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);
extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    fuzz_select_target<TestHandleRequest, TestUnpackNodes>(data, size);
    return 0;
}
