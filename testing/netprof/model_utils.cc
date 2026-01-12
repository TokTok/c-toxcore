#include "model_utils.hh"

#include <cmath>

#include "../../toxcore/tox_private.h"

namespace tox::netprof {
namespace {

    void classify_packet(const NodeInfo::ProtocolKey &pk, uint64_t total, uint64_t &dht,
        uint64_t &data, uint64_t &onion)
    {
        Tox_Netprof_Packet_Id id = static_cast<Tox_Netprof_Packet_Id>(pk.id);

        if (pk.protocol == TOX_NETPROF_PACKET_TYPE_UDP) {
            switch (id) {
            case TOX_NETPROF_PACKET_ID_ZERO:  // Ping Req
            case TOX_NETPROF_PACKET_ID_ONE:  // Ping Resp
            case TOX_NETPROF_PACKET_ID_TWO:  // Nodes Req
            case TOX_NETPROF_PACKET_ID_FOUR:  // Nodes Resp
            case TOX_NETPROF_PACKET_ID_ANNOUNCE_REQUEST_OLD:
            case TOX_NETPROF_PACKET_ID_ANNOUNCE_RESPONSE_OLD:
            case TOX_NETPROF_PACKET_ID_ANNOUNCE_REQUEST:
            case TOX_NETPROF_PACKET_ID_ANNOUNCE_RESPONSE:
                dht += total;
                break;
            case TOX_NETPROF_PACKET_ID_CRYPTO_HS:
            case TOX_NETPROF_PACKET_ID_CRYPTO_DATA:
            case TOX_NETPROF_PACKET_ID_CRYPTO:
                data += total;
                break;
            case TOX_NETPROF_PACKET_ID_ONION_SEND_INITIAL:
            case TOX_NETPROF_PACKET_ID_ONION_SEND_1:
            case TOX_NETPROF_PACKET_ID_ONION_SEND_2:
            case TOX_NETPROF_PACKET_ID_ONION_DATA_REQUEST:
            case TOX_NETPROF_PACKET_ID_ONION_DATA_RESPONSE:
            case TOX_NETPROF_PACKET_ID_ONION_RECV_3:
            case TOX_NETPROF_PACKET_ID_ONION_RECV_2:
            case TOX_NETPROF_PACKET_ID_ONION_RECV_1:
                onion += total;
                break;
            case TOX_NETPROF_PACKET_ID_TCP_DISCONNECT:
            case TOX_NETPROF_PACKET_ID_TCP_PONG:
            case TOX_NETPROF_PACKET_ID_TCP_OOB_SEND:
            case TOX_NETPROF_PACKET_ID_TCP_OOB_RECV:
            case TOX_NETPROF_PACKET_ID_TCP_ONION_REQUEST:
            case TOX_NETPROF_PACKET_ID_TCP_ONION_RESPONSE:
            case TOX_NETPROF_PACKET_ID_TCP_FORWARD_REQUEST:
            case TOX_NETPROF_PACKET_ID_TCP_FORWARDING:
            case TOX_NETPROF_PACKET_ID_TCP_DATA:
            case TOX_NETPROF_PACKET_ID_COOKIE_REQUEST:
            case TOX_NETPROF_PACKET_ID_COOKIE_RESPONSE:
            case TOX_NETPROF_PACKET_ID_LAN_DISCOVERY:
            case TOX_NETPROF_PACKET_ID_GC_HANDSHAKE:
            case TOX_NETPROF_PACKET_ID_GC_LOSSLESS:
            case TOX_NETPROF_PACKET_ID_GC_LOSSY:
            case TOX_NETPROF_PACKET_ID_FORWARD_REQUEST:
            case TOX_NETPROF_PACKET_ID_FORWARDING:
            case TOX_NETPROF_PACKET_ID_FORWARD_REPLY:
            case TOX_NETPROF_PACKET_ID_DATA_SEARCH_REQUEST:
            case TOX_NETPROF_PACKET_ID_DATA_SEARCH_RESPONSE:
            case TOX_NETPROF_PACKET_ID_DATA_RETRIEVE_REQUEST:
            case TOX_NETPROF_PACKET_ID_DATA_RETRIEVE_RESPONSE:
            case TOX_NETPROF_PACKET_ID_STORE_ANNOUNCE_REQUEST:
            case TOX_NETPROF_PACKET_ID_STORE_ANNOUNCE_RESPONSE:
            case TOX_NETPROF_PACKET_ID_BOOTSTRAP_INFO:
                break;
            }
        } else {
            // TCP (don't need to handle all the items, so cast to int).
            switch (static_cast<int>(id)) {
            case TOX_NETPROF_PACKET_ID_TCP_ONION_REQUEST:
            case TOX_NETPROF_PACKET_ID_TCP_ONION_RESPONSE:
                onion += total;
                break;
            case TOX_NETPROF_PACKET_ID_TCP_DATA:
                data += total;
                break;
            default:
                break;
            }
        }
    }

}  // namespace

TrafficCategory get_dominant_traffic_category(const NodeInfo &node)
{
    uint64_t dht = 0, data = 0, onion = 0;
    for (const auto &pk : node.protocol_breakdown) {
        uint64_t total = pk.second.sent + pk.second.recv;
        classify_packet(pk.first, total, dht, data, onion);
    }

    if (dht == 0 && data == 0 && onion == 0) {
        return TrafficCategory::None;
    }

    if (dht > data && dht > onion) {
        return TrafficCategory::DHT;
    }

    if (data > dht && data > onion) {
        return TrafficCategory::Data;
    }

    if (onion > dht && onion > data) {
        return TrafficCategory::Onion;
    }

    return TrafficCategory::None;
}

float project_dht_id_to_theta(const std::vector<uint8_t> &dht_id)
{
    if (dht_id.size() < 4) {
        return 0.0f;
    }
    // Use first 4 bytes for better entropy than 2 bytes
    uint32_t val = (static_cast<uint32_t>(dht_id[0]) << 24)
        | (static_cast<uint32_t>(dht_id[1]) << 16) | (static_cast<uint32_t>(dht_id[2]) << 8)
        | static_cast<uint32_t>(dht_id[3]);

    return static_cast<float>(val) / 4294967296.0f * 2.0f * 3.14159265f;
}

bool safe_stod(const std::string &s, double &out)
{
    if (s.empty())
        return false;
    char *end;
    out = std::strtod(s.c_str(), &end);
    return *end == '\0';
}

bool safe_stof(const std::string &s, float &out)
{
    if (s.empty())
        return false;
    char *end;
    out = std::strtof(s.c_str(), &end);
    return *end == '\0';
}

bool safe_stoul(const std::string &s, uint32_t &out)
{
    if (s.empty())
        return false;
    if (s[0] == '-' || s[0] == '+')
        return false;
    char *end;
    unsigned long val = std::strtoul(s.c_str(), &end, 10);
    if (*end != '\0')
        return false;
    out = static_cast<uint32_t>(val);
    return true;
}

bool case_insensitive_equal(const std::string &a, const std::string &b)
{
    if (a.length() != b.length())
        return false;
    for (size_t i = 0; i < a.length(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i]))
            != std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

}  // namespace tox::netprof
