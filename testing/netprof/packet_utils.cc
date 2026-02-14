#include "packet_utils.hh"

#include <string>

#include "../../toxcore/tox_private.h"

namespace tox::netprof {

std::string get_packet_name(Tox_Netprof_Packet_Type protocol, uint8_t id)
{
    switch (static_cast<Tox_Netprof_Packet_Id>(id)) {
    case TOX_NETPROF_PACKET_ID_ZERO:
        return (protocol == TOX_NETPROF_PACKET_TYPE_UDP) ? "Ping Req" : "Routing Req";
    case TOX_NETPROF_PACKET_ID_ONE:
        return (protocol == TOX_NETPROF_PACKET_TYPE_UDP) ? "Ping Resp" : "Routing Resp";
    case TOX_NETPROF_PACKET_ID_TWO:
        return (protocol == TOX_NETPROF_PACKET_TYPE_UDP) ? "Nodes Req" : "Conn Notification";
    case TOX_NETPROF_PACKET_ID_TCP_DISCONNECT:
        return "TCP Disconnect";
    case TOX_NETPROF_PACKET_ID_FOUR:
        return (protocol == TOX_NETPROF_PACKET_TYPE_UDP) ? "Nodes Resp" : "Ping (TCP)";
    case TOX_NETPROF_PACKET_ID_TCP_PONG:
        return "TCP Pong";
    case TOX_NETPROF_PACKET_ID_TCP_OOB_SEND:
        return "TCP OOB Send";
    case TOX_NETPROF_PACKET_ID_TCP_OOB_RECV:
        return "TCP OOB Recv";
    case TOX_NETPROF_PACKET_ID_TCP_ONION_REQUEST:
        return "TCP Onion Req";
    case TOX_NETPROF_PACKET_ID_TCP_ONION_RESPONSE:
        return "TCP Onion Resp";
    case TOX_NETPROF_PACKET_ID_TCP_FORWARD_REQUEST:
        return "TCP Forward Req";
    case TOX_NETPROF_PACKET_ID_TCP_FORWARDING:
        return "TCP Forwarding";
    case TOX_NETPROF_PACKET_ID_TCP_DATA:
        return (protocol == TOX_NETPROF_PACKET_TYPE_TCP) ? "TCP Data (Conn 0)" : "UDP Range 16-255";
    case TOX_NETPROF_PACKET_ID_COOKIE_REQUEST:
        return "Cookie Req";
    case TOX_NETPROF_PACKET_ID_COOKIE_RESPONSE:
        return "Cookie Resp";
    case TOX_NETPROF_PACKET_ID_CRYPTO_HS:
        return "Crypto HS";
    case TOX_NETPROF_PACKET_ID_CRYPTO_DATA:
        return "Crypto Data";
    case TOX_NETPROF_PACKET_ID_CRYPTO:
        return "Encrypted Data";
    case TOX_NETPROF_PACKET_ID_LAN_DISCOVERY:
        return "LAN Discovery";
    case TOX_NETPROF_PACKET_ID_GC_HANDSHAKE:
        return "GC Handshake";
    case TOX_NETPROF_PACKET_ID_GC_LOSSLESS:
        return "GC Lossless";
    case TOX_NETPROF_PACKET_ID_GC_LOSSY:
        return "GC Lossy";
    case TOX_NETPROF_PACKET_ID_ONION_SEND_INITIAL:
        return "Onion Send Init";
    case TOX_NETPROF_PACKET_ID_ONION_SEND_1:
        return "Onion Send 1";
    case TOX_NETPROF_PACKET_ID_ONION_SEND_2:
        return "Onion Send 2";
    case TOX_NETPROF_PACKET_ID_ANNOUNCE_REQUEST_OLD:
        return "Announce Req (Old)";
    case TOX_NETPROF_PACKET_ID_ANNOUNCE_RESPONSE_OLD:
        return "Announce Resp (Old)";
    case TOX_NETPROF_PACKET_ID_ONION_DATA_REQUEST:
        return "Onion Data Req";
    case TOX_NETPROF_PACKET_ID_ONION_DATA_RESPONSE:
        return "Onion Data Resp";
    case TOX_NETPROF_PACKET_ID_ANNOUNCE_REQUEST:
        return "Announce Req";
    case TOX_NETPROF_PACKET_ID_ANNOUNCE_RESPONSE:
        return "Announce Resp";
    case TOX_NETPROF_PACKET_ID_ONION_RECV_3:
        return "Onion Recv 3";
    case TOX_NETPROF_PACKET_ID_ONION_RECV_2:
        return "Onion Recv 2";
    case TOX_NETPROF_PACKET_ID_ONION_RECV_1:
        return "Onion Recv 1";
    case TOX_NETPROF_PACKET_ID_FORWARD_REQUEST:
        return "Forward Req";
    case TOX_NETPROF_PACKET_ID_FORWARDING:
        return "Forwarding";
    case TOX_NETPROF_PACKET_ID_FORWARD_REPLY:
        return "Forward Reply";
    case TOX_NETPROF_PACKET_ID_DATA_SEARCH_REQUEST:
        return "Data Search Req";
    case TOX_NETPROF_PACKET_ID_DATA_SEARCH_RESPONSE:
        return "Data Search Resp";
    case TOX_NETPROF_PACKET_ID_DATA_RETRIEVE_REQUEST:
        return "Data Retrieve Req";
    case TOX_NETPROF_PACKET_ID_DATA_RETRIEVE_RESPONSE:
        return "Data Retrieve Resp";
    case TOX_NETPROF_PACKET_ID_STORE_ANNOUNCE_REQUEST:
        return "Store Announce Req";
    case TOX_NETPROF_PACKET_ID_STORE_ANNOUNCE_RESPONSE:
        return "Store Announce Resp";
    case TOX_NETPROF_PACKET_ID_BOOTSTRAP_INFO:
        return "Bootstrap Info";
    }

    if (protocol == TOX_NETPROF_PACKET_TYPE_TCP && id >= 16) {
        return "TCP Conn " + std::to_string(id - 16);
    }

    const char *name_ptr = tox_netprof_packet_id_to_string(static_cast<Tox_Netprof_Packet_Id>(id));
    if (!name_ptr || std::string(name_ptr).find("<invalid") != std::string::npos) {
        return (protocol == TOX_NETPROF_PACKET_TYPE_UDP ? "UDP " : "TCP ") + std::to_string(id);
    }

    std::string name = name_ptr;
    const std::string prefix = "TOX_NETPROF_PACKET_ID_";
    if (name.compare(0, prefix.length(), prefix) == 0) {
        name = name.substr(prefix.length());
    }
    return name;
}

}  // namespace tox::netprof
