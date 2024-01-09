#include "DHT_test_util.h"

PublicKey random_pk(const Random *rng)
{
    PublicKey pk;
    random_bytes(rng, pk.data(), pk.size());
    return pk;
}

IP_Port random_ip_port(const Random *rng)
{
    IP_Port ip_port;
    ip_port.ip.family = net_family_ipv4();
    ip_port.ip.ip.v4.uint8[0] = 192;
    ip_port.ip.ip.v4.uint8[1] = 168;
    ip_port.ip.ip.v4.uint8[2] = 0;
    ip_port.ip.ip.v4.uint8[3] = random_u08(rng);
    ip_port.port = random_u16(rng);
    return ip_port;
}

Node_format random_node_format(const Random *rng)
{
    Node_format node;
    auto const pk = random_pk(rng);
    std::copy(pk.begin(), pk.end(), node.public_key);
    node.ip_port = random_ip_port(rng);
    return node;
}
