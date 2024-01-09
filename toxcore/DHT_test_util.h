#ifndef C_TOXCORE_TOXCORE_DHT_TEST_UTIL_H
#define C_TOXCORE_TOXCORE_DHT_TEST_UTIL_H

#include "DHT.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <iomanip>
#include <vector>

template <typename T, size_t N>
std::array<T, N> to_array(T const (&arr)[N])
{
    std::array<T, N> stdarr;
    std::copy(arr, arr + N, stdarr.begin());
    return stdarr;
}

template <size_t N, typename T, typename... Args>
auto array_of(T &&make, Args... args)
{
    std::array<typename std::result_of<T(Args...)>::type, N> arr;
    for (auto &elem : arr) {
        elem = make(args...);
    }
    return arr;
}

template <typename T, typename... Args>
auto vector_of(size_t n, T &&make, Args... args)
{
    std::vector<typename std::result_of<T(Args...)>::type> vec(n);
    for (auto &elem : vec) {
        elem = make(args...);
    }
    return vec;
}

template <typename Container, typename Less>
Container sorted(Container arr, Less less)
{
    std::sort(arr.begin(), arr.end(), less);
    return arr;
}

struct PublicKey : private std::array<uint8_t, CRYPTO_PUBLIC_KEY_SIZE> {
    using Base = std::array<uint8_t, CRYPTO_PUBLIC_KEY_SIZE>;

    using Base::begin;
    using Base::data;
    using Base::end;
    using Base::size;
    using Base::operator[];

    PublicKey() = default;
    PublicKey(uint8_t const (&arr)[CRYPTO_PUBLIC_KEY_SIZE])
        : PublicKey(to_array(arr))
    {
    }
    PublicKey(std::array<uint8_t, CRYPTO_PUBLIC_KEY_SIZE> const &arr)
    {
        std::copy(arr.begin(), arr.end(), begin());
    }

    PublicKey(std::initializer_list<uint8_t> const &arr)
    {
        std::copy(arr.begin(), arr.end(), begin());
    }

    Base const &base() const { return *this; }
};

inline bool operator!=(PublicKey const &pk1, PublicKey const &pk2)
{
    return pk1.base() != pk2.base();
}

inline bool operator==(PublicKey const &pk1, PublicKey const &pk2)
{
    return pk1.base() == pk2.base();
}

inline bool operator==(PublicKey::Base const &pk1, PublicKey const &pk2)
{
    return pk1 == pk2.base();
}

inline std::ostream &operator<<(std::ostream &out, PublicKey const &pk)
{
    out << '"';
    for (uint8_t byte : pk) {
        out << std::setw(2) << std::setfill('0') << std::hex << uint32_t(byte);
    }
    out << '"';
    return out;
}

inline bool operator==(Node_format const &a, Node_format const &b)
{
    return std::memcmp(&a, &b, sizeof(Node_format)) == 0;
}

inline std::ostream &operator<<(std::ostream &out, IP const &v)
{
    Ip_Ntoa ip_str;
    out << '"' << net_ip_ntoa(&v, &ip_str) << '"';
    return out;
}

inline std::ostream &operator<<(std::ostream &out, IP_Port const &v)
{
    return out << "IP_Port{\n"
               << "        ip = " << v.ip << ",\n"
               << "        port = " << std::dec << std::setw(0) << v.port << " }";
}

inline std::ostream &operator<<(std::ostream &out, Node_format const &v)
{
    return out << "\n    Node_format{\n"
               << "      public_key = " << PublicKey(v.public_key) << ",\n"
               << "      ip_port = " << v.ip_port << " }";
}

PublicKey random_pk(const Random *rng);
IP_Port random_ip_port(const Random *rng);
Node_format random_node_format(const Random *rng);

#endif  // C_TOXCORE_TOXCORE_DHT_TEST_UTIL_H
