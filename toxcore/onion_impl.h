#ifndef C_TOXCORE_TOXCORE_ONION_IMPL_H
#define C_TOXCORE_TOXCORE_ONION_IMPL_H
#include "onion.h"
#include "DHT.h"
#include "mono_time.h"
#include "network.h"
#include "shared_key_cache.h"

struct Onion {
    const Logger *_Nonnull log;
    const Mono_Time *_Nonnull mono_time;
    const Random *_Nonnull rng;
    const Memory *_Nonnull mem;
    DHT *_Nonnull dht;
    Networking_Core *_Nonnull net;
    uint8_t secret_symmetric_key[CRYPTO_SYMMETRIC_KEY_SIZE];
    uint64_t timestamp;

    Shared_Key_Cache *_Nonnull shared_keys_1;
    Shared_Key_Cache *_Nonnull shared_keys_2;
    Shared_Key_Cache *_Nonnull shared_keys_3;

    onion_recv_1_cb *_Nullable recv_1_function;
    void *_Nullable callback_object;
};

#endif /* C_TOXCORE_TOXCORE_ONION_IMPL_H */
