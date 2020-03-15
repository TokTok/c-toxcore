/* SPDX-License-Identifier: GPL-3.0-or-later
 * Copyright © 2016-2018 The TokTok team.
 * Copyright © 2013-2015 Tox project.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif /* HAVE_CONFIG_H */

#include "bwcontroller.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "ring_buffer.h"

#include "../toxcore/logger.h"
#include "../toxcore/mono_time.h"
#include "../toxcore/util.h"

/*
 * Zoff: disable logging in ToxAV for now
 */
static void dummy()
{
}

#undef LOGGER_DEBUG
#define LOGGER_DEBUG(log, ...) dummy()
#undef LOGGER_INFO
#define LOGGER_INFO(log, ...) dummy()

#define BWC_PACKET_ID 196
#define BWC_SEND_INTERVAL_MS 950     // 0.95s
#define BWC_AVG_PKT_COUNT 20
#define BWC_AVG_LOSS_OVER_CYCLES_COUNT 30

typedef struct BWCCycle {
    uint32_t last_recv_timestamp; /* Last recv update time stamp */
    uint32_t last_sent_timestamp; /* Last sent update time stamp */
    uint32_t last_refresh_timestamp; /* Last refresh time stamp */

    uint32_t lost;
    uint32_t recv;
} BWCCycle;

typedef struct BWCRcvPkt {
    uint32_t packet_length_array[BWC_AVG_PKT_COUNT];
    RingBuffer *rb;
} BWCRcvPkt;

struct BWController_s {
    m_cb *mcb;
    void *mcb_user_data;

    Messenger *m;
    uint32_t friend_number;

    BWCCycle cycle;

    BWCRcvPkt rcvpkt; /* To calculate average received packet (this means split parts, not the full message!) */

    uint32_t packet_loss_counted_cycles;
};

struct BWCMessage {
    uint32_t lost;
    uint32_t recv;
};

int bwc_handle_data(Messenger *m, uint32_t friendnumber, const uint8_t *data, uint16_t length, void *object);
void send_update(BWController *bwc);

BWController *bwc_new(Messenger *m, uint32_t friendnumber, m_cb *mcb, void *mcb_user_data)
{
    BWController *retu = (BWController *)calloc(sizeof(struct BWController_s), 1);
    LOGGER_DEBUG(m->log, "Creating bandwidth controller");
    retu->mcb = mcb;
    retu->mcb_user_data = mcb_user_data;
    retu->m = m;
    retu->friend_number = friendnumber;
    uint64_t now = current_time_monotonic(m->mono_time);
    retu->cycle.last_sent_timestamp = now;
    retu->cycle.last_refresh_timestamp = now;
    retu->rcvpkt.rb = rb_new(BWC_AVG_PKT_COUNT);
    retu->cycle.lost = 0;
    retu->cycle.recv = 0;
    retu->packet_loss_counted_cycles = 0;

    /* Fill with zeros */
    for (int i = 0; i < BWC_AVG_PKT_COUNT; ++i) {
        rb_write(retu->rcvpkt.rb, &retu->rcvpkt.packet_length_array[i]);
    }

    //*PP*// m_callback_rtp_packet(m, friendnumber, BWC_PACKET_ID, bwc_handle_data, retu);
    return retu;
}

void bwc_kill(BWController *bwc)
{
    if (!bwc) {
        return;
    }

    //*PP*// m_callback_rtp_packet(bwc->m, bwc->friend_number, BWC_PACKET_ID, nullptr, nullptr);
    rb_kill(bwc->rcvpkt.rb);
    free(bwc);
}

void bwc_add_lost(BWController *bwc, uint32_t bytes_lost)
{
    if (!bwc) {
        return;
    }

    if (bytes_lost > 0) {
        LOGGER_DEBUG(bwc->m->log, "BWC lost(1): %d", (int)bytes_lost);
        bwc->cycle.lost += bytes_lost;
        send_update(bwc);
    }
}

void bwc_add_recv(BWController *bwc, uint32_t recv_bytes)
{
    if (!bwc || !recv_bytes) {
        return;
    }

    ++bwc->packet_loss_counted_cycles;
    bwc->cycle.recv += recv_bytes;
    send_update(bwc);
}

void send_update(BWController *bwc)
{
    if (bwc->packet_loss_counted_cycles > BWC_AVG_LOSS_OVER_CYCLES_COUNT &&
            current_time_monotonic(bwc->m->mono_time) - bwc->cycle.last_sent_timestamp > BWC_SEND_INTERVAL_MS) {
        bwc->packet_loss_counted_cycles = 0;

        if (bwc->cycle.lost) {
            LOGGER_DEBUG(bwc->m->log, "%p Sent update rcv: %u lost: %u percent: %f %%",
                         (void *)bwc, bwc->cycle.recv, bwc->cycle.lost,
                         (((double) bwc->cycle.lost / (bwc->cycle.recv + bwc->cycle.lost)) * 100.0));
            uint8_t bwc_packet[sizeof(struct BWCMessage) + 1];
            size_t offset = 0;

            bwc_packet[offset] = BWC_PACKET_ID; // set packet ID
            ++offset;

            offset += net_pack_u32(bwc_packet + offset, bwc->cycle.lost);
            offset += net_pack_u32(bwc_packet + offset, bwc->cycle.recv);
            assert(offset == sizeof(bwc_packet));

#if 0

            if (m_msi_send_custom_lossy_packet(bwc->m, bwc->friend_number, bwc_packet, sizeof(bwc_packet)) == -1) {
                const char *netstrerror = net_new_strerror(net_error());
                LOGGER_WARNING(bwc->m->log, "BWC send failed (len: %u)! std error: %s, net error %s",
                               (unsigned)sizeof(bwc_packet), strerror(errno), netstrerror);
                net_kill_strerror(netstrerror);
            }

#endif
        }

        bwc->cycle.last_sent_timestamp = current_time_monotonic(bwc->m->mono_time);
        bwc->cycle.lost = 0;
        bwc->cycle.recv = 0;
    }
}

static int on_update(BWController *bwc, const struct BWCMessage *msg)
{
    LOGGER_DEBUG(bwc->m->log, "%p Got update from peer", (void *)bwc);

    /* Peers sent update too soon */
    if (bwc->cycle.last_recv_timestamp + BWC_SEND_INTERVAL_MS > current_time_monotonic(bwc->m->mono_time)) {
        LOGGER_INFO(bwc->m->log, "%p Rejecting extra update", (void *)bwc);
        return -1;
    }

    bwc->cycle.last_recv_timestamp = current_time_monotonic(bwc->m->mono_time);

    const uint32_t recv = msg->recv;
    const uint32_t lost = msg->lost;

    if (lost && bwc->mcb) {
        LOGGER_DEBUG(bwc->m->log, "recved: %u lost: %u percentage: %f %%", recv, lost,
                     (((double) lost / (recv + lost)) * 100.0));
        bwc->mcb(bwc, bwc->friend_number,
                 ((float) lost / (recv + lost)),
                 bwc->mcb_user_data);
    }

    return 0;
}

int bwc_handle_data(Messenger *m, uint32_t friendnumber, const uint8_t *data, uint16_t length, void *object)
{
    if (length - 1 != sizeof(struct BWCMessage)) {
        return -1;
    }

    size_t offset = 1;  // Ignore packet id.
    struct BWCMessage msg;
    offset += net_unpack_u32(data + offset, &msg.lost);
    offset += net_unpack_u32(data + offset, &msg.recv);
    assert(offset == length);

    return on_update((BWController *)object, &msg);
}
