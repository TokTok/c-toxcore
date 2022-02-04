# Tox MessageV3 (alias Hubble telescope glasses)


proposal to transpartently patch current text messages to fix double messages and missed messages (and to support history sync in the future)


new defines:
------------

```
#define TOX_MAX_MESSAGE_LENGTH         (1372)
#define TOX_MSGV3_MSGID_LENGTH         (32)
#define TOX_MSGV3_TIMESTAMP_LENGTH     (4)
#define TOX_MSGV3_GUARD                (2)
#define TOX_MSGV3_MAX_MESSAGE_LENGTH   (TOX_MAX_MESSAGE_LENGTH - TOX_MSGV3_MSGID_LENGTH - TOX_MSGV3_TIMESTAMP_LENGTH - TOX_MSGV3_GUARD)


#define PACKET_ID_HIGH_LEVEL_ACK       (66)

typedef enum Message_Type {
    MESSAGE_NORMAL = 0,
    MESSAGE_ACTION = 1,
    MESSAGE_HIGH_LEVEL_ACK = 2,
} Message_Type;
```

new message type:
-----------------

```
typedef enum TOX_MESSAGE_TYPE {

    /**
     * Normal text message. Similar to PRIVMSG on IRC.
     */
    TOX_MESSAGE_TYPE_NORMAL = 0,

    /**
     * A message describing an user action. This is similar to /me (CTCP ACTION)
     * on IRC.
     */
    TOX_MESSAGE_TYPE_ACTION = 1,

    /**
     * A high level ACK for MSG IG (MSG V3 functionality)
     */
    TOX_MESSAGE_TYPE_HIGH_LEVEL_ACK = 2,

} TOX_MESSAGE_TYPE;
```

tweak in Messenger.c in m_handle_packet():
------------------------------------------

```
        case PACKET_ID_MESSAGE: // fall-through
        case PACKET_ID_ACTION:
        case PACKET_ID_HIGH_LEVEL_ACK: {
```

tweak in Messenger.c in m_send_message_generic():
-------------------------------------------------

```
if (type > MESSAGE_HIGH_LEVEL_ACK) {
```



sending and receiving msgV3:
----------------------------


raw data:

```
what           |Length     | Contents
----------------------------------------------------------------
pkt id         |1          | PACKET_ID_MESSAGE (64)
msg txt        |[0, 1334]  | Message (usually as a UTF8 byte string)
guard          |2          | 2 NULL bytes
msg id         |32         | *uint8_t hash (what hash function?) to uniquely identify the message
create ts      |4          | uint32_t unixtimestamp in UTC of local wall clock
 1334 = TOX_MSGV3_MAX_MESSAGE_LENGTH
```

sending description:
the client needs to use the new msgV3 format for text messages.
msg id will be a 32 byte hash value calculated the same way as now for filetransfers.
a helper function will be added to do that.
a client needs to save the created msd ig and the timstamp, to be able to resend the exact same data when a high level ACK was not received.


receiving description:

the maximum real text playload will decreae to 1334 bytes.
cients not using msgV3 will just process the message text up to the first NULL byte when interpreted as UTF-8.
if a client is using the data for other things as UTF-8 text, then that client needs to account for that.

clients using msgV3, will check for the guard and use the remaining data as uniqe message ID and unix timestamp in UTC wall clock time.
after fully processing the message, the client then needs to send the high level ACK with that msd id.

what happens if a malicious client sends the guard and then some random data?
then a bogus msg id and bogus timestamp will be received. so if messages are ordered by this timestamp, then message ordering will be wrong
for this single message.
are there other possible problematic things that can happen?


sending and receiving high level ACK:
-------------------------------------

raw data:

```
what           |Length     | Contents
----------------------------------------------------------------
pkt id         |1          | PACKET_ID_HIGH_LEVEL_ACK (66)
msg txt        |1          | dummy Message always '_' character
guard          |2          | 2 NULL bytes
msg id         |32         | *uint8_t hash (what hash function?) to uniquely identify the message
receive ts     |4          | uint32_t unixtimestamp in UTC of local wall clock
```
send the high level ACK as new message type. get a new uniqe hash with the new helper function.

new clients know which messages was received and also get the proper receive timestamp.
old clients will just ignore the unknown message type.
in case some older clients just display any message type from the callback, we include a valid UTF-8 text as '_' with NULL termination.


add helper functions for receiving:
-----------------------------------

```
bool tox_messagev3_get_new_message_id(*uint8_t msg_id)
  will return the msg id
  msg_id A valid memory location for the hash data.
         It must be at least TOX_HASH_LENGTH bytes in size.

         calculated the same as we do for filetransfers now:
         /* Tox keys are 32 bytes like FILE_ID_LENGTH. */
         new_symmetric_key(f_id);
         file_id = f_id;
```


### pros:
* does not break API or clients
* prevent double message sending (when a msg id is received again, just ignore it and send a high level ACK again)
* prevent missed messages (low level ACK sent but message not fully processed)

### cons:
* to be fully used clients need to add functionality


