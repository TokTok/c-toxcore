
# Spec for Filetransfer version 2 addon (short: ftv2a)

## how do filetransfers in tox work?

```
sender --->                                   | ---> receiver
-------------------------------------------------------------------
tox_file_send()                               |
  new_filesender()                            |   
    file_sendrequest()                        |
      write_cryptpacket_id()                  |
       network[PACKET_ID_FILE_SENDREQUEST] -> | -> network[PACKET_ID_FILE_SENDREQUEST]
                                              | <- network[-ACK-]
                                              |      [-OFFLINE-] --> EEE001 --> FT will break
                                              |        m_handle_packet() --> [break] --> EEE002 --> FT will break
                                              |          [OK] --> all good from here on
                                              |        

```

## toxcore changes for ftv2a

with filetransfers it can happen that the sender starts a filetransfer and the receiver accepts it, but
one of both parties now suddenly went offline. so the sender will not start the filetransfer.

we need to tell the sender that the receiver has actually received
the "file send request" and has fully processed it.

if the sender has not received the new FILECONTROL_SEND_ACK it will periodically send the PACKET_ID_FILE_SENDREQUEST again
until it actually receives a FILECONTROL_SEND_ACK or the FT gets cancelled.

solution:

add a new Filecontrol enum `FILECONTROL_SEND_ACK = 8`
add new capability `TOX_CAPABILITY_FTV2A`
and remember the filename (and some other bits)

```
sender --->                                             | ---> receiver
-------------------------------------------------------------------
tox_file_send()                                         |
  new_filesender()                                      |   
    file_sendrequest()                                  |
      write_cryptpacket_id()                            |
       network[PACKET_ID_FILE_SENDREQUEST] ->           | -> network[PACKET_ID_FILE_SENDREQUEST]
                                                        | <- network[-ACK-]
                                                        |      [-OFFLINE-] --> EEE001 --> FT will break
                                                        |        m_handle_packet() --> [break] --> EEE002 --> FT will break
network[PACKET_ID_FILE_CONTROL:FILECONTROL_SEND_ACK] <- | <-       network[PACKET_ID_FILE_CONTROL:FILECONTROL_SEND_ACK]
                                                        |            [OK] --> all good from here on
                                                        |        
```




