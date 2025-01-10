
# Spec for Filetransfer version 2 addon (short: ftv2a)

## how do filetransfers in tox work

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

we need to tell the sender that the receiver has actually received
the "file send request" and has fully processed it.


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




