# Group custom packet IDs

Group custom packets (`tox_group_send_custom_packet` and
`tox_group_send_custom_private_packet`) have no packet type of their own. So
that clients can tell their packets apart, every group custom packet starts with
a 16-bit packet ID in network byte order: `0x6677` is the bytes `66 77` at the
start of the packet. This was decided in
[#2544](https://github.com/TokTok/c-toxcore/issues/2544).

To use IDs, pick a range nobody uses and add it to the table in a pull request.
Some clients still send one-byte IDs, so a range that starts with one of those
bytes is taken whole.

| IDs               | Used by                                         |
| ----------------- | ----------------------------------------------- |
| `0x0000`–`0x03FF` | Reserved for TokTok.                            |
| `0x6677`          | zoff99: packets start with `66 77 88 11 34 35`. |
| `0x8000`–`0x90FF` | Green-Sky.                                      |
| `0xA000`–`0xA0FF` | Green-Sky.                                      |
