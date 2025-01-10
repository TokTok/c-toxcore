#### Recommended Tox Clients

<a href="https://github.com/Zoxcore/trifa_material/releases"><img src="https://github.com/Zoxcore/trifa_material/releases/download/nightly/screenshot-macos.png" height="200"></a>
<a href="https://f-droid.org/app/com.zoffcc.applications.trifa"><img src="https://raw.githubusercontent.com/zoff99/ToxAndroidRefImpl/zoff99/dev003/doc/mockup_004a.png" height="200">


#### by some random twist of fate you stumbled into the Department of Science of Tox-University

[![CircleCI](https://circleci.com/gh/zoff99/c-toxcore/tree/zoff99%2Fzoxcore_local_fork.png?style=badge)](https://circleci.com/gh/zoff99/c-toxcore/tree/zoff99%2Fzoxcore_local_fork)
[![Android CI](https://github.com/zoff99/c-toxcore/workflows/github_build/badge.svg)](https://github.com/zoff99/c-toxcore/actions?query=workflow%3A%22github_build%22)
[![License: GPL v3](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0.en.html)

some of the subjects we are teaching here are:<br><br>

- [x] Video enchancements
- [x] Audio enchancements
- [x] H264 Codec
- [x] HW accelerated de-/en-coding on Raspberry Pi
- [x] HW accelerated de-/en-coding on Android (with [TRIfA](https://github.com/zoff99/ToxAndroidRefImpl))
- [x] HW accelerated de-/en-coding on Linux (with uTox and [qTox_enhanced](https://github.com/Zoxcore/qTox_enhanced))
- [x] Message V2 (see: https://github.com/zoff99/c-toxcore/blob/zoff99/zoxcore_local_fork/docs/message_v2.md) (see: https://github.com/TokTok/c-toxcore/issues/735)
- [x] Message V3 (see: https://github.com/zoff99/c-toxcore/blob/zoff99/zoxcore_local_fork/docs/msgv3_addon.patch)
- [x] automatic Video bandwith control
- [x] additional threads for A/V
- [x] Tox - Custom Packets Registry (see: https://github.com/zoff99/toxcore_custom_packets_registry)
- [x] fix some thread safety issues (see: https://github.com/TokTok/c-toxcore/issues/956) (https://github.com/TokTok/c-toxcore/issues/854) (https://github.com/TokTok/c-toxcore/issues/871) (https://github.com/TokTok/c-toxcore/issues/1257)
- [x] make Toxcore API thread safe (see: https://github.com/TokTok/c-toxcore/pull/1382)
- [x] make ToxAV use only public Tox API functions (see: https://github.com/TokTok/c-toxcore/pull/1431) (https://github.com/TokTok/c-toxcore/pull/2651)
- [ ] ~~resumable Filetransfers, even across restarts (inside c-toxcore)~~ [was removed in favor of Filetransfers V2]
- [x] Filetransfers V2, resumeable when connection is lost. does not survive client restarts (see: https://github.com/zoff99/c-toxcore/blob/zoff99/zoxcore_local_fork/docs/filetransfer_v2.md)
- [x] Push Message Support (with TRIfA on Android, Antidote on iPhone and with [qTox_enhanced](https://github.com/Zoxcore/qTox_enhanced))
- [x] New Group Chats - NGC. with IRC like features (see: https://github.com/TokTok/c-toxcore/pull/2269)
- [x] Filetransfers in NGC Groups (see: https://github.com/zoff99/c-toxcore/blob/zoff99/zoxcore_local_fork/docs/ngc_filetransfer.md)
- [x] Sync History in NGC Groups (see: https://github.com/zoff99/c-toxcore/blob/zoff99/zoxcore_local_fork/docs/ngc_group_history_sync.md)
- [x] own default peername in NGC Groups (see: https://github.com/zoff99/c-toxcore/blob/zoff99/zoxcore_local_fork/docs/ngc_usernames_spec.md)
- [x] fix wrong self connection status when only connected to LAN (see: https://github.com/zoff99/c-toxcore/commit/6e1c0a24b0c74575a6a23d264f41493425424e34)
- [x] Video in NGC Groups (see: https://github.com/zoff99/c-toxcore/blob/zoff99/zoxcore_local_fork/docs/ngc_video_v2.md)
- [x] Audio in NGC Groups (see: https://github.com/zoff99/c-toxcore/blob/zoff99/zoxcore_local_fork/docs/ngc_audio.md)

<br>
Any use of this project's code by GitHub Copilot, past or present, is done
without our permission.  We do not consent to GitHub's use of this project's
code in Copilot.
<br>
No part of this work may be used or reproduced in any manner for the purpose of training artificial intelligence technologies or systems.

