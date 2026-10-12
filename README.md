# DVReflectors
This repo contains the reflectors originally from G4KLX's NXDNClients, P25Clients, and YSFClients repositories.

The NXDN and P25 reflectors are used as a single talkgroup. The NXDN reflector also includes the option to link it to NXCore to allow for interchange of audio between the two. At the NXCore end, it should be set up to receive the traffic from only one talk group.

They build on 32-bit and 64-bit Linux as well as on Windows using Visual Studio 2017 on x86 and x64.

## Building

```
make                  # all three reflectors
make YSFReflector     # or NXDNReflector, P25Reflector
sudo make install     # to /usr/local/bin
make clean
```

## Block List

All three reflectors take a block list:

```
[Block List]
File=BlockList.txt
Time=5
```

- Each reflector has a `blocklist.example` to start from.
- One callsign or Id per line. `#` comments, blank lines and anything after the first word are ignored.
- Re-read every `Time` minutes; changes apply without a restart.
- Blocks by station: `M1AB` blocks `M1AB-ND`, `M1AB-RPT`, `M1AB/P` and `DL/M1AB`, not `M1ABC`. A full entry like `M1AB-ND` blocks just that callsign.
- `*` ends a prefix, as in XLXd: `LX*` blocks every callsign starting `LX`, `*` blocks everyone. An `xlxd.blacklist` can be shared as-is.
- Blocks users and nodes. A blocked node can't link, and is dropped if already linked.
- NXDN and P25: a callsign blocks every Id registered to it in the Id lookup file. Ids can be listed directly too, and wildcards match Ids as well (`235*`).

## Loop Detection

Built in, same rules as XLXd. Three short (<1s) transmissions in quick succession from the same user is a strike:

| Strike | Penalty |
|---|---|
| 1 | User and node blocked for 3s |
| 2 | Blocked for 10s |
| 3 | Blocked for 300s, node removed and barred from linking |

Strikes decay after 300s clean. Blocks cover the whole station, users and nodes alike.

This software is licenced under the GPL v2 and is primarily intended for amateur and educational use.
