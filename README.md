# SADDNS2.0: DNS Cache Poisoning Attack: Resurrections with Side Channels

## Introduction
**SADDNS2.0** is a tool for launching the **DNS cache poisoning attack**. It infers the ephemeral port number and brute forces the TxID by exploiting ***F**orwarding Information Base(FIB) **N**ext **H**op **E**xception(FNHE)* cache as a side channel.

This is a different side channel cache poisoning attack derived from [SADDNS](https://github.com/seclab-ucr/SADDNS). Most code usage may remain the same. 

## How it works
1. Scan ephemeral ports opened by the resolver.
2. Brute force TxID.

The side channel leverages the hash table storing fnhe entry as a shared resource (between the **spoofed** and non-spoofed IPs), which controls whether an IP packet should be fragmented or not. This gives the off-path attacker the ability to identify whether previous **spoofed** ICMP fragment needed packets were accepted or not, which further indicates whether the guessed port is correct or not.

The following figure shows the detail of inferring ephemeral ports.

![Off-path port scanning](https://www.saddns.net/attack2.svg)

### Why spoofed IP is still necessary?
- Compared with [SADDNS](https://github.com/seclab-ucr/SADDNS), SADDNS2.0 uses embedded UDP packet to scan open port and therefore no IP spoofing is needed during the scanning phase.
- IP spoofing is still required for injecting rogue responses.

## Additional resources

### Publication

[**DNS Cache Poisoning Attack: Resurrections with Side Channels**](https://doi.org/10.1145/3460120.3486219)

Keyu Man, Xin'an Zhou, Zhiyun Qian

*In Proceedings of ACM Conference on Computer and Communications Security (CCS`21), November 15-19, 2021, Virtual Event, Republic of Korea.*

### Website

[**SADDNS**](https://www.saddns.net)

## How to run

### Requirements

- An IP-spoofing-capable host (preferably Linux. Windows is ok but suffers from low performance.).
- A domain (attacker-controlled name server)
- Other things needed to make clear:
    - The resolver to poison (victim resolver)
    - The domain to poison (victim domain)
    - *The **victim domain**'s record will be poisoned on the **victim resolver**.*

### Overview

- Determine the attack type (e.g., public or private port, fragment needed or redirect packet as the payload).
- Guess the seed/key of FNHE hsah table if private port is used.
- Flood query traffic to mute the name server of the victim domain (see [SADDNS](https://github.com/seclab-ucr/SADDNS) repo for flooding scripts).
- Run attack program to guess the port number and TxID automatically.

### Steps

1. Compile

   ```go build ucr.edu/SADDNS2.0```(requires ```gopacket``` and ```libpcap```)

2. Seed guessing (only required when probing private ports)

    See the paper for details. ```GuessSeed.go``` provides methods to send out seed guessing packets. ```guessSeed4.c``` implements hash guessing functions to guess the seed.

4. Start flooding

   ```./dns_query.sh &```(requires ```hping3```)

   Please see the comment in the file for usage.

5. Start attacking (flooding is still in progress)

   ```sudo ./saddns [args]```

   Run ```./saddns -h``` for usage.

```attack.sh``` is a sample script for finish the whole PoC (both Step 2 & 3) including the verification of the poisoned result. It's a demonstrative script and please modify the code accordingly (it **won't** run by default).


## Questions and issues

Please submit them by opening a new issue.

