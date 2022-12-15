package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"net"
	"runtime/debug"
	"time"
)

func Send(handle *pcap.Handle, l ...gopacket.SerializableLayer) error {
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	buffer := gopacket.NewSerializeBuffer()
	newLayers := make([]gopacket.SerializableLayer, 0)
	for _, layers := range l {
		if layers != nil {
			newLayers = append(newLayers, layers)
		}
	}
	if err := gopacket.SerializeLayers(buffer, opts, newLayers...); err != nil {
		return err
	}
	return handle.WritePacketData(buffer.Bytes())
}

func getData(l ...gopacket.SerializableLayer) ([]byte, error) {
	opts := gopacket.SerializeOptions{
		FixLengths:       true,
		ComputeChecksums: true,
	}
	buffer := gopacket.NewSerializeBuffer()
	newLayers := make([]gopacket.SerializableLayer, 0)
	for _, layers := range l {
		if layers != nil {
			newLayers = append(newLayers, layers)
		}
	}
	if err := gopacket.SerializeLayers(buffer, opts, newLayers...); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func GetIfaceAddrMulti(iface *net.Interface) ([]net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, errors.New("can not get ip address")
	}

	var srcIP []net.IP
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				//check repeat
				okToAdd := true
				for _, temp := range srcIP {
					if CompareIPAddr(temp, ipnet.IP.To4(), 0) == 0 {
						okToAdd = false
						break
					}
				}
				if okToAdd {
					srcIP = append(srcIP, ipnet.IP.To4())
				}
			}
		}
	}

	if srcIP == nil || len(srcIP) == 0 {
		return nil, errors.New("can not get ip address")
	}

	return srcIP, nil
}

func GetIfaceAddr(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, errors.New("can not get ip address")
	}

	var srcIP net.IP
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				srcIP = ipnet.IP.To4()
				break
			}
		}
	}

	if srcIP == nil {
		return nil, errors.New("can not get ip address")
	}

	return srcIP, nil
}

func GetIfaceAddr6(iface *net.Interface) (net.IP, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, errors.New("can not get ip address")
	}

	var srcIP net.IP
	for _, address := range addrs {
		if ipnet, ok := address.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() == nil {
				srcIP = ipnet.IP
				break
			}
		}
	}

	if srcIP == nil {
		return nil, errors.New("can not get ip address")
	}

	return srcIP, nil
}

func GetGatewayAddr(iface *net.Interface, handle *pcap.Handle, gatewayIP net.IP) (net.HardwareAddr, error) {
	srcIP, err := GetIfaceAddr(iface)
	if err != nil {
		return nil, errors.New("can not get ip address")
	}

	start := time.Now()
	// Prepare the layers to send for an ARP request.
	eth := layers.Ethernet{
		SrcMAC:       iface.HardwareAddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte(iface.HardwareAddr),
		SourceProtAddress: []byte(srcIP),
		DstHwAddress:      []byte{0, 0, 0, 0, 0, 0},
		DstProtAddress:    []byte(gatewayIP),
	}
	// Send a single ARP request packet (we never retry a send, since this
	// is just an example ;)
	if err := Send(handle, &eth, &arp); err != nil {
		return nil, err
	}
	// Wait 3 seconds for an ARP reply.
	for {
		if time.Since(start) > time.Second*3 {
			return nil, errors.New("timeout getting ARP reply")
		}
		data, _, err := handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		} else if err != nil {
			return nil, err
		}
		packet := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)
		if arpLayer := packet.Layer(layers.LayerTypeARP); arpLayer != nil {
			arp := arpLayer.(*layers.ARP)
			//Logger().Debugw("arp", "ip", gatewayIP)
			if net.IP(arp.SourceProtAddress).Equal(net.IP(gatewayIP)) {
				return net.HardwareAddr(arp.SourceHwAddress), nil
			}
		}
	}
}

func IncreaseIPAddr(ip net.IP, delta uint32) {
	if CheckIPv6(ip) {
		IncreaseIPv6Addr(ip, delta, 0)
	} else {
		IncreaseIPv4Addr(ip, delta)
	}
}

//i should be 0 when init
//bug: 0xffff->0x0000
func IncreaseIPv6Addr(ip net.IP, delta uint32, i uint) {
	temp := binary.BigEndian.Uint32(ip[12-i*4 : 16-i*4])
	newtemp := temp + delta
	binary.BigEndian.PutUint32(ip[12-i*4:16-i*4], newtemp)
	if newtemp <= temp && delta != 0 {
		IncreaseIPv6Addr(ip, 1, i+1)
	}
}

//bug: 0xffff->0x0000
func IncreaseIPv4Addr(ip net.IP, delta uint32) {
	temp := binary.BigEndian.Uint32(ip.To4())
	newtemp := temp + delta
	binary.BigEndian.PutUint32(ip, newtemp)
}

func GetIPLayer(srcIP net.IP, dstIP net.IP, swap bool, fl uint32, nextHeader layers.IPProtocol) gopacket.SerializableLayer {
	return GetIPLayerWithTTL(srcIP, dstIP, swap, fl, nextHeader, 100)
}

func GetIPLayerWithTTL(srcIP net.IP, dstIP net.IP, swap bool, fl uint32, nextHeader layers.IPProtocol, ttl int) gopacket.SerializableLayer {
	if CheckIPv6(dstIP) {
		if swap {
			tmp := dstIP
			dstIP = srcIP
			srcIP = tmp
		}
		if nextHeader == layers.IPProtocolICMPv4 {
			nextHeader = layers.IPProtocolICMPv6
		}
		return &layers.IPv6{
			Version:    6,
			FlowLabel:  fl,
			HopLimit:   uint8(ttl),
			SrcIP:      srcIP,
			DstIP:      dstIP,
			NextHeader: nextHeader,
		}
	} else {
		if swap {
			tmp := dstIP
			dstIP = srcIP
			srcIP = tmp
		}
		if nextHeader == layers.IPProtocolICMPv6 {
			nextHeader = layers.IPProtocolICMPv4
		}
		return &layers.IPv4{
			Version:  4,
			Id:       uint16(fl),
			TTL:      uint8(ttl),
			Protocol: nextHeader,
			SrcIP:    srcIP,
			DstIP:    dstIP,
		}
	}
}

func GetUDPLayer(srcPort layers.UDPPort, dstPort layers.UDPPort) layers.UDP {
	return layers.UDP{
		SrcPort: srcPort,
		DstPort: dstPort,
	}
}

func GetICMPTimeExceededLayer(v6 bool) (gopacket.SerializableLayer, gopacket.SerializableLayer) {
	if v6 {
		return &layers.ICMPv6{
			TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeTimeExceeded, layers.ICMPv6CodeHopLimitExceeded),
		}, nil
	} else {
		return &layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeTimeExceeded, layers.ICMPv4CodeTTLExceeded),
		}, nil
	}
}

func GetICMPPkt2BigLayer(pmtu uint16, v6 bool) (gopacket.SerializableLayer, gopacket.SerializableLayer) {
	if v6 {
		return &layers.ICMPv6{
				TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypePacketTooBig, 0),
			}, &layers.ICMPv6Echo{
				Identifier: 0,
				SeqNumber:  pmtu,
			}
	} else {
		return &layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodeFragmentationNeeded),
			Seq:      pmtu,
		}, nil
	}
}

func GetICMPPingLayer(identifier uint16, seqNumber uint16, v6 bool) (gopacket.SerializableLayer, gopacket.SerializableLayer) {
	if v6 {
		return &layers.ICMPv6{
				TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoRequest, 0),
			}, &layers.ICMPv6Echo{
				Identifier: identifier,
				SeqNumber:  seqNumber,
			}
	} else {
		return &layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoRequest, 0),
			Id:       identifier,
			Seq:      seqNumber,
		}, nil
	}
}

func GetICMPPingReplyLayer(identifier uint16, seqNumber uint16, v6 bool) (gopacket.SerializableLayer, gopacket.SerializableLayer) {
	if v6 {
		return &layers.ICMPv6{
				TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeEchoReply, 0),
			}, &layers.ICMPv6Echo{
				Identifier: identifier,
				SeqNumber:  seqNumber,
			}
	} else {
		return &layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeEchoReply, 0),
			Id:       identifier,
			Seq:      seqNumber,
		}, nil
	}
}

func GetICMPUnreachableLayer(v6 bool) (gopacket.SerializableLayer, gopacket.SerializableLayer) {
	if v6 {
		return &layers.ICMPv6{
				TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeDestinationUnreachable, layers.ICMPv6CodePortUnreachable),
			}, &layers.ICMPv6Echo{
				Identifier: 0,
				SeqNumber:  0,
			}
	} else {
		return &layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeDestinationUnreachable, layers.ICMPv4CodePort),
		}, nil
	}
}

func XmitUDP(h *pcap.Handle, ethernet *layers.Ethernet, ipLayer gopacket.SerializableLayer, UDPLayer *layers.UDP, data gopacket.SerializableLayer, delay uint) {
	ipLayer6, ok := ipLayer.(*layers.IPv6)
	if ok {
		err := UDPLayer.SetNetworkLayerForChecksum(ipLayer6)
		if err != nil {
			fmt.Println("xmitUDP6:", err)
			debug.PrintStack()
		}
		err = Send(h, ethernet, ipLayer, UDPLayer, data)
		if err != nil {
			fmt.Println("xmitUDP6:", err)
			debug.PrintStack()
		}

	} else {
		err := UDPLayer.SetNetworkLayerForChecksum(ipLayer.(*layers.IPv4))
		if err != nil {
			fmt.Println("xmitUDP4:", err)
			debug.PrintStack()
		}
		err = Send(h, ethernet, ipLayer, UDPLayer, data)
		if err != nil {
			fmt.Println("xmitUDP4:", err)
			debug.PrintStack()
		}
	}
	if delay != 0 {
		time.Sleep(time.Duration(delay) * time.Nanosecond)
	}
}

func XmitICMP(h *pcap.Handle, ethernet *layers.Ethernet, outIPLayer gopacket.SerializableLayer, ICMPLayer0 gopacket.SerializableLayer, ICMPLayer1 gopacket.SerializableLayer, innerIPLayer gopacket.SerializableLayer, innerLayer0 gopacket.SerializableLayer, innerLayer1 gopacket.SerializableLayer, data []byte, delay uint) {
	outIPLayer6, ok := outIPLayer.(*layers.IPv6)
	if ok {
		err := ICMPLayer0.(*layers.ICMPv6).SetNetworkLayerForChecksum(outIPLayer6)
		if err != nil {
			fmt.Println("xmitICMPv6:", err)
			debug.PrintStack()
			return
		}
		if innerIPLayer != nil && innerLayer0 != nil {
			if innerIPLayer.(*layers.IPv6).NextHeader == layers.IPProtocolUDP {
				err = innerLayer0.(*layers.UDP).SetNetworkLayerForChecksum(innerIPLayer.(*layers.IPv6))
			} else if innerIPLayer.(*layers.IPv6).NextHeader == layers.IPProtocolICMPv6 {
				err = innerLayer0.(*layers.ICMPv6).SetNetworkLayerForChecksum(innerIPLayer.(*layers.IPv6))
			}
			if err != nil {
				fmt.Println("xmitICMPv6:", err)
				debug.PrintStack()
				return
			}
			err = Send(h, ethernet, outIPLayer, ICMPLayer0, ICMPLayer1, innerIPLayer, innerLayer0, innerLayer1, gopacket.Payload(data))
			if err != nil {
				fmt.Println("xmitICMPv6:", err)
				debug.PrintStack()
				return
			}
		} else {
			err = Send(h, ethernet, outIPLayer, ICMPLayer0, ICMPLayer1, gopacket.Payload(data))
			if err != nil {
				fmt.Println("xmitICMPv6:", err)
				debug.PrintStack()
				return
			}
		}
	} else {
		var err error = nil
		if innerIPLayer != nil && innerLayer0 != nil {
			if innerIPLayer.(*layers.IPv4).Protocol == layers.IPProtocolUDP {
				err = innerLayer0.(*layers.UDP).SetNetworkLayerForChecksum(innerIPLayer.(*layers.IPv4))
			}
			if err != nil {
				fmt.Println("xmitICMPv41:", err)
				debug.PrintStack()
				return
			}
			err = Send(h, ethernet, outIPLayer, ICMPLayer0, ICMPLayer1, innerIPLayer, innerLayer0, innerLayer1, gopacket.Payload(data))
			if err != nil {
				fmt.Println("xmitICMPv42:", err)
				debug.PrintStack()
				return
			}
		} else {
			err = Send(h, ethernet, outIPLayer, ICMPLayer0, ICMPLayer1, gopacket.Payload(data))
			if err != nil {
				fmt.Println("xmitICMPv43:", err)
				debug.PrintStack()
				return
			}
		}
	}
	if delay != 0 {
		time.Sleep(time.Duration(delay) * time.Microsecond)
	}
}

/* TODO: buggy, len of the outer IPv6 header is incorrect. */
func XmitICMP_redirect(h *pcap.Handle, ethernet *layers.Ethernet, outIPLayer gopacket.SerializableLayer, ICMPLayer0 gopacket.SerializableLayer, ICMPLayer1 gopacket.SerializableLayer, innerIPLayer gopacket.SerializableLayer, innerLayer0 gopacket.SerializableLayer, innerLayer1 gopacket.SerializableLayer, data []byte, delay uint) {
	outIPLayer6, ok := outIPLayer.(*layers.IPv6)
	if ok {
		err := ICMPLayer0.(*layers.ICMPv6).SetNetworkLayerForChecksum(outIPLayer6)
		if err != nil {
			fmt.Println("xmitICMPv6:", err)
			return
		}
		var innerData []byte
		if innerIPLayer != nil && innerLayer0 != nil {
			if innerIPLayer.(*layers.IPv6).NextHeader == layers.IPProtocolUDP {
				err = innerLayer0.(*layers.UDP).SetNetworkLayerForChecksum(innerIPLayer.(*layers.IPv6))
			} else if innerIPLayer.(*layers.IPv6).NextHeader == layers.IPProtocolICMPv6 {
				err = innerLayer0.(*layers.ICMPv6).SetNetworkLayerForChecksum(innerIPLayer.(*layers.IPv6))
			}
			if err != nil {
				fmt.Println("xmitICMPv6:", err)
				return
			}
			innerData, err = getData(innerIPLayer, innerLayer0, innerLayer1, gopacket.Payload(data))
			if err != nil {
				fmt.Println("xmitICMPv6:", err)
				return
			}
		} else {
			innerData, err = getData(gopacket.Payload(data))
			if err != nil {
				fmt.Println("xmitICMPv6:", err)
				return
			}
		}
		writeInnerData := true
		if ICMPLayer0.(*layers.ICMPv6).TypeCode.Type() == layers.ICMPv6TypeRedirect {
			// fix data len and reserved area
			rem := len(innerData) % 8
			for i := 0; i < rem; i++ {
				innerData = append(innerData, 0)
			}
			tmpLen := []byte{0, 0, 0, 0, 0, 0}
			innerData = append(tmpLen, innerData...)
			ICMPLayer1.(*layers.ICMPv6Redirect).Options[0].Data = innerData
			writeInnerData = false
		}
		outerData, err := getData(ethernet, outIPLayer, ICMPLayer0, ICMPLayer1)
		if err != nil {
			fmt.Println("xmitICMPv6:", err)
			return
		}
		if writeInnerData {
			err = h.WritePacketData(append(outerData, innerData...))
		} else {
			err = h.WritePacketData(outerData)
		}
		if err != nil {
			fmt.Println("xmitICMPv6:", err)
			return
		}
	} else {
		var err error = nil
		if innerIPLayer != nil && innerLayer0 != nil {
			if innerIPLayer.(*layers.IPv4).Protocol == layers.IPProtocolUDP {
				err = innerLayer0.(*layers.UDP).SetNetworkLayerForChecksum(innerIPLayer.(*layers.IPv6))
			}
			if err != nil {
				fmt.Println("xmitICMPv4:", err)
				return
			}
			err = Send(h, ethernet, outIPLayer, ICMPLayer0, ICMPLayer1, innerIPLayer, innerLayer0, innerLayer1, gopacket.Payload(data))
			if err != nil {
				fmt.Println("xmitICMPv4:", err)
				return
			}
		} else {
			err = Send(h, ethernet, outIPLayer, ICMPLayer0, ICMPLayer1, gopacket.Payload(data))
			if err != nil {
				fmt.Println("xmitICMPv4:", err)
				return
			}
		}
	}
	if delay != 0 {
		time.Sleep(time.Duration(delay) * time.Microsecond)
	}
}

func GetDNSQuery(txid uint16, name string) layers.DNS {
	return layers.DNS{
		ID:           txid,
		QR:           false,
		OpCode:       0,
		AA:           false,
		TC:           false,
		RD:           true,
		RA:           false,
		Z:            0,
		ResponseCode: 0,
		QDCount:      1,
		ANCount:      0,
		NSCount:      0,
		ARCount:      0,
		Questions: []layers.DNSQuestion{{
			Name:  []byte(name),
			Type:  layers.DNSTypeA,
			Class: layers.DNSClassIN,
		}},
		Authorities: nil,
		Additionals: nil,
	}
}

func GetDNSResponse(txid uint16, tc bool, questions []layers.DNSQuestion, answers []layers.DNSResourceRecord) layers.DNS {
	return layers.DNS{
		ID:           txid,
		QR:           true,
		OpCode:       0,
		AA:           true,
		TC:           tc,
		RA:           false,
		Z:            0,
		ResponseCode: 0,
		QDCount:      1,
		ANCount:      0,
		NSCount:      0,
		ARCount:      0,
		Questions:    questions,
		Answers:      answers,
		Authorities:  nil,
		Additionals:  nil,
	}
}

func CheckIPv6(ip net.IP) bool {
	if ip.To4() == nil {
		return true
	} else {
		ip = ip.To4()
		return false
	}
}

//i should be 0 when init
func CompareIPAddr(ip0 net.IP, ip1 net.IP, i uint) int {
	if ip0 == nil || ip1 == nil {
		return -2
	}
	if CheckIPv6(ip0) && CheckIPv6(ip1) {
		temp0 := binary.LittleEndian.Uint32(ip0[i*4 : (i+1)*4])
		temp1 := binary.LittleEndian.Uint32(ip1[i*4 : (i+1)*4])
		if temp0 == temp1 {
			if i != 3 {
				return CompareIPAddr(ip0, ip1, i+1)
			}
			return 0
		}
		if temp0 > temp1 {
			return 1
		}
		return -1
	} else if !CheckIPv6(ip0) && !CheckIPv6(ip1) {
		temp0 := binary.LittleEndian.Uint32(ip0.To4())
		temp1 := binary.LittleEndian.Uint32(ip1.To4())
		if temp0 == temp1 {
			return 0
		}
		if temp0 > temp1 {
			return 1
		}
		return -1
	}
	return -2
}

func ExtractTCPPacket(packet *gopacket.Packet) uint16 {
	if rspTCPLayer := (*packet).Layer(layers.LayerTypeTCP); rspTCPLayer != nil {
		if rspTCP := rspTCPLayer.(*layers.TCP); rspTCP != nil {
			if rspTCP.SYN {
				if rspTCP.Options != nil && len(rspTCP.Options) > 0 {
					for _, option := range rspTCP.Options {
						if option.OptionType == layers.TCPOptionKindMSS {
							var retval uint16
							retval |= uint16(option.OptionData[0]) << 8
							retval |= uint16(option.OptionData[1])
							return retval
						}
					}
				}
			}
		}
	}
	return 0xffff
}

func ExtractFragment(packet *gopacket.Packet) (uint16, uint16, bool, layers.IPProtocol, []byte) {
	if rspIPLayer := (*packet).Layer(layers.LayerTypeIPv4); rspIPLayer != nil {
		if rspIP := rspIPLayer.(*layers.IPv4); rspIP != nil {
			return rspIP.Id, rspIP.FragOffset, rspIP.Flags&layers.IPv4MoreFragments != 0, rspIP.Protocol, rspIP.Payload
		}
	} else if rspFragLayer := (*packet).Layer(layers.LayerTypeIPv6Fragment); rspFragLayer != nil {
		if rspFrag := rspFragLayer.(*layers.IPv6Fragment); rspFrag != nil {
			return uint16(rspFrag.Identification), rspFrag.FragmentOffset, rspFrag.MoreFragments, rspFrag.NextHeader, rspFrag.Payload
		}
	}
	return 0xffff, 0xffff, false, 0xff, nil
}

func ExtractIPPacket(packet *gopacket.Packet) (net.IP, net.IP, uint16, uint16, layers.IPProtocol) {
	if rspNet := (*packet).NetworkLayer(); rspNet == nil {
		return nil, nil, 0, 0, 0xff
	} else {
		var srcIP net.IP
		var dstIP net.IP
		var ipid uint16
		var length uint16
		var rspIPLayer gopacket.Layer
		var nextHeader layers.IPProtocol

		if rspIPLayer = (*packet).Layer(layers.LayerTypeIPv4); rspIPLayer != nil {
			if rspIP := rspIPLayer.(*layers.IPv4); rspIP != nil {
				srcIP = rspIP.SrcIP
				dstIP = rspIP.DstIP
				ipid = rspIP.Id
				length = rspIP.Length
				nextHeader = rspIP.Protocol
				if rspIP.Flags&layers.IPv4MoreFragments != 0 || rspIP.FragOffset != 0 {
					nextHeader = layers.IPProtocolIPv6Fragment
				}
				return srcIP, dstIP, ipid, length, nextHeader
			}
		} else if rspIPLayer = (*packet).Layer(layers.LayerTypeIPv6); rspIPLayer != nil {
			if rspIP6 := rspIPLayer.(*layers.IPv6); rspIP6 != nil {
				srcIP = rspIP6.SrcIP
				dstIP = rspIP6.DstIP
				ipid = uint16(rspIP6.FlowLabel)
				length = rspIP6.Length + 40
				nextHeader = rspIP6.NextHeader
				return srcIP, dstIP, ipid, length, nextHeader
			}
		}
	}
	return nil, nil, 0, 0, 0xff
}

func ExtractDNSPacket(packet *gopacket.Packet) (uint16, bool, *layers.DNS) {
	rspDNSLayer := (*packet).Layer(layers.LayerTypeDNS)
	if rspDNSLayer == nil {
		return 0xffff, false, nil
	}
	rspDNS := rspDNSLayer.(*layers.DNS)
	if rspDNS == nil {
		return 0xffff, false, nil
	}
	if rspDNS.Questions == nil || len(rspDNS.Questions) < 1 || rspDNS.Questions[0].Name == nil || len(rspDNS.Questions[0].Name) < 15 {
		return 0xffff, false, nil
	}
	return rspDNS.ID, rspDNS.QR, rspDNS
}

func ExtractUDPPacket(packet *gopacket.Packet) (layers.UDPPort, layers.UDPPort, uint16) {
	if rspTP := (*packet).TransportLayer(); rspTP == nil {
		return 0, 0, 0xffff
	} else {
		if rspUDPLayer := (*packet).Layer(layers.LayerTypeUDP); rspUDPLayer != nil {
			if rspUDP := rspUDPLayer.(*layers.UDP); rspUDP != nil {
				return rspUDP.SrcPort, rspUDP.DstPort, rspUDP.Length
			}
		}
		return 0, 0, 0xffff
	}
}

func ExtractICMPPacket(packet *gopacket.Packet) (uint8, uint8, uint16, uint16, gopacket.Packet) {
	var _type uint8
	var _code uint8
	var _id uint16
	var _seq uint16
	var innerPacket gopacket.Packet

	if rspICMPLayer := (*packet).Layer(layers.LayerTypeICMPv4); rspICMPLayer != nil {
		if rspICMP := rspICMPLayer.(*layers.ICMPv4); rspICMP != nil {
			_type = rspICMP.TypeCode.Type()
			_code = rspICMP.TypeCode.Code()
			_id = rspICMP.Id
			_seq = rspICMP.Seq
			innerPacket = gopacket.NewPacket(rspICMP.Payload, layers.LayerTypeIPv4, gopacket.NoCopy)
			return _type, _code, _id, _seq, innerPacket
		}
	} else if rspICMP6Layer := (*packet).Layer(layers.LayerTypeICMPv6); rspICMP6Layer != nil {
		if rspICMP6 := rspICMP6Layer.(*layers.ICMPv6); rspICMP6 != nil {
			_type = rspICMP6.TypeCode.Type()
			_code = rspICMP6.TypeCode.Code()
			innerPacket = gopacket.NewPacket(rspICMP6.Payload[4:], layers.LayerTypeIPv6, gopacket.NoCopy)
			if rspPING6Layer := (*packet).Layer(layers.LayerTypeICMPv6Echo); rspPING6Layer != nil {
				if rspPING6 := rspPING6Layer.(*layers.ICMPv6Echo); rspPING6 != nil {
					_seq = rspPING6.SeqNumber
					_id = rspPING6.Identifier
					return _type, _code, _id, _seq, innerPacket
				}
			}
			return _type, _code, 0xffff, 0xffff, innerPacket
		}
	}
	return 0xff, 0xff, 0xffff, 0xffff, nil
}

func SendToUs(packet *gopacket.Packet, dstmac net.HardwareAddr) bool {
	if rspEthLayer := (*packet).Layer(layers.LayerTypeEthernet); rspEthLayer != nil {
		if rspEth := rspEthLayer.(*layers.Ethernet); rspEth != nil {
			for i := 0; i < 6; i++ {
				if dstmac[i] != rspEth.DstMAC[i] {
					return false
				}
			}
			return true
		}
	}
	return false
}

func SendByUs(packet *gopacket.Packet, srcmac net.HardwareAddr) bool {
	if rspEthLayer := (*packet).Layer(layers.LayerTypeEthernet); rspEthLayer != nil {
		if rspEth := rspEthLayer.(*layers.Ethernet); rspEth != nil {
			for i := 0; i < 6; i++ {
				if srcmac[i] != rspEth.SrcMAC[i] {
					return false
				}
			}
			return true
		}
	}
	return false
}

func ExtractMacPacket(packet *gopacket.Packet) (net.HardwareAddr, net.HardwareAddr) {
	if rspEthLayer := (*packet).Layer(layers.LayerTypeEthernet); rspEthLayer != nil {
		if rspEth := rspEthLayer.(*layers.Ethernet); rspEth != nil {
			return rspEth.SrcMAC, rspEth.DstMAC
		}
	}
	return nil, nil
}

func GetICMPRedirectLayer(tgt net.IP, dst net.IP, v6 bool) (gopacket.SerializableLayer, gopacket.SerializableLayer) {
	if v6 {
		return &layers.ICMPv6{
				TypeCode: layers.CreateICMPv6TypeCode(layers.ICMPv6TypeRedirect, 0),
			}, &layers.ICMPv6Redirect{
				TargetAddress:      tgt,
				DestinationAddress: dst,
				Options: layers.ICMPv6Options{layers.ICMPv6Option{
					Type: layers.ICMPv6OptRedirectedHeader,
					Data: nil,
				}},
			}
	} else {
		tgt = tgt.To4()
		return &layers.ICMPv4{
			TypeCode: layers.CreateICMPv4TypeCode(layers.ICMPv4TypeRedirect, 1),
			Id:       uint16(tgt[0])<<8 | uint16(tgt[1]),
			Seq:      uint16(tgt[2])<<8 | uint16(tgt[3]),
		}, nil
	}
}
