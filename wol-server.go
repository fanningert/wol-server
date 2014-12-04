package main

import (
	"fmt"
	"log"
	"net"
)

func main() {
	//etherWake("14:da:e9:de:d5:82")
	for {
		checkHost()
	}
}

// extracts the payload from an ipv4 packet
func extractPayload(b []byte) []byte {
	// IP Header has 20 bytes
	if len(b) < 20 {
		return b
	}
	headerLength := int(b[0]&0x0f) << 2
	return b[headerLength:]
}

// checks if the Host is alive after we've sent a
// magic packet
// also this is currently an utter mess
func checkHost( /*host string*/ ) bool {

	// from here on we want to receive the icmp echo reply
	icmpIn := make([]byte, 512)
	icmpOobIn := make([]byte, 512)
	success := false
	icmpr, err := net.ListenIP("ip4:icmp", nil)
	if err != nil {
		log.Println("I only received death:", err)
	}

	_, _, _, remoteAddress, err := icmpr.ReadMsgIP(icmpIn, icmpOobIn)

	if err != nil {
		log.Fatalln("Ich verreckte... weil:", err)
	}

	/*
		payLoad := extractPayload(icmpIn)

		fmt.Println("Type:", payLoad[0])
		fmt.Println("Code:", payLoad[1])
		fmt.Println("Checksum:", int(payLoad[2])<<8|int(payLoad[3]))
		fmt.Println("Identifier:", int(payLoad[4])<<8|int(payLoad[5]))
		fmt.Println("Sequence Number:", int(payLoad[6])<<8|int(payLoad[7]))
		//fmt.Println("Header data:", payLoad[8:])
	*/
	fmt.Println("pong from:", remoteAddress)
	return success
}

// sends a magic packet to a given MAC-Address
// this is a pretty basic implementation of WOL
// no support for directed broadcasts etc
func etherWake(hostMAC string) {
	magicPacket := make([]byte, 102)
	macAddress, err := net.ParseMAC(hostMAC)

	// filling the first part of the magic packet with
	// FF (6 bytes)
	currentByte := 0
	for ; currentByte < 6; currentByte++ {
		magicPacket[currentByte] = 255
	}

	// fill the rest of the 102 bytes with the MAC (16 times)
	for k := 0; k < 16; k++ {
		for j := range macAddress {
			magicPacket[currentByte] = macAddress[j]
			currentByte++
		}
	}

	// open a socket towards the broadcast address
	broadcastIPv4 := net.IPv4(255, 255, 255, 255)
	socket, err := net.DialUDP("udp4", nil, &net.UDPAddr{
		IP:   broadcastIPv4,
		Port: 7,
	})

	if err != nil {
		log.Fatal("OMG is br0k:", err)
	}

	packetLength, err := socket.Write(magicPacket)
	if err != nil {
		log.Fatal("OMG", err)
	}
	if packetLength != 102 {
		log.Println("Weird, packet length not the expected 102: ", packetLength)
	}

	fmt.Println("Sent wol magic packet for: ", macAddress)
}
