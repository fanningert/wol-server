package main

import (
	"fmt"
	"log"
	"net"
)

type packet struct {
	bytes []byte
	addr  *net.IPAddr
}

func main() {
	etherWake("14:da:e9:de:d5:82")
	checkHost()
}

// checks if the Host is alive after we've sent a
// magic packet
// also this is currently an utter mess
func checkHost( /*host net.IP*/ ) bool {
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

	response := &packet{bytes: icmpIn, addr: remoteAddress}
	for i := 0; i < 4; i++ {
		fmt.Println(icmpIn[i])
	}

	fmt.Println(response)

	return success
}

// sends a magic packet to a given MAC-Address
// this is a pretty basic implementation of WOL
// no support for directed broadcasts etc
func etherWake(hostMAC string) {
	magicPacket := make([]byte, 102)
	macAddress, err := net.ParseMAC(host)

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

	_, err := socket.Write(magicPacket)

	if err != nil {
		log.Fatal("OMG", err)
	}

	fmt.Println("Sent wol magic packet for: ", macAddress)
}
