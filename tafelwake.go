package main

import (
	"fmt"
	"log"
	"net"
)

func main() {
	etherWake("14:da:e9:de:d5:82")
}

// checks if the Host is alive after we've sent a
// magic packet
func checkHost(host net.IP) bool {
	success := false

	return success
}

// sends a magic packet to a given MAC-Address
func etherWake(host string) {
	magicPacket := make([]byte, 102)
	macAddress, err := net.ParseMAC(host)

	// filling the first part of the magic packet with
	// the payload
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
		log.Fatal("OMG", err)
	}

	packetLength, err := socket.Write(magicPacket)
	if packetLength != 102 {
		log.Fatal("Ooops, packet is not 102 bytes long:", packetLength)
	}

	if err != nil {
		log.Fatal("OMG", err)
	}

	fmt.Println("Sent wol magic packet for: ", macAddress)
}
