package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
)

var ident int

type icmpMsg struct {
	Type, Code                       uint8
	Checksum, Identifier, SequenceNo uint16
}

type host struct {
	name      string
	ip        string
	hwaddress string
}

func init() {
	ident = os.Getpid()
}

func main() {
	host := &host{"tafelrundeTest", "141.70.126.1", "14:da:e9:de:d5:82"}
	etherWake(host.hwaddress)
	checkHost(host.ip)
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

	// send the packet to the wire
	packetLength, err := socket.Write(magicPacket)
	if err != nil {
		log.Fatal("OMG", err)
	}
	if packetLength != 102 {
		log.Println("Weird, packet length not the expected 102: ", packetLength)
	}

	fmt.Println("Sent wol magic packet for: ", macAddress)
}

func checksum(packet []byte) uint16 {
	length := len(packet)
	var index int
	var sum uint32
	for length > 1 {
		sum += uint32(packet[index])<<8 + uint32(packet[index+1])
		index += 2
		length -= 2
	}
	if length > 0 {
		sum += uint32(packet[index])
	}
	// calculate the 17th bit, add it back into the LSb
	sum += (sum >> 16)
	return uint16(^sum)
}

// fetches the payload from an ipv4 packet
func getPayload(b []byte) []byte {
	// IP Header should have 20 bytes
	if len(b) < 20 {
		return b
	}
	headerLength := int(b[0]&0x0f) << 2

	return b[headerLength:]
}
func getICMPHeader(b []byte) []byte {
	return b[20:28]
}

func buildICMPEchoRequest(id, seq, length int) []byte {
	var buffer bytes.Buffer
	var packet icmpMsg
	var err error

	packet.SequenceNo = uint16(seq)
	packet.Identifier = uint16(id)
	packet.Type = 8
	packet.Code = 0

	if err = binary.Write(&buffer, binary.BigEndian, packet); err != nil {
		log.Fatalln("Error writing packet to buffer:", err)
	}
	packet.Checksum = checksum(buffer.Bytes())
	buffer.Reset()
	if err = binary.Write(&buffer, binary.BigEndian, packet); err != nil {
		log.Fatalln("Error writing packet to buffer:", err)
	}

	return buffer.Bytes()
}

// checks if the Host is alive after we've sent a
// magic packet
func checkHost(host string) bool {
	success := false
	var err error
	var connection net.Conn

	send := buildICMPEchoRequest(ident&0xffff, 1, 64)

	//icmps, err := net.DialIP("ip4:icmp", nil, raddr)
	connection, err = net.Dial("ip4:icmp", host)
	_, err = connection.Write(send)
	if err != nil {
		log.Fatalln("Fuck:", err)
	}
	fmt.Println("ping:", host)
	fmt.Println("sent ID:", int(send[4])<<8|int(send[5]))

	// from here on we want to receive the icmp echo reply
	icmpReply := make([]byte, 64)
	_, err = connection.Read(icmpReply)

	recv := getPayload(icmpReply)

	fmt.Println("received ID:", int(recv[4])<<8|int(recv[5]))
	fmt.Println("pong:", host)
	return success
}
