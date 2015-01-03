package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const (
	tlsKey = "ssl/localhost.key"
	tlsCRT = "ssl/localhost.crt"
)

var ident int
var listenPort int
var stopPing = make(chan bool)
var running bool

type icmpMsg struct {
	Type, Code                       uint8
	Checksum, Identifier, SequenceNo uint16
}

type page struct {
	Title string
	Body  []byte
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
	running = false

	pingeling := func() { checkHost(strings.TrimSpace("127.0.0.1")) }
	stopPing = pingScheduler(pingeling, 60*time.Second)

	http.HandleFunc("/", doRest)
	http.ListenAndServeTLS("localhost:443", tlsCRT, tlsKey, nil)

}

// sends a magic packet to a given MAC-Address
// this is a pretty basic implementation of WOL
// no support for directed broadcasts etc
func etherWake(hostMAC string) {
	running = true
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
	fmt.Printf("magic packet sent to: %v\n", macAddress)
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
	var err error
	var connection net.Conn
	online := false
	send := buildICMPEchoRequest((rand.Int()*ident)&0xffff, 1, 64)

	//icmps, err := net.DialIP("ip4:icmp", nil, raddr)
	connection, err = net.Dial("ip4:icmp", host)
	_, err = connection.Write(send)
	if err != nil {
		log.Fatalln("Fuck:", err)
	}
	fmt.Printf("sent ID: %v\n", int(send[4])<<8|int(send[5]))
	sending := int(send[4])<<8 | int(send[5])

	// from here on we want to receive the icmp echo reply
	icmpReply := make([]byte, 64)
	_, err = connection.Read(icmpReply)

	recv := getPayload(icmpReply)
	fmt.Printf("received ID: %v\n", int(recv[4])<<8|int(recv[5]))
	receiving := int(recv[4])<<8 | int(recv[5])

	if sending == receiving {
		online = true
	}
	return online
}

func pingScheduler(pinger func(), delay time.Duration) chan bool {
	stop := make(chan bool)
	go func() {
		for {
			pinger()
			select {
			case <-time.After(delay):
			case <-stop:
				fmt.Println("stopping pinger")
				return
			}
		}
	}()
	return stop
}

func doRest(w http.ResponseWriter, r *http.Request) {
	mac := string(r.PostFormValue("mac"))
	starter := r.PostFormValue("starter")
	stopper := r.PostFormValue("stopper")
	if mac == "" {
		mac = "FF:FF:FF:FF:FF:FF"
	}
	if starter == "start" {
		if !running {
			etherWake(mac)
		}
	}
	if stopper == "stop" {
		stopPing <- true
		running = false
	}
	p := &page{Title: "Wake on Lan Service"}
	t, _ := template.ParseFiles("assets/html/index.html")
	t.Execute(w, p)
}
