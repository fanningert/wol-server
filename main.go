package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"github.com/BurntSushi/toml"
	"github.com/gorilla/mux"
	"html/template"
	"log"
	"math/rand"
	"net"
	"net/http"
	//"os"
	//"runtime"
	"strings"
	"time"
)

type indexPage struct {
	Title string
	Hosts tomlConfig
}
type workstation struct {
	IP    string
	MAC   string
	Alive bool
}
type icmpMsg struct {
	Type, Code                       uint8
	Checksum, Identifier, SequenceNo uint16
}
type tomlConfig struct {
	Workstations map[string]workstation
}

var configFile = "config.toml"
var hostConfig tomlConfig
var ident int
var stopPing = make(chan bool)

func init() {
	ident = 1
	//runtime.GOMAXPROCS(2)
	if _, err := toml.DecodeFile(configFile, &hostConfig); err != nil {
		log.Println(err)
		log.Fatalln("couldnt read config file")
	}
	for hostname := range hostConfig.Workstations {
		hostConfig.Workstations[hostname] = changeAliveness(hostConfig.Workstations[hostname], false)
	}
}

func main() {
	go func() { pingWorker() }()
	//pingeling := func() { pingWorker() }
	//stopPing = pingScheduler(pingeling, 60*time.Second)

	router := mux.NewRouter()
	router.HandleFunc("/wake/{host}", wake).Methods("GET")
	router.HandleFunc("/", index).Methods("GET")
	http.ListenAndServe(":8070", router)

}

func wake(w http.ResponseWriter, r *http.Request) {
	host := mux.Vars(r)["host"]
	if hostConfig.Workstations[host].MAC != "" {
		etherWake(hostConfig.Workstations[host].MAC)
	}
	hostConfig.Workstations[host] = changeAliveness(hostConfig.Workstations[host], true)
	w.Header().Set("X-WakeOnLan", host)
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)

}

// simple function to render the index.html page
func index(w http.ResponseWriter, r *http.Request) {
	p := &indexPage{Title: "WAAS", Hosts: hostConfig}
	t := template.New("index.tmpl")
	t = template.Must(t.ParseGlob("templates/*.tmpl"))
	t.Execute(w, p)
}

func pingWorker() {
	for {
		time.Sleep(20 * time.Second)
		for hostname := range hostConfig.Workstations {
			hostConfig.Workstations[hostname] = changeAliveness(hostConfig.Workstations[hostname], checkHost(strings.TrimSpace(hostname)))
		}
		time.Sleep(40 * time.Second)
	}
}

// work around the fact that maps aren't adressable https://github.com/golang/go/issues/3117
func changeAliveness(gostinkt workstation, isAlive bool) workstation {
	gostinkt.Alive = isAlive
	return gostinkt
}

//
//	Network related functions
//

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
	if err != nil {
		log.Printf("Can't resolve: %s", host)
		return false
	}
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

// sends a wake on lan package to the specified MAC address
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

	// sewake/vaih-workstation-16nd the packet to the wire
	packetLength, err := socket.Write(magicPacket)
	if err != nil {
		log.Fatal("OMG", err)
	}
	if packetLength != 102 {
		log.Println("Weird, packet length not the expected 102: ", packetLength)
	}
	fmt.Printf("magic packet sent for: %v\n", macAddress)
}
