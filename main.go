//
// wol-server is a simple go web app to check if
// the workstations in our office are on, and if not
// allow the viewer to turn them on via wake on lan
//
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"html/template"
	"log"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/gorilla/mux"
	"github.com/mailgun/manners"
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
type appConfig struct {
	Address     string
	ExternalURL string
	WebPrefix   string
	TemplateDir string
	HTML        appConfigHTML
}
type appConfigHTML struct {
	Title string
}
type tomlConfig struct {
	Core         appConfig
	Workstations map[string]workstation
}
type icmpMsg struct {
	Type, Code                       uint8
	Checksum, Identifier, SequenceNo uint16
}

var configFile string
var templateDir string
var listenAddress string
var externalURL string
var webPrefix string
var hostConfig tomlConfig
var ident int
var stopPing = make(chan bool)

func init() {
	flag.StringVar(&configFile, "config", "./config.toml", "config file location")
	flag.Parse()
	ident = os.Getpid()
	if _, err := toml.DecodeFile(configFile, &hostConfig); err != nil {
		log.Println(err)
		log.Fatalln("couldnt read config file")
	}
	for hostname := range hostConfig.Workstations {
		hostConfig.Workstations[hostname] = changeAliveness(hostConfig.Workstations[hostname], false)
	}
	templateDir = hostConfig.Core.TemplateDir
	externalURL = hostConfig.Core.ExternalURL
	listenAddress = hostConfig.Core.Address
	webPrefix = hostConfig.Core.WebPrefix

	if len(webPrefix) == 0 {
		webPrefix = "/"
	}
}

func main() {
	// handle sigterm/kill/interrupt
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		fmt.Println(sig)
		manners.Close()
	}()

	go func() { pingWorker() }()
	router := mux.NewRouter()
	router.HandleFunc(webPrefix+"wake/{host}", wake).Methods("GET")
	router.HandleFunc(webPrefix, index).Methods("GET")
	manners.ListenAndServe(listenAddress, router)

}

func wake(w http.ResponseWriter, r *http.Request) {
	host := mux.Vars(r)["host"]
	if hostConfig.Workstations[host].MAC != "" {
		etherWake(hostConfig.Workstations[host].MAC)
	}
	hostConfig.Workstations[host] = changeAliveness(hostConfig.Workstations[host], true)
	w.Header().Set("X-WakeOnLan", host)
	http.Redirect(w, r, webPrefix, http.StatusTemporaryRedirect)

}

// simple function to render the index.html page
func index(w http.ResponseWriter, r *http.Request) {
	p := &indexPage{Title: hostConfig.Core.HTML.Title, Hosts: hostConfig}
	t := template.New("index.tmpl")
	t = template.Must(t.ParseGlob(templateDir + "/*.tmpl"))
	t.Execute(w, p)
}

// ping our workstations periodically, in the background
func pingWorker() {
	for {
		for hostname := range hostConfig.Workstations {
			hostConfig.Workstations[hostname] = changeAliveness(hostConfig.Workstations[hostname], checkHost(hostname))
		}
		time.Sleep(60 * time.Second)
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
		log.Printf("Error writing packet to buffer: %v\n", err)
	}
	packet.Checksum = checksum(buffer.Bytes())
	buffer.Reset()
	if err = binary.Write(&buffer, binary.BigEndian, packet); err != nil {
		log.Printf("Error writing packet to buffer: %v\n", err)
	}

	return buffer.Bytes()
}

// checks if the Host is alive after we've sent a
// magic packet
func checkHost(host string) bool {
	var err error
	var connection net.Conn
	send := buildICMPEchoRequest((rand.Int()*ident)&0xffff, 1, 64)

	//icmps, err := net.DialIP("ip4:icmp", nil, raddr)
	connection, err = net.Dial("ip4:icmp", host)
	if err != nil {
		log.Printf("Catch all possible errors #yolo: %v\n", err)
		return false
	}
	_, err = connection.Write(send)
	if err != nil {
		log.Printf("Could not send to host: %s\n", host)
		log.Printf("Error dump: %v\n", err)
		return false
	}
	online := make(chan bool, 1)
	go func() {
		sending := int(send[4])<<8 | int(send[5])

		// from here on we want to receive the icmp echo reply
		icmpReply := make([]byte, 64)
		_, err = connection.Read(icmpReply)
		if err != nil {
			log.Printf("Error dump: %v\n", err)
			online <- false
		}

		recv := getPayload(icmpReply)
		receiving := int(recv[4])<<8 | int(recv[5])
		//fmt.Printf("received ID: %v\n", receiving)

		if sending == receiving {
			online <- true
		}

	}()
	select {
	case <-online:
		return true
	case <-time.After(time.Second * 2):
		return false
	}

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
		log.Println("Could not open socket to broadcast ip")
		log.Printf("Error dump: %v\n", err)
	}

	// sewake/vaih-workstation-16nd the packet to the wire
	packetLength, err := socket.Write(magicPacket)
	if err != nil {
		log.Printf("Could not send magic packet: %v\n", err)
	}
	if packetLength != 102 {
		log.Printf("Weird, packet length not the expected 102: %d", packetLength)
	}
}
