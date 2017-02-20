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
	"html/template"
	"math/rand"
	"net"
	"net/http"
	"os"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/fatih/color"
	"github.com/gorilla/mux"
	"github.com/robfig/cron"
)

type indexPage struct {
	Title string
	Hosts tomlConfig
}
type workstation struct {
	NAME   string
	IP     string
	MAC    string
	LINK   string
	Sended bool
	Alive  bool
}
type appConfig struct {
	Address     string
	WebPrefix   string
	TemplateDir string
	Scheduler   string
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

type justFilesFilesystem struct {
	fs http.FileSystem
}

type neuteredReaddirFile struct {
	http.File
}

type colorLog struct {
	Error    color.Color
	Warning  color.Color
	Info     color.Color
	Headline color.Color
	InfoBold color.Color
	Default  color.Color
}

var configFile string
var hostConfig tomlConfig
var ident int
var stopPing = make(chan bool)
var colorPrint colorLog

func init() {
	colorPrint.Headline.Add(color.Bold)
	colorPrint.Error.Add(color.FgRed)
	colorPrint.Warning.Add(color.FgYellow)
	colorPrint.Info.Add(color.FgCyan)
	colorPrint.InfoBold.Add(color.FgCyan).Add(color.Bold)

	flag.StringVar(&configFile, "config", "./config.toml", "config file location")
	flag.Parse()
	ident = os.Getpid()
	if _, err := toml.DecodeFile(configFile, &hostConfig); err != nil {
		colorPrint.Error.Printf("couldnt read config file: %s", err)
	}
	for hostname := range hostConfig.Workstations {
		hostConfig.Workstations[hostname] = changeAliveness(hostConfig.Workstations[hostname], false)
	}

	if len(hostConfig.Core.WebPrefix) == 0 {
		hostConfig.Core.WebPrefix = "/"
	}

	if len(hostConfig.Core.Scheduler) == 0 {
		hostConfig.Core.Scheduler = "@every 1m"
	} else {
		hostConfig.Core.Scheduler = "@every " + hostConfig.Core.Scheduler
	}
}

func main() {
	var err error

	router := mux.NewRouter()
	router.HandleFunc(hostConfig.Core.WebPrefix+"wake/{host}", wake).Methods("GET")
	router.HandleFunc(hostConfig.Core.WebPrefix, index).Methods("GET")

	fs := justFilesFilesystem{http.Dir(hostConfig.Core.TemplateDir + "static/")}
	router.PathPrefix(hostConfig.Core.WebPrefix + "static/").Handler(http.StripPrefix(hostConfig.Core.WebPrefix+"static/", http.FileServer(fs)))

	// Print some infos
	colorPrint.Headline.Print("Listen on: ")
	colorPrint.Default.Println(hostConfig.Core.Address)
	colorPrint.Headline.Print("Scheduler: ")
	colorPrint.Default.Println(hostConfig.Core.Scheduler)
	colorPrint.Headline.Print("WebPrefix: ")
	colorPrint.Default.Println(hostConfig.Core.WebPrefix)
	colorPrint.Headline.Print("Template directory: ")
	colorPrint.Default.Println(hostConfig.Core.TemplateDir)

	http.DefaultTransport.(*http.Transport).MaxIdleConnsPerHost = 100
	srv := &http.Server{
		Handler: router,
		Addr:    hostConfig.Core.Address,
		// Good practice: enforce timeouts for servers you create!
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	// Inital run, the next run is executed via cron
	go func() { pingWorker() }()
	//Cron
	c := cron.New()
	if err = c.AddFunc(hostConfig.Core.Scheduler, func() { pingWorker() }); err != nil {
		colorPrint.Error.Printf("%v\n", err)
	}
	c.Start()

	// Start http server
	err = srv.ListenAndServe()
	if err = srv.ListenAndServe(); err != nil {
		colorPrint.Error.Printf("%v\n", err)
	}
}

func (fs justFilesFilesystem) Open(name string) (http.File, error) {
	f, err := fs.fs.Open(name)
	if err != nil {
		return nil, err
	}
	return neuteredReaddirFile{f}, nil
}

func (f neuteredReaddirFile) Readdir(count int) ([]os.FileInfo, error) {
	return nil, nil
}

func wake(w http.ResponseWriter, r *http.Request) {
	host := mux.Vars(r)["host"]
	if hostConfig.Workstations[host].MAC != "" {
		etherWake(hostConfig.Workstations[host].MAC)
	}
	hostConfig.Workstations[host] = changeSended(hostConfig.Workstations[host], true)
	w.Header().Set("X-WakeOnLan", host)
	http.Redirect(w, r, hostConfig.Core.WebPrefix, http.StatusTemporaryRedirect)

}

// simple function to render the index.html page
func index(w http.ResponseWriter, r *http.Request) {
	p := &indexPage{Title: hostConfig.Core.HTML.Title, Hosts: hostConfig}
	t := template.New("index.tmpl")
	t = template.Must(t.ParseGlob(hostConfig.Core.TemplateDir + "/*.tmpl"))
	t.Execute(w, p)
}

// ping our workstations periodically, in the background
func pingWorker() {
	colorPrint.InfoBold.Println("Ping hosts")
	for hostname, data := range hostConfig.Workstations {
		hostConfig.Workstations[hostname] = changeAliveness(hostConfig.Workstations[hostname], checkHost(hostname, data.IP))
	}
}

// work around the fact that maps aren't adressable https://github.com/golang/go/issues/3117
func changeAliveness(gostinkt workstation, isAlive bool) workstation {
	// Reset sended when the current value of isAlive is true and will change to false
	if gostinkt.Alive == false && gostinkt.Alive != isAlive {
		gostinkt = changeSended(gostinkt, false)
	}
	gostinkt.Alive = isAlive
	return gostinkt
}

func changeSended(gostinkt workstation, isSended bool) workstation {
	gostinkt.Sended = isSended
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
		colorPrint.Warning.Printf("Error writing packet to buffer: %v\n", err)
	}
	packet.Checksum = checksum(buffer.Bytes())
	buffer.Reset()
	if err = binary.Write(&buffer, binary.BigEndian, packet); err != nil {
		colorPrint.Warning.Printf("Error writing packet to buffer: %v\n", err)
	}

	return buffer.Bytes()
}

// checks if the Host is alive after we've sent a
// magic packet
func checkHost(host string, ipString string) bool {
	var err error
	var connection net.Conn
	send := buildICMPEchoRequest((rand.Int()*ident)&0xffff, 1, 64)

	//icmps, err := net.DialIP("ip4:icmp", nil, raddr)
	connection, err = net.Dial("ip4:icmp", host)
	if err != nil {
		colorPrint.Warning.Printf("Catch all possible errors: %v\n", err)
		return false
	}
	_, err = connection.Write(send)
	if err != nil {
		colorPrint.Warning.Printf("Could not send to host: %s\n", host)
		colorPrint.Warning.Printf("Error dump: %v\n", err)
		return false
	}
	online := make(chan bool, 1)
	go func() {
		sending := int(send[4])<<8 | int(send[5])

		// from here on we want to receive the icmp echo reply
		icmpReply := make([]byte, 64)
		_, err = connection.Read(icmpReply)
		if err != nil {
			colorPrint.Warning.Printf("Error dump: %v\n", err)
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
		colorPrint.Warning.Println("Could not open socket to broadcast ip")
		colorPrint.Warning.Printf("Error dump: %v\n", err)
	}

	// sewake/vaih-workstation-16nd the packet to the wire
	packetLength, err := socket.Write(magicPacket)
	if err != nil {
		colorPrint.Warning.Printf("Could not send magic packet: %v\n", err)
	}
	if packetLength != 102 {
		colorPrint.Warning.Printf("Weird, packet length not the expected 102: %d", packetLength)
	}
}
