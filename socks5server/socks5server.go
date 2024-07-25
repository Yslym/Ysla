package socks5server

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
)
import "C"
//export SocksV
func SocksV(ip *C.char,port C.int) error{
	s := NewSocks5Server(C.GoString(ip),int(port))	
	return s.Run()
}

// FirstMessage represents the initial message sent by SOCKS5 clients.
type FirstMessage struct {
	Version byte
	Method  byte
}

// NewFirstMessage creates a new FirstMessage instance.
func NewFirstMessage(v byte, m byte) *FirstMessage {
	return &FirstMessage{
		Version: v,
		Method:  m,
	}
}

// Bytes returns the byte representation of FirstMessage.
func (self *FirstMessage) Bytes() []byte {
	return []byte{self.Version, self.Method}
}

// Socks5Server represents a SOCKS5 server.
type Socks5Server struct {
	IP   string
	Port int
}

// NewSocks5Server creates a new instance of Socks5Server.
func NewSocks5Server(ip string, port int) *Socks5Server {
	return &Socks5Server{ip, port}
}

// Run starts the SOCKS5 server and listens for incoming connections.
func (self *Socks5Server) Run() error {
	listen, err := net.Listen("tcp", self.IP+":"+strconv.Itoa(self.Port))
	if err != nil {
		log.Printf("Failed to listen: %v", err)
		return err
	}
	defer listen.Close()

	log.Printf("Successfully started SOCKS5 server on %s:%d\n", self.IP, self.Port)
	for {
		conn, err := listen.Accept()
		if err != nil {
			log.Printf("Failed to accept connection: %v", err)
			continue
		}
		go handleClient(conn)
	}
}

// handleClient handles an incoming client connection.
func handleClient(conn net.Conn) {
	defer conn.Close()
	log.Println("###########################################")

	err := auth(conn) // Perform the authentication process
	if err != nil {
		log.Printf("Failed to authenticate: %v", err)
		conn.Close()
		return
	}
	log.Println("[+] Authentication successful")

	msg, err := req(conn) // Handle the request from the client
	if err != nil {
		log.Printf("Failed to handle request: %v", err)
		response, _ := buildSecondResponse(0x05, 0x08, 0x00, 0xff, []byte{0xff, 0xff, 0xff, 0xff}, 0xffff)
		conn.Write(response.Bytes())
		conn.Close()
		return
	}
	log.Println("[+] Request handled successfully")

	err = proxy(conn, msg) // Proxy the connection to the requested target
	if err != nil {
		log.Printf("Failed to proxy connection: %v", err)
		conn.Close()
		return
	}
	log.Println("[+] Proxying successful")
}

// connectToDomain connects to a domain specified by `domain` and `port`.
func connectToDomain(domain []byte, port uint16) (net.Conn, error) {
	addr := string(domain)
	tcpAddr := fmt.Sprintf("%s:%d", addr, port)
	log.Println("[Proxy] Domain address:", tcpAddr)

	return net.Dial("tcp", tcpAddr)
}

// toNet converts a uint16 integer from host byte order to network byte order.
func toNet(i uint16) uint16 {
	return (i << 8 | i >> 8)
}

// proxy proxies the connection `conn` based on the SecondMessage `msg`.
func proxy(conn net.Conn, msg *SecondMessage) error {
	log.Println("[Proxy] Starting proxy")
	log.Println("[Proxy] Message:", msg)

	var targetConn net.Conn
	var err error

	if msg.Atype == 0x03 { // Domain name
		targetConn, err = connectToDomain(msg.Addr, msg.Port)
	} else { // IPv4 or IPv6 address
		target := fmt.Sprintf("%d.%d.%d.%d:%d", msg.Addr[0], msg.Addr[1], msg.Addr[2], msg.Addr[3], msg.Port)
		targetConn, err = net.Dial("tcp", target)
	}

	if err != nil {
		log.Printf("Failed to dial target: %v", err)
		secondResponse, _ := buildSecondResponse(0x05, 0x01, 0x00, msg.Atype, msg.Addr, msg.Port)
		conn.Write(secondResponse.Bytes())
		return errors.New("failed to dial target")
	}

	log.Println("[Proxy] Built TCP connection successfully")

	localAddr := targetConn.LocalAddr().(*net.TCPAddr)
	addrBytes := localAddr.IP.To4()

	response, _ := buildSecondResponse(0x05, 0x00, 0x00, 0x01, addrBytes, toNet(uint16(localAddr.Port)))
	conn.Write(response.Bytes())

	defer targetConn.Close()

	log.Println("[Proxy] Start forwarding")

	go io.Copy(conn, targetConn)
	io.Copy(targetConn, conn)

	log.Println("[+] Forwarding ended")

	conn.Close()
	targetConn.Close()
	return nil
}

// SecondMessage represents the second message exchanged in the SOCKS5 protocol.
type SecondMessage struct {
	Version byte
	Cmd     byte
	Rsv     byte
	Atype   byte
	Addr    []byte
	Port    uint16
}

// buildSecondResponse builds a SecondMessage response.
func buildSecondResponse(version byte, rep byte, rsv byte, atype byte, addr []byte, port uint16) (*SecondMessage, error) {
	return &SecondMessage{
		Version: version,
		Cmd:     rep,
		Rsv:     rsv,
		Atype:   atype,
		Addr:    addr,
		Port:    port,
	}, nil
}

// Bytes returns the byte representation of SecondMessage.
func (self *SecondMessage) Bytes() []byte {
	var buff = make([]byte, 6+len(self.Addr))
	buff[0] = self.Version
	buff[1] = self.Cmd
	buff[2] = self.Rsv
	buff[3] = self.Atype
	copy(buff[4:], self.Addr)
	buff[4+len(self.Addr)] = byte(self.Port >> 8 & 0xff)
	buff[5+len(self.Addr)] = byte(self.Port & 0xff)

	return buff
}

// builfSecondMessage builds a SecondMessage from `io`.
func builfSecondMessage(io io.ReadWriter) (*SecondMessage, error) {
	var buf [4]byte
	io.Read(buf[:4])
	log.Println("[build] ",buf)
	
	var msg SecondMessage = SecondMessage{
		Version: buf[0],
		Cmd:     buf[1],
		Rsv:     buf[2],
		Atype:   buf[3],
	}

	switch buf[3] {
	case 0x01: // IPv4
		var addrBuf [4]byte
		io.Read(addrBuf[:4])
		msg.Addr = net.IP(addrBuf[:4])
		var portbuf [2]byte
		io.Read(portbuf[:2])
		msg.Port = uint16(portbuf[0])<<8 | uint16(portbuf[1])
		return &msg, nil
	case 0x04: // IPv6
		var addrBuf []byte = make([]byte, 16)
		io.Read(addrBuf)
		msg.Addr = net.IP(addrBuf[:16])
		var portbuf [2]byte
		io.Read(portbuf[:2])
		msg.Port = uint16(portbuf[0])<<8 | uint16(portbuf[1])
		return &msg, nil
	case 0x03: // Domain
		var domainLen [1]byte
		io.Read(domainLen[:1])
		var domain []byte = make([]byte, domainLen[0])
		io.Read(domain)
		msg.Addr = net.IP(domain[:])
		var portbuf [2]byte
		io.Read(portbuf[:2])
		msg.Port = uint16(portbuf[0])<<8 | uint16(portbuf[1])
		return &msg, nil
	default:
		log.Printf("Triggered default, Atype is %d", buf[3])
		log.Printf("%v", buf)
		return nil, errors.New("Invalid command in building Second Message")
	}
}

// req handles the request from the client `conn`.
func req(conn net.Conn) (*SecondMessage, error) {
	log.Println("[+] in req")	
	message, err := builfSecondMessage(conn)
	if err != nil {
		return nil, err
	}

	log.Println("[REQ] Built request message:", message)

	if message.Version != 0x05 {
		return nil, errors.New("Invalid SOCKS version")
	}
	log.Println("[REQ] SOCKS version check passed")

	if message.Cmd != 0x01 {
		return nil, errors.New("Unsupported command")
	}
	log.Println("[REQ] Command check passed")

	if message.Rsv != 0x00 {
		return nil, errors.New("Invalid RSV")
	}
	log.Println("[REQ] RSV check passed")

	if message.Atype != 0x01 {
		log.Println("Not an IP address:", message.Atype)
	}

	return message, nil
}

// auth handles the authentication process with the client `conn`.
func password_auth(conn net.Conn) error{
	var buf [2]byte
	conn.Read(buf[:])
	log.Println("p/u head-> ",buf)
	if buf[0] != 0x01{
		return errors.New("Version is not SubNagtive v1")
	}
	username := make([]byte,buf[1])
	conn.Read(username)
	var plen [1]byte
	conn.Read(plen[:])
	password := make([]byte,plen[0])
	conn.Read(password)
	log.Println("username len: ",buf[1],"password len: ",plen[0])
	log.Println(username,":",password)

	// check
	if string(password) != "bolar@password" || string(username) != "bolar"{
		
		return errors.New(fmt.Sprintf("PassWord/Username Failed %s/%s",string(username),string(password)))
	}
	log.Println("[password] successful got password")
	return nil
	
	
}
func auth(conn net.Conn) error {
	var buf [2]byte
	conn.Read(buf[:])

	if buf[0] != 0x5 {
		msg := NewFirstMessage(0x05, 0xff) // Refuse SOCKS version not supported
		conn.Write(msg.Bytes())
		return errors.New("Version is not SOCKS5")
	}
	log.Println("[AUTH] Version verification successful")

	nmethod := int(buf[1])
	log.Println("nmethods ",nmethod)
	
	buff := make([]byte, nmethod)

	_, err := io.ReadFull(conn, buff)
	if err != nil {
		return err
	}
	log.Println("[AUTH] Number of methods received:->", buff,"end")

	for _, i := range buff {
		if i == 0x00 { // No authentication required
			conn.Write(NewFirstMessage(0x05, 0x00).Bytes())
			return nil
		} else if i == 0x02 { // Password authentication
			conn.Write(NewFirstMessage(0x05, 0x02).Bytes()) // send username/password method			
			err := password_auth(conn)
			if err != nil{	
				log.Println("[auth] ",err)
				conn.Write(NewFirstMessage(0x01, 0x01).Bytes()) // Temporary not implemented
				return errors.New("Auth Failed")
			}
			conn.Write(NewFirstMessage(0x01, 0x00).Bytes())
			return nil
		}
	}

	// If no supported method found
	return errors.New("No supported method")
}

	

