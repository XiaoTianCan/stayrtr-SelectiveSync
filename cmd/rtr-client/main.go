package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	rtr "github.com/bgp/stayrtr/lib"
	"golang.org/x/crypto/ssh"
)

// RTRClient
type RTRClient struct {
	addr     string
	connType int
	session  *rtr.ClientSession

	vrps      map[string]*rtr.VRP       // prefix cache
	brks      map[string]*rtr.BgpsecKey // BGPsec key cache
	serial    uint32                    // current serial
	sessionID uint16                    // session ID
	mutex     sync.RWMutex

	handler        *ClientEventHandler
	subscribedList []uint8 // subscribed PDU types
}

// ClientEventHandler implements RTRClientSessionEventHandler interface
type ClientEventHandler struct {
	client *RTRClient
}

func (h *ClientEventHandler) HandlePDU(cs *rtr.ClientSession, pdu rtr.PDU) {
	switch pdu.(type) {
	case *rtr.PDUCacheResponse:
		p := pdu.(*rtr.PDUCacheResponse)
		h.client.mutex.Lock()
		h.client.sessionID = p.SessionId
		h.client.mutex.Unlock()
		log.Printf("[Cache Response] SessionID: %d\n", p.SessionId)

	case *rtr.PDUIPv4Prefix:
		p := pdu.(*rtr.PDUIPv4Prefix)
		h.client.handleIPv4Prefix(p)

	case *rtr.PDUIPv6Prefix:
		p := pdu.(*rtr.PDUIPv6Prefix)
		h.client.handleIPv6Prefix(p)

	case *rtr.PDURouterKey:
		p := pdu.(*rtr.PDURouterKey)
		h.client.handleRouterKey(p)

	case *rtr.PDUEndOfData:
		p := pdu.(*rtr.PDUEndOfData)
		h.client.mutex.Lock()
		h.client.serial = p.SerialNumber
		h.client.mutex.Unlock()
		log.Printf("[End of Data] SessionID: %d, Serial: %d, RefreshInterval: %d, RetryInterval: %d, ExpireInterval: %d\n",
			p.SessionId, p.SerialNumber, p.RefreshInterval, p.RetryInterval, p.ExpireInterval)

	case *rtr.PDUSerialNotify:
		p := pdu.(*rtr.PDUSerialNotify)
		log.Printf("[Serial Notify] SessionID: %d, Serial: %d\n", p.SessionId, p.SerialNumber)
		// send Serial Query to update to the latest data
		h.client.mutex.RLock()
		sessionID := h.client.sessionID
		serial := h.client.serial
		h.client.mutex.RUnlock()
		h.client.session.SendSerialQuery(sessionID, serial)

	case *rtr.PDUCacheReset:
		log.Printf("[Cache Reset] Need to get all data again\n")
		h.client.session.SendResetQuery()

	case *rtr.PDUErrorReport:
		p := pdu.(*rtr.PDUErrorReport)
		log.Printf("[Error Report] ErrorCode: %d, Message: %s\n", p.ErrorCode, p.ErrorMsg)

	default:
		log.Printf("[Unknown PDU] Type: %s\n", rtr.TypeToString(pdu.GetType()))
	}
}

func (h *ClientEventHandler) ClientConnected(cs *rtr.ClientSession) {
	log.Println("[Connected] RTR client connected to server")

	// send Subscribe PDU
	if len(h.client.subscribedList) > 0 {
		h.client.session.SendSubscribe(h.client.subscribedList)
		log.Printf("[Subscribe] Have sent subscribed types: %v\n", h.client.subscribedList)
	}

	// send Reset Query
	h.client.session.SendResetQuery()
}

func (h *ClientEventHandler) ClientDisconnected(cs *rtr.ClientSession) {
	log.Println("[Disconnected] RTR client disconnected")
}

// handleIPv4Prefix PDU
func (c *RTRClient) handleIPv4Prefix(pdu *rtr.PDUIPv4Prefix) {
	prefix := pdu.Prefix
	key := fmt.Sprintf("%s-%d-%d", prefix.String(), pdu.MaxLen, pdu.ASN)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if pdu.Flags == rtr.FLAG_ADDED {
		vrp := &rtr.VRP{
			Prefix: prefix,
			MaxLen: pdu.MaxLen,
			ASN:    pdu.ASN,
		}
		c.vrps[key] = vrp
		log.Printf("[IPv4 Add] Prefix: %s, MaxLen: %d, ASN: %d\n", prefix, pdu.MaxLen, pdu.ASN)
	} else {
		delete(c.vrps, key)
		log.Printf("[IPv4 Remove] Prefix: %s, MaxLen: %d, ASN: %d\n", prefix, pdu.MaxLen, pdu.ASN)
	}
}

// handleIPv6Prefix PDU
func (c *RTRClient) handleIPv6Prefix(pdu *rtr.PDUIPv6Prefix) {
	prefix := pdu.Prefix
	key := fmt.Sprintf("%s-%d-%d", prefix.String(), pdu.MaxLen, pdu.ASN)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if pdu.Flags == rtr.FLAG_ADDED {
		vrp := &rtr.VRP{
			Prefix: prefix,
			MaxLen: pdu.MaxLen,
			ASN:    pdu.ASN,
		}
		c.vrps[key] = vrp
		log.Printf("[IPv6 Add] Prefix: %s, MaxLen: %d, ASN: %d\n", prefix, pdu.MaxLen, pdu.ASN)
	} else {
		delete(c.vrps, key)
		log.Printf("[IPv6 Remove] Prefix: %s, MaxLen: %d, ASN: %d\n", prefix, pdu.MaxLen, pdu.ASN)
	}
}

// handleRouterKey PDU
func (c *RTRClient) handleRouterKey(pdu *rtr.PDURouterKey) {
	key := fmt.Sprintf("%d-%x", pdu.ASN, pdu.SubjectKeyIdentifier)

	c.mutex.Lock()
	defer c.mutex.Unlock()

	if pdu.Flags == rtr.FLAG_ADDED {
		brk := &rtr.BgpsecKey{
			ASN:    pdu.ASN,
			Ski:    pdu.SubjectKeyIdentifier,
			Pubkey: pdu.SubjectPublicKeyInfo,
		}
		c.brks[key] = brk
		log.Printf("[Router Key Add] ASN: %d, SKI: %x\n", pdu.ASN, pdu.SubjectKeyIdentifier)
	} else {
		delete(c.brks, key)
		log.Printf("[Router Key Remove] ASN: %d, SKI: %x\n", pdu.ASN, pdu.SubjectKeyIdentifier)
	}
}

// GetVRPs get all VRPs
func (c *RTRClient) GetVRPs() []*rtr.VRP {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	vrps := make([]*rtr.VRP, 0, len(c.vrps))
	for _, vrp := range c.vrps {
		vrps = append(vrps, vrp)
	}
	return vrps
}

// GetBGPsecKeys get all current BGPsec keys
func (c *RTRClient) GetBGPsecKeys() []*rtr.BgpsecKey {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	brks := make([]*rtr.BgpsecKey, 0, len(c.brks))
	for _, brk := range c.brks {
		brks = append(brks, brk)
	}
	return brks
}

// PrintStats print current stats of the client
func (c *RTRClient) PrintStats() {
	c.mutex.RLock()
	defer c.mutex.RUnlock()

	log.Printf("\n========== RTR Client Stats ==========\n")
	log.Printf("Session ID: %d\n", c.sessionID)
	log.Printf("Serial: %d\n", c.serial)
	log.Printf("Total VRPs: %d\n", len(c.vrps))
	log.Printf("Total BGPsec Keys: %d\n", len(c.brks))
	log.Printf("=====================================\n")
}

// Connect to RTR server
func (c *RTRClient) Connect(protocol string) error {
	config := rtr.ClientConfiguration{
		ProtocolVersion: rtr.PROTOCOL_VERSION_1,
		Log:             &SimpleLogger{},
	}

	c.handler = &ClientEventHandler{client: c}
	c.session = rtr.NewClientSession(config, c.handler)

	var err error
	switch protocol {
	case "plain":
		c.connType = rtr.TYPE_PLAIN
		err = c.session.Start(c.addr, rtr.TYPE_PLAIN, nil, nil)

	case "tls":
		c.connType = rtr.TYPE_TLS
		tlsConfig := &tls.Config{
			InsecureSkipVerify: true, // only for testing, in production you should verify the server's certificate
		}
		err = c.session.Start(c.addr, rtr.TYPE_TLS, tlsConfig, nil)

	case "ssh":
		c.connType = rtr.TYPE_SSH
		sshConfig := &ssh.ClientConfig{
			User: "rpki",
			Auth: []ssh.AuthMethod{
				ssh.Password(""), // no password, only for testing
			},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // only for testing, in production you should verify the server's host key
			Timeout:         10 * time.Second,
		}
		err = c.session.Start(c.addr, rtr.TYPE_SSH, nil, sshConfig)

	default:
		return fmt.Errorf("unsupported protocol: %s", protocol)
	}

	return err
}

// SimpleLogger is a simple implementation of Logger interface that logs to standard output
type SimpleLogger struct{}

func (l *SimpleLogger) Debugf(format string, args ...interface{}) {
	log.Printf("[DEBUG] "+format, args...)
}

func (l *SimpleLogger) Printf(format string, args ...interface{}) {
	log.Printf(format, args...)
}

func (l *SimpleLogger) Warnf(format string, args ...interface{}) {
	log.Printf("[WARN] "+format, args...)
}

func (l *SimpleLogger) Errorf(format string, args ...interface{}) {
	log.Printf("[ERROR] "+format, args...)
}

func (l *SimpleLogger) Infof(format string, args ...interface{}) {
	log.Printf("[INFO] "+format, args...)
}

// parseSubscribeList parse the subscribe string into a list of PDU types
func parseSubscribeList(subscribeStr string) ([]uint8, error) {
	if subscribeStr == "" {
		// if null or empty, subscribe all types
		return []uint8{rtr.PDU_ID_IPV4_PREFIX, rtr.PDU_ID_IPV6_PREFIX, rtr.PDU_ID_ROUTER_KEY}, nil
	}

	parts := strings.Split(subscribeStr, ",")
	var subscribedList []uint8

	for _, part := range parts {
		part = strings.TrimSpace(part)
		num, err := strconv.Atoi(part)
		if err != nil {
			return nil, fmt.Errorf("Invalid PDU type: %s", part)
		}

		pduType := uint8(num)
		// validate the PDU type and add to the subscribed list
		switch pduType {
		case rtr.PDU_ID_IPV4_PREFIX, rtr.PDU_ID_IPV6_PREFIX, rtr.PDU_ID_ROUTER_KEY:
			subscribedList = append(subscribedList, pduType)
		default:
			return nil, fmt.Errorf("Unsupported PDU type: %d (Only support 4=IPv4 Prefix, 6=IPv6 Prefix, 9=Router Key)", num)
		}
	}

	if len(subscribedList) == 0 {
		return nil, fmt.Errorf("Subscribe list cannot be empty")
	}

	return subscribedList, nil
}

func main() {
	host := flag.String("host", "127.0.0.1", "RTR server host name or IP address")
	port := flag.String("port", "8282", "RTR server port")
	protocol := flag.String("protocol", "plain", "connect protocol (plain/tls/ssh)")
	statsInterval := flag.Duration("stats", 30*time.Second, "stats print interval (e.g., 30s, 1m)")
	subscribe := flag.String("subscribe", "", "subscribe PDU type list, e.g., '4,6,9' (4=IPv4 Prefix, 6=IPv6 Prefix, 9=Router Key), if empty subscribe all types")
	flag.Parse()

	addr := fmt.Sprintf("%s:%s", *host, *port)

	// Parse subscribe list
	subscribedList, err := parseSubscribeList(*subscribe)
	if err != nil {
		log.Fatalf("Subscribe list error: %v", err)
	}

	client := &RTRClient{
		addr:           addr,
		vrps:           make(map[string]*rtr.VRP),
		brks:           make(map[string]*rtr.BgpsecKey),
		subscribedList: subscribedList,
	}

	log.Printf("Connect to RTR server: %s (protocol: %s)\n", addr, *protocol)
	log.Printf("Subscribe PDU type: %v\n", subscribedList)
	err = client.Connect(*protocol)
	if err != nil {
		log.Fatalf("Connection failed: %v", err)
	}

	// Setup signal handling
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	// Periodically print stats
	ticker := time.NewTicker(*statsInterval)
	defer ticker.Stop()

	log.Println("RTR client started, press Ctrl+C to exit")

	for {
		select {
		case <-sigChan:
			log.Println("Received interrupt signal, shutting down...")
			client.session.Disconnect()
			client.PrintStats()
			os.Exit(0)

		case <-ticker.C:
			client.PrintStats()
			vrps := client.GetVRPs()
			if len(vrps) > 0 && len(vrps) <= 10 {
				log.Println("Current VRPs:")
				for _, vrp := range vrps {
					log.Printf("  - %s (MaxLen: %d, ASN: %d)\n", vrp.Prefix, vrp.MaxLen, vrp.ASN)
				}
			}
		}
	}
}
