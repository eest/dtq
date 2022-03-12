package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"runtime/pprof"
	"strconv"
	"strings"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	bexpr "github.com/hashicorp/go-bexpr"
	"github.com/miekg/dns"
)

// dtqData encapsulates the data we parse out of the dnstap file. Any custom
// fields outside the main Dnstap and Msg fields are there for easy
// reference where data might only be available in a numeric format while it is
// easier to search for the type string "A" or "MX" rather than the equivalent
// numerical value. We do not want to duplicate fields already present
// somewhere else.
type dtqData struct {
	Dnstap                *dnstap.Dnstap `json:",omitempty"`
	Msg                   *dns.Msg       `json:",omitempty"`
	DnstapTypeString      string         `json:",omitempty"`
	MessageTypeString     string         `json:",omitempty"`
	SocketFamilyString    string         `json:",omitempty"`
	SocketProtocolString  string         `json:",omitempty"`
	QueryAddressString    string         `json:",omitempty"`
	ResponseAddressString string         `json:",omitempty"`
	QueryTimeString       string         `json:",omitempty"`
	ResponseTimeString    string         `json:",omitempty"`
	DnstapIsQuery         *bool          `json:",omitempty"`
	// While it would be possible to have more than one question in the
	// question section, it is not generally supported, so we pick out the
	// first question entry only and include class and type strings for
	// easy reference
	DNSQuestionName        string `json:",omitempty"`
	DNSQuestionClassString string `json:",omitempty"`
	DNSQuestionTypeString  string `json:",omitempty"`
}

func main() {
	var filter = flag.String("filter", "", "filter expression")
	var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
	var dnstapfile = flag.String("file", "", "read dnstap data from file")

	flag.Parse()

	var eval *bexpr.Evaluator

	if *filter != "" {
		var err error
		eval, err = bexpr.CreateEvaluator(*filter)
		if err != nil {
			log.Fatalf("Failed to create evaluator for expression %q: %v\n", *filter, err)
		}
	}

	if *cpuprofile != "" {
		pf, err := os.Create(*cpuprofile)
		if err != nil {
			log.Fatal(err)
		}
		err = pprof.StartCPUProfile(pf)
		if err != nil {
			log.Fatal(err)
		}
		defer pprof.StopCPUProfile()
	}

	if *dnstapfile == "" {
		flag.Usage()
		os.Exit(1)
	}

	f, err := os.Open(*dnstapfile)
	if err != nil {
		log.Fatal(err)
	}

	opts := &dnstap.ReaderOptions{}

	r, err := dnstap.NewReader(f, opts)
	if err != nil {
		log.Fatal(err)
	}

	dec := dnstap.NewDecoder(r, int(dnstap.MaxPayloadSize))

	// Use buffered output to speed things up
	bufStdout := bufio.NewWriter(os.Stdout)

	for {
		var dt dnstap.Dnstap

		if err := dec.Decode(&dt); err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err)
		}

		var dd dtqData
		var queryAddress, responseAddress string

		isQuery := strings.HasSuffix(dnstap.Message_Type_name[int32(*dt.Message.Type)], "_QUERY")
		qa := net.IP(dt.Message.QueryAddress)
		ra := net.IP(dt.Message.ResponseAddress)

		msg := new(dns.Msg)

		if isQuery {
			dd.QueryTimeString = time.Unix(int64(*dt.Message.QueryTimeSec), int64(*dt.Message.QueryTimeNsec)).Local().Format(time.RFC3339Nano)
			err = msg.Unpack(dt.Message.QueryMessage)
			if err != nil {
				log.Printf("unable to unpack query message (%s -> %s): %s", queryAddress, responseAddress, err)
				msg = nil
			}
		} else {
			dd.ResponseTimeString = time.Unix(int64(*dt.Message.ResponseTimeSec), int64(*dt.Message.ResponseTimeNsec)).Local().Format(time.RFC3339Nano)
			err = msg.Unpack(dt.Message.ResponseMessage)
			if err != nil {
				log.Printf("unable to unpack response message (%s <- %s): %s", queryAddress, responseAddress, err)
				msg = nil
			}
		}

		dd.Dnstap = &dt
		dd.Msg = msg

		if msg != nil {
			var dnsQuestionClassString string
			var dnsQuestionTypeString string

			dd.DNSQuestionName = msg.Question[0].Name

			// IN, CH etc or synthesized "CLASS31337" based on the
			// numeric value if not a known class
			if c, ok := dns.ClassToString[msg.Question[0].Qclass]; ok {
				dnsQuestionClassString = c
			} else {
				dnsQuestionClassString = "CLASS" + strconv.FormatUint(uint64(msg.Question[0].Qclass), 10)
			}
			dd.DNSQuestionClassString = dnsQuestionClassString

			// A, MX, NS etc or synthesized "TYPE31337" based on the
			// numeric value if not a known type
			if t, ok := dns.TypeToString[msg.Question[0].Qtype]; ok {
				dnsQuestionTypeString = t
			} else {
				dnsQuestionTypeString = strconv.FormatUint(uint64(msg.Question[0].Qtype), 10)
			}
			dd.DNSQuestionTypeString = dnsQuestionTypeString
		}

		dd.DnstapIsQuery = &isQuery

		if qa != nil {
			dd.QueryAddressString = qa.String()
		}

		if ra != nil {
			dd.ResponseAddressString = ra.String()
		}

		dd.DnstapIsQuery = &isQuery
		dd.DnstapTypeString = dnstap.Dnstap_Type_name[int32(*dt.Type)]
		dd.MessageTypeString = dnstap.Message_Type_name[int32(*dt.Message.Type)]
		dd.SocketFamilyString = dnstap.SocketFamily_name[int32(*dt.Message.SocketFamily)]
		dd.SocketProtocolString = dnstap.SocketProtocol_name[int32(*dt.Message.SocketProtocol)]

		if eval != nil {
			result, err := eval.Evaluate(dd)
			if err != nil {
				log.Fatalf("Failed to run evaluation of expression %q: %v\n", *filter, err)
			}

			if !result {
				continue
			}
		}

		ddJSON, err := json.Marshal(&dd)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Fprintf(bufStdout, "%s\n", ddJSON)
	}

	err = bufStdout.Flush()
	if err != nil {
		log.Fatal(err)
	}
}
