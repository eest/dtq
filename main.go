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
	"reflect"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"
	"time"

	dnstap "github.com/dnstap/golang-dnstap"
	"github.com/miekg/dns"
	"github.com/xwb1989/sqlparser"
)

// parsedData is used to store the values we parse out of the dnstap messages.
// We keep them in maps so the WHERE comparisions can map between the column
// names easily
type parsedData struct {
	stringData map[string]string
	uint16Data map[string]uint16
	uint32Data map[string]uint32
	boolData   map[string]bool
	timeData   map[string]time.Time
}

// Filter nodes are used to build a tree given a WHERE statement for filtering
// parsed records
type filterNode interface{}

type andNode struct {
	left, right filterNode
}

type orNode struct {
	left, right filterNode
}

type stringEqNode struct {
	colName string
	val     string
}

type stringNotEqNode struct {
	colName string
	val     string
}

type uint16EqNode struct {
	colName string
	val     uint16
}

type uint16NotEqNode struct {
	colName string
	val     uint16
}

type uint32EqNode struct {
	colName string
	val     uint32
}

type uint32NotEqNode struct {
	colName string
	val     uint32
}

type boolNode struct {
	colName string
	val     bool
}

// dtqData describes the content of the JSON output
type dtqData struct {
	DnstapRaw             *dnstap.Dnstap `json:"dnstap_raw,omitempty"`
	DnstapTypeName        string         `json:"dnstap_type_name,omitempty"`
	MessageTypeName       string         `json:"message_type_name,omitempty"`
	SocketFamilyName      string         `json:"socket_family_name,omitempty"`
	SocketProtocolName    string         `json:"socket_protocol_name,omitempty"`
	QueryAddressString    string         `json:"query_address_string,omitempty"`
	ResponseAddressString string         `json:"response_address_string,omitempty"`
	QueryPort             uint32         `json:"query_port,omitempty"`
	ResponsePort          uint32         `json:"response_port,omitempty"`
	QueryTimeString       string         `json:"query_time_string,omitempty"`
	ResponseTimeString    string         `json:"response_time_string,omitempty"`
	DnstapIsQuery         *bool          `json:"dnstap_is_query,omitempty"`
	DNSMsgRaw             *dns.Msg       `json:"dns_msg_raw,omitempty"`
	// While it would be possible to have more than one question in the
	// question section, it is not generally supported, so we pick out the
	// first question entry only
	DNSQuestionName      string `json:"dns_question_name,omitempty"`
	DNSQuestionClassName string `json:"dns_question_class_name,omitempty"`
	DNSQuestionTypeName  string `json:"dns_question_type_name,omitempty"`
	DNSID                uint16 `json:"dns_id,omitempty"`
}

func main() {
	var cpuprofile = flag.String("cpuprofile", "", "write cpu profile to file")
	var dnstapfile = flag.String("file", "", "read dnstap data from file")
	var query = flag.String("query", "", "SELECT statement")
	var whereColumns = flag.Bool("where-columns", false, "list columns available for WHERE statement")

	flag.Parse()

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

	// Figure out what JSON fields we know about by inspecting the
	// available `json` struct tags
	jsonFieldNames := map[string]string{}
	jsonFieldNamesSlice := []string{}
	dtqVal := reflect.ValueOf(dtqData{})
	for i := 0; i < dtqVal.NumField(); i++ {
		//varName := dtqVal.Type().Field(i).Name
		varType := dtqVal.Type().Field(i).Type
		varTag := dtqVal.Type().Field(i).Tag.Get("json")
		//fmt.Printf("%v: %v\n", varName, varTag)
		fieldName := strings.Split(varTag, ",")[0]
		if _, ok := jsonFieldNames[fieldName]; !ok {
			jsonFieldNames[fieldName] = varType.String()
			jsonFieldNamesSlice = append(jsonFieldNamesSlice, fieldName)
		} else {
			log.Fatalf("Duplicated json field name found: %s", fieldName)
		}
	}
	sort.Strings(jsonFieldNamesSlice)

	if *whereColumns {
		fmt.Printf("Columns available for WHERE statement:\n")
		for _, column := range jsonFieldNamesSlice {
			if strings.HasSuffix(column, "_raw") {
				continue
			}
			fmt.Printf("  %s (%s)\n", column, jsonFieldNames[column])
		}
		os.Exit(0)
	}

	stmt, err := sqlparser.Parse(*query)
	if err != nil {
		log.Fatal(err)
	}

	selectColumns := map[string]bool{}

	var ft filterNode

	var limitOffset, limitRows *uint64

	switch stmt := stmt.(type) {
	case *sqlparser.Select:
		// Make sure all fields in
		// https://pkg.go.dev/github.com/xwb1989/sqlparser#Select that
		// we currently do not support stops the program
		if stmt.Cache != "" {
			log.Fatal("CACHE is not supported")
		}
		if stmt.Distinct != "" {
			log.Fatal("DISTINCT is not supported")
		}
		if stmt.Hints != "" {
			log.Fatal("Hints are not supported")
		}
		for _, selectColumn := range stmt.SelectExprs {
			if jsonFieldNames[sqlparser.String(selectColumn)] != "" || sqlparser.String(selectColumn) == "*" {
				selectColumns[sqlparser.String(selectColumn)] = true
			} else {
				fmt.Fprintf(os.Stderr, "'%s' is not a supported column, supported: %s\n", sqlparser.String(selectColumn), jsonFieldNamesSlice)
				os.Exit(1)
			}
		}
		if sqlparser.String(stmt.From) != "dnstap" {
			log.Fatal("only existing table is 'dnstap'")
		}
		if stmt.Where != nil {
			if stmt.Where.Type == "where" {
				ft = newFilterTree(stmt.Where.Expr, jsonFieldNames)
			}
		}
		if sqlparser.String(stmt.GroupBy) != "" {
			log.Fatal("GROUP BY is not supported")
		}
		if stmt.Having != nil {
			log.Fatal("HAVING is not supported")
		}
		if sqlparser.String(stmt.OrderBy) != "" {
			log.Fatal("ORDER BY is not supported")
		}
		if stmt.Limit != nil {
			if stmt.Limit.Offset != nil {
				switch e := stmt.Limit.Offset.(type) {
				case *sqlparser.SQLVal:
					*limitOffset, err = strconv.ParseUint(string(e.Val), 10, 64)
					if err != nil {
						log.Fatalf("unable to parse LIMIT offset: %s", err)
					}
				default:
					log.Fatalf("unknown LIMIT offset type: %#v", e)

				}
			}
			if stmt.Limit.Rowcount != nil {
				switch e := stmt.Limit.Rowcount.(type) {
				case *sqlparser.SQLVal:
					*limitRows, err = strconv.ParseUint(string(e.Val), 10, 64)
					if err != nil {
						log.Fatalf("unable to parse LIMIT rows: %s", err)
					}
				default:
					log.Fatalf("unknown LIMIT rows type: %#v", e)

				}
			}
		}
		if stmt.Lock != "" {
			log.Fatal("LOCK is not supported")
		}
	default:
		log.Fatal("Only SELECT statements are supported")
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

	var rowCount uint64
	var printedRows uint64
	for {

		if limitRows != nil {
			// Stop parsing rows if we have printed up to the requested LIMIT
			if printedRows == *limitRows {
				break
			}
		}

		rowCount++

		var dt dnstap.Dnstap

		if err := dec.Decode(&dt); err == io.EOF {
			break
		} else if err != nil {
			log.Fatal(err)
		}

		if limitOffset != nil {
			// Skip further parsing of current row if we have not reached
			// the given LIMIT offset yet. The rowCount is incremented
			// above so also skip when the count and offset is equal.
			if rowCount <= *limitOffset {
				continue
			}
		}

		pd := parsedData{
			boolData:   map[string]bool{},
			stringData: map[string]string{},
			uint32Data: map[string]uint32{},
			uint16Data: map[string]uint16{},
			timeData:   map[string]time.Time{},
		}
		var ddOut dtqData
		var queryAddress, responseAddress string

		isQuery := strings.HasSuffix(dnstap.Message_Type_name[int32(*dt.Message.Type)], "_QUERY")
		qa := net.IP(dt.Message.QueryAddress)
		ra := net.IP(dt.Message.ResponseAddress)

		msg := new(dns.Msg)

		if isQuery {
			pd.timeData["message_query_time"] = time.Unix(int64(*dt.Message.QueryTimeSec), int64(*dt.Message.QueryTimeNsec))
			if selectColumns["*"] || selectColumns["query_time_string"] {
				pd.stringData["query_time_string"] = pd.timeData["message_query_time"].Local().Format(time.RFC3339Nano)
			}
			err = msg.Unpack(dt.Message.QueryMessage)
			if err != nil {
				log.Printf("unable to unpack query message (%s -> %s): %s", queryAddress, responseAddress, err)
				msg = nil
			}
		} else {
			pd.timeData["message_response_time"] = time.Unix(int64(*dt.Message.ResponseTimeSec), int64(*dt.Message.ResponseTimeNsec))
			if selectColumns["*"] || selectColumns["response_time_string"] {
				pd.stringData["response_time_string"] = pd.timeData["message_response_time"].Local().Format(time.RFC3339Nano)
			}
			err = msg.Unpack(dt.Message.ResponseMessage)
			if err != nil {
				log.Printf("unable to unpack response message (%s <- %s): %s", queryAddress, responseAddress, err)
				msg = nil
			}
		}

		var dnsQuestionClassName string
		var dnsQuestionTypeName string

		if msg != nil {
			// IN, CH etc or synthesized "CLASS31337" based on the
			// numeric value if not a known class
			if c, ok := dns.ClassToString[msg.Question[0].Qclass]; ok {
				dnsQuestionClassName = c
			} else {
				dnsQuestionClassName = "CLASS" + strconv.FormatUint(uint64(msg.Question[0].Qclass), 10)
			}

			// A, MX, NS etc or synthesized "TYPE31337" based on the
			// numeric value if not a known type
			if t, ok := dns.TypeToString[msg.Question[0].Qtype]; ok {
				dnsQuestionTypeName = t
			} else {
				dnsQuestionTypeName = strconv.FormatUint(uint64(msg.Question[0].Qtype), 10)
			}
		}

		pd.boolData["dnstap_is_query"] = isQuery
		pd.stringData["dnstap_type_name"] = dnstap.Dnstap_Type_name[int32(*dt.Type)]
		pd.stringData["message_type_name"] = dnstap.Message_Type_name[int32(*dt.Message.Type)]
		pd.stringData["socket_family_name"] = dnstap.SocketFamily_name[int32(*dt.Message.SocketFamily)]
		pd.stringData["socket_protocol_name"] = dnstap.SocketProtocol_name[int32(*dt.Message.SocketProtocol)]

		if qa != nil {
			pd.stringData["query_address_string"] = qa.String()
			pd.uint32Data["query_port"] = *dt.Message.QueryPort
		}

		if ra != nil {
			pd.stringData["reponse_address_string"] = ra.String()
			pd.uint32Data["reponse_port"] = *dt.Message.ResponsePort
		}

		if msg != nil {
			pd.stringData["dns_question_name"] = msg.Question[0].Name
			pd.stringData["dns_question_class_name"] = dnsQuestionClassName
			pd.stringData["dns_question_type_name"] = dnsQuestionTypeName
			pd.uint16Data["dns_id"] = msg.Id
		}

		if ft != nil {
			if !evaluateFilter(ft, pd) {
				continue
			}
		}

		var err error

		if selectColumns["*"] || selectColumns["dnstap_is_query"] {
			ddOut.DnstapIsQuery = &isQuery
		}

		if selectColumns["*"] || selectColumns["dnstap_raw"] {
			ddOut.DnstapRaw = &dt
		}

		if selectColumns["*"] || selectColumns["dnstap_type_name"] {
			ddOut.DnstapTypeName = dnstap.Dnstap_Type_name[int32(*dt.Type)]
		}

		if selectColumns["*"] || selectColumns["message_type_name"] {
			ddOut.MessageTypeName = dnstap.Message_Type_name[int32(*dt.Message.Type)]
		}

		if selectColumns["*"] || selectColumns["socket_family_name"] {
			ddOut.SocketFamilyName = dnstap.SocketFamily_name[int32(*dt.Message.SocketFamily)]
		}

		if selectColumns["*"] || selectColumns["socket_protocol_name"] {
			ddOut.SocketProtocolName = dnstap.SocketProtocol_name[int32(*dt.Message.SocketProtocol)]
		}

		if selectColumns["*"] || selectColumns["query_address_string"] || selectColumns["query_port"] {

			if qa != nil {

				if selectColumns["*"] || selectColumns["query_address_string"] {
					ddOut.QueryAddressString = qa.String()
				}

				if selectColumns["*"] || selectColumns["query_port"] {
					ddOut.QueryPort = *dt.Message.QueryPort
				}
			}
		}

		if selectColumns["*"] || selectColumns["response_address_string"] || selectColumns["response_port"] {

			if ra != nil {
				if selectColumns["*"] || selectColumns["response_address_string"] {
					ddOut.ResponseAddressString = ra.String()
				}

				if selectColumns["*"] || selectColumns["response_port"] {
					ddOut.ResponsePort = *dt.Message.ResponsePort
				}
			}
		}

		if msg != nil {
			if selectColumns["*"] || selectColumns["dns_msg_raw"] {
				ddOut.DNSMsgRaw = msg
			}

			if selectColumns["*"] || selectColumns["dns_question_name"] {
				ddOut.DNSQuestionName = msg.Question[0].Name
			}

			if selectColumns["*"] || selectColumns["dns_question_class_name"] {
				ddOut.DNSQuestionClassName = dnsQuestionClassName
			}

			if selectColumns["*"] || selectColumns["dns_question_type_name"] {
				ddOut.DNSQuestionTypeName = dnsQuestionTypeName
			}

			if selectColumns["*"] || selectColumns["dns_id"] {
				ddOut.DNSID = msg.Id
			}
		}

		ddJSON, err := json.Marshal(&ddOut)
		if err != nil {
			log.Fatal(err)
		}

		fmt.Fprintf(bufStdout, "%s\n", ddJSON)

		printedRows++
	}

	err = bufStdout.Flush()
	if err != nil {
		log.Fatal(err)
	}
}

// Convert WHERE statement to a tree of type-specific filter nodes
func newFilterTree(expr sqlparser.Expr, jsonFieldNames map[string]string) filterNode {

	var n filterNode

	switch e := expr.(type) {

	case *sqlparser.AndExpr:
		n = &andNode{
			left:  newFilterTree(e.Left, jsonFieldNames),
			right: newFilterTree(e.Right, jsonFieldNames),
		}
	case *sqlparser.OrExpr:
		n = &orNode{
			left:  newFilterTree(e.Left, jsonFieldNames),
			right: newFilterTree(e.Right, jsonFieldNames),
		}
	case *sqlparser.ComparisonExpr:
		switch lhs := e.Left.(type) {
		case *sqlparser.ColName:
			colName := sqlparser.String(lhs)

			switch rhs := e.Right.(type) {
			case *sqlparser.SQLVal:
				switch rhs.Type {
				case sqlparser.StrVal:
					if jsonFieldNames[colName] != "string" {
						log.Fatalf("%s is a '%s' field, can not compare with string", colName, jsonFieldNames[colName])
					}
					switch e.Operator {
					case "=":
						n = &stringEqNode{
							colName: colName,
							val:     string(rhs.Val),
						}
					case "!=":
						n = &stringNotEqNode{
							colName: colName,
							val:     string(rhs.Val),
						}
					default:
						log.Fatal("unsupported operator for string comparision")
					}

				case sqlparser.IntVal:
					if jsonFieldNames[sqlparser.String(lhs.Name)] == "int32" {
						u, err := strconv.ParseUint(string(rhs.Val), 10, 32)
						if err != nil {
							log.Fatalf("unable to parse uint32 out of the right hand side integer: %s", err)
						}
						switch e.Operator {
						case "=":
							n = &uint32EqNode{
								colName: colName,
								val:     uint32(u),
							}
						case "!=":
							n = &uint32NotEqNode{
								colName: colName,
								val:     uint32(u),
							}
						default:
							log.Fatalf("unsupported uint32 operator: %s", e.Operator)
						}
					} else if jsonFieldNames[sqlparser.String(lhs.Name)] == "uint16" {
						u, err := strconv.ParseUint(string(rhs.Val), 10, 16)
						if err != nil {
							log.Fatalf("unable to parse uint16 out of the right hand side integer: %s", err)
						}
						switch e.Operator {
						case "=":
							n = &uint16EqNode{
								colName: colName,
								val:     uint16(u),
							}
						case "!=":
							n = &uint16EqNode{
								colName: colName,
								val:     uint16(u),
							}
						default:
							log.Fatalf("unsupported uint16 operator: %s", e.Operator)
						}
					} else {
						log.Fatalf("%s is a '%s' field, can not compare with integer", sqlparser.String(lhs.Name), jsonFieldNames[sqlparser.String(lhs.Name)])
					}

				default:
					log.Fatalf("got unsupported SQLVal in right hand side: %#v", rhs.Type)
				}
			case sqlparser.BoolVal:
				if jsonFieldNames[sqlparser.String(lhs.Name)] == "*bool" {
					n = &boolNode{
						colName: colName,
						val:     bool(rhs),
					}
				} else {
					log.Fatalf("%s is a '%s' field, can not compare with *bool", sqlparser.String(lhs.Name), jsonFieldNames[sqlparser.String(lhs.Name)])
				}
			default:
				log.Fatalf("unsupported RHS value: %T\n", rhs)
			}
		default:
			log.Fatalf("unsupported LHS type in comparision: %#v", lhs)
		}
	default:
		log.Fatalf("unsupported WHERE expression '%#v'", e)
	}

	return n

}

// Traverse filter tree and see of the given parsed record matches the filter
func evaluateFilter(fn filterNode, pd parsedData) bool {

	switch n := fn.(type) {
	case *andNode:
		if evaluateFilter(n.left, pd) && evaluateFilter(n.right, pd) {
			return true
		}
	case *orNode:
		if evaluateFilter(n.left, pd) || evaluateFilter(n.right, pd) {
			return true
		}
	case *stringEqNode:
		if n.val == pd.stringData[n.colName] {
			return true
		}
	case *stringNotEqNode:
		if n.val != pd.stringData[n.colName] {
			return true
		}
	case *uint16EqNode:
		if n.val == pd.uint16Data[n.colName] {
			return true
		}
	case *uint16NotEqNode:
		if n.val != pd.uint16Data[n.colName] {
			return true
		}
	case *uint32EqNode:
		if n.val == pd.uint32Data[n.colName] {
			return true
		}
	case *uint32NotEqNode:
		if n.val != pd.uint32Data[n.colName] {
			return true
		}
	case *boolNode:
		if n.val == pd.boolData[n.colName] {
			return true
		}
	default:
		log.Fatalf("unsupported filter node: %#v", n)
	}

	return false
}
