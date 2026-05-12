package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/oschwald/geoip2-golang"
)

var (
	cityDB *geoip2.Reader
	asnDB  *geoip2.Reader
)

const BindLogPath = "/var/log/bind/queries.log"

type RequestPayload struct {
	SchoolName string `json:"schoolName"`
	ClientIp   string `json:"clientIp"`
	V6Ip       string `json:"v6Ip"`
	Uuid       string `json:"uuid"`
}

type IPInfo struct {
	Region string `json:"regionName"`
	ISP    string `json:"isp"`
	Org    string `json:"org"`
}

type ParsedIP struct {
	IP         string `json:"ip"`
	Region     string `json:"region"`
	ISPBase    string `json:"ispBase"`
	Display    string `json:"display"`
	ISPFull    string `json:"ispFull"`
	MappedName string `json:"mappedName,omitempty"`
	MappedIP   string `json:"mappedIP,omitempty"`
}

type DNSMapping struct {
	Name     string
	MappedIP string
	Networks []*net.IPNet
}

var dnsMappings []DNSMapping

type SchoolIPMapping struct {
	School   string
	Networks []*net.IPNet
	ExactIPs []string
	IPRanges [][2]net.IP // start, end
}

var schoolMappings []SchoolIPMapping

func loadDNSList() {
	file, err := os.Open("dns.list")
	if err != nil {
		log.Println("No dns.list found, skipping DNS mapping")
		return
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.Split(line, "|")
		if len(parts) < 3 {
			continue
		}
		name := parts[0]
		mappedIP := parts[1]
		cidrs := strings.Split(parts[2], ";")

		var networks []*net.IPNet
		for _, cidr := range cidrs {
			cidr = strings.TrimSpace(cidr)
			if cidr == "" {
				continue
			}
			_, ipnet, err := net.ParseCIDR(cidr)
			if err == nil {
				networks = append(networks, ipnet)
			}
		}
		dnsMappings = append(dnsMappings, DNSMapping{
			Name:     name,
			MappedIP: mappedIP,
			Networks: networks,
		})
	}
	log.Printf("Loaded %d DNS mapping rules", len(dnsMappings))
}

func loadSchoolIPs() {
	file, err := os.Open("school_ips.json")
	if err != nil {
		log.Println("No school_ips.json found, skipping school detection")
		return
	}
	defer file.Close()

	var rawData []struct {
		School string   `json:"school"`
		IPs    []string `json:"ips"`
	}
	if err := json.NewDecoder(file).Decode(&rawData); err != nil {
		log.Printf("Failed to decode school_ips.json: %v", err)
		return
	}

	for _, item := range rawData {
		mapping := SchoolIPMapping{School: item.School}
		for _, ipStr := range item.IPs {
			if strings.Contains(ipStr, "/") {
				_, ipnet, err := net.ParseCIDR(ipStr)
				if err == nil {
					mapping.Networks = append(mapping.Networks, ipnet)
				}
			} else if strings.Contains(ipStr, "-") {
				parts := strings.Split(ipStr, "-")
				if len(parts) == 2 {
					start := net.ParseIP(strings.TrimSpace(parts[0]))
					end := net.ParseIP(strings.TrimSpace(parts[1]))
					if start != nil && end != nil {
						mapping.IPRanges = append(mapping.IPRanges, [2]net.IP{start, end})
					}
				}
			} else {
				mapping.ExactIPs = append(mapping.ExactIPs, strings.TrimSpace(ipStr))
			}
		}
		schoolMappings = append(schoolMappings, mapping)
	}
	log.Printf("Loaded %d school IP mapping rules", len(schoolMappings))
}

func matchSchool(ipStr string) string {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return ""
	}

	for _, mapping := range schoolMappings {
		for _, exact := range mapping.ExactIPs {
			if exact == ipStr {
				return mapping.School
			}
		}
		for _, network := range mapping.Networks {
			if network.Contains(ip) {
				return mapping.School
			}
		}
		for _, r := range mapping.IPRanges {
			if ipInRange(ip, r[0], r[1]) {
				return mapping.School
			}
		}
	}
	return ""
}

func ipInRange(ip, start, end net.IP) bool {
	ip4 := ip.To4()
	start4 := start.To4()
	end4 := end.To4()
	if ip4 == nil || start4 == nil || end4 == nil {
		return false
	}
	return compareIP(ip4, start4) >= 0 && compareIP(ip4, end4) <= 0
}

func compareIP(a, b net.IP) int {
	for i := 0; i < len(a); i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	return 0
}

func detectSchoolHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	ip := getClientIP(r)
	school := matchSchool(ip)
	json.NewEncoder(w).Encode(map[string]string{"school": school})
}

func main() {
	loadDNSList()
	loadSchoolIPs()

	var err error
	cityDB, err = geoip2.Open("GeoLite2-City_20260508/GeoLite2-City.mmdb")
	if err != nil {
		log.Fatalf("Error opening City database: %v", err)
	}
	defer cityDB.Close()

	asnDB, err = geoip2.Open("GeoLite2-ASN_20260508/GeoLite2-ASN.mmdb")
	if err != nil {
		log.Fatalf("Error opening ASN database: %v", err)
	}
	defer asnDB.Close()

	fs := http.FileServer(http.Dir("./static"))
	http.Handle("/", fs)
	http.HandleFunc("/api/ip", ipHandler)
	http.HandleFunc("/api/submit", submitHandler)
	http.HandleFunc("/admin_dashboard_secured", adminPageHandler)
	http.HandleFunc("/api/records", recordsAPIHandler)
	http.HandleFunc("/api/client_submit", clientSubmitHandler)
	http.HandleFunc("/api/client_records", clientRecordsAPIHandler)
	http.HandleFunc("/api/detect_school", detectSchoolHandler)

	log.Println("Starting Web server on :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatalf("Web server failed: %v", err)
	}
}

func ipHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Content-Type", "application/json")
	ip := getClientIP(r)
	json.NewEncoder(w).Encode(map[string]string{"ip": ip})
}

func submitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var req RequestPayload
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.SchoolName == "10086admin" {
		http.SetCookie(w, &http.Cookie{
			Name:     "auth_token",
			Value:    "super_secret_10086",
			Path:     "/",
			HttpOnly: true,
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":   "redirect",
			"redirect": "/admin_dashboard_secured",
		})
		return
	}

	if req.ClientIp == "" {
		req.ClientIp = getClientIP(r)
	}

	recursiveIp := findRecursiveIPFromLog(req.Uuid)
	if recursiveIp == "" {
		recursiveIp = "Not Detected / Timeout"
	}

	clientParsed := getParsedIP(req.ClientIp)
	v6Parsed := getParsedIP(req.V6Ip)
	recursiveParsed := getParsedIP(recursiveIp)

	if parsedRecIP := net.ParseIP(recursiveIp); parsedRecIP != nil {
		for _, mapping := range dnsMappings {
			matched := false
			for _, network := range mapping.Networks {
				if network.Contains(parsedRecIP) {
					matched = true
					break
				}
			}
			if matched {
				recursiveParsed.MappedName = mapping.Name
				recursiveParsed.MappedIP = mapping.MappedIP
				break
			}
		}
	}

	traceId := req.Uuid
	if len(traceId) > 8 {
		traceId = traceId[:8]
	}

	mappedStr := recursiveParsed.MappedIP
	if recursiveParsed.MappedName != "" {
		mappedStr += fmt.Sprintf(" (%s)", recursiveParsed.MappedName)
	}

	_, port, _ := net.SplitHostPort(r.RemoteAddr)
	line := fmt.Sprintf("[%s] TraceID: %s | School: %s | ClientIP: %s | SourcePort: %s | V6IP: %s | RecursiveDNS: %s | 真实DNS: %s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		traceId, req.SchoolName, clientParsed.Display, port, v6Parsed.Display, recursiveParsed.Display, mappedStr)

	log.Print("Record collected: ", line)

	f, err := os.OpenFile("records.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open records.txt: %v", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(line); err != nil {
		log.Printf("Failed to write to records.txt: %v", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"status":    "success",
		"client":    clientParsed,
		"v6":        v6Parsed,
		"recursive": recursiveParsed,
	})
}

var regionMap = map[string]string{
	"Beijing": "北京", "Shanghai": "上海", "Tianjin": "天津", "Chongqing": "重庆",
	"Hebei": "河北", "Shanxi": "山西", "Liaoning": "辽宁", "Jilin": "吉林", "Heilongjiang": "黑龙江",
	"Jiangsu": "江苏", "Zhejiang": "浙江", "Anhui": "安徽", "Fujian": "福建", "Jiangxi": "江西", "Shandong": "山东",
	"Henan": "河南", "Hubei": "湖北", "Hunan": "湖南", "Guangdong": "广东", "Hainan": "海南",
	"Sichuan": "四川", "Guizhou": "贵州", "Yunnan": "云南", "Shaanxi": "陕西", "Gansu": "甘肃",
	"Qinghai": "青海", "Taiwan": "台湾", "Inner Mongolia": "内蒙古", "Guangxi": "广西",
	"Tibet": "西藏", "Ningxia": "宁夏", "Xinjiang": "新疆", "Hong Kong": "香港", "Macao": "澳门",
}

type Record struct {
	Time         string `json:"time"`
	TraceID      string `json:"traceId"`
	School       string `json:"school"`
	ClientIP     string `json:"clientIp"`
	V6IP         string `json:"v6Ip"`
	RecursiveDNS string `json:"recursiveDns"`
	MappedDNS    string `json:"mappedDns"`
	Status       string `json:"status"`
	SourcePort   string `json:"sourcePort"`
}

func extractISP(s string) string {
	start := strings.Index(s, "(")
	end := strings.Index(s, ")")
	if start != -1 && end != -1 && end > start {
		return s[start+1 : end]
	}
	return ""
}

func adminPageHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("auth_token")
	if err != nil || cookie.Value != "super_secret_10086" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	http.ServeFile(w, r, "report.html")
}

func recordsAPIHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("auth_token")
	if err != nil || cookie.Value != "super_secret_10086" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	file, err := os.Open("records.txt")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]Record{})
		return
	}
	defer file.Close()

	var records []Record
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, " | ")
		if len(parts) < 5 {
			continue
		}

		rec := Record{}
		if strings.HasPrefix(parts[0], "[") {
			closeIdx := strings.Index(parts[0], "]")
			if closeIdx > 0 {
				rec.Time = parts[0][1:closeIdx]
				idPart := parts[0][closeIdx+1:]
				rec.TraceID = strings.TrimPrefix(strings.TrimSpace(idPart), "TraceID: ")
			}
		}

		for _, p := range parts[1:] {
			if strings.HasPrefix(p, "School: ") {
				rec.School = strings.TrimPrefix(p, "School: ")
			} else if strings.HasPrefix(p, "ClientIP: ") {
				rec.ClientIP = strings.TrimPrefix(p, "ClientIP: ")
			} else if strings.HasPrefix(p, "SourcePort: ") {
				rec.SourcePort = strings.TrimPrefix(p, "SourcePort: ")
			} else if strings.HasPrefix(p, "V6IP: ") {
				rec.V6IP = strings.TrimPrefix(p, "V6IP: ")
			} else if strings.HasPrefix(p, "RecursiveDNS: ") {
				rec.RecursiveDNS = strings.TrimPrefix(p, "RecursiveDNS: ")
			} else if strings.HasPrefix(p, "真实DNS: ") {
				rec.MappedDNS = strings.TrimPrefix(p, "真实DNS: ")
			} else if strings.HasPrefix(p, "MappedDNS: ") {
				rec.MappedDNS = strings.TrimPrefix(p, "MappedDNS: ")
			}
		}

		clientISP := extractISP(rec.ClientIP)
		recISP := extractISP(rec.RecursiveDNS)
		if clientISP != "" && recISP != "" && clientISP == recISP {
			rec.Status = "正常"
		} else {
			rec.Status = "异常"
		}

		records = append(records, rec)
	}

	for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
		records[i], records[j] = records[j], records[i]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(records)
}

type ClientReportData struct {
	School         string `json:"school"`
	LocalIP        string `json:"local_ip"`
	PublicIP       string `json:"public_ip"`
	ConfiguredDNS  string `json:"configured_dns"`
	InterfacesInfo string `json:"interfaces_info"`
	Routes         string `json:"routes"`
	OutboundIF     string `json:"outbound_if"`
	C4Result       string `json:"c4_result"`
}

type ClientRecord struct {
	Time           string `json:"time"`
	School         string `json:"school"`
	LocalIP        string `json:"localIp"`
	PublicIP       string `json:"publicIp"`
	ConfiguredDNS  string `json:"configuredDns"`
	InterfacesInfo string `json:"interfacesInfo"`
	Routes         string `json:"routes"`
	OutboundIF     string `json:"outboundIf"`
	C4Result       string `json:"c4Result"`
	SourcePort     string `json:"sourcePort"`
}

func clientSubmitHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var data ClientReportData
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	// Escape newlines in Routes for flat file storage
	escapedRoutes := strings.ReplaceAll(data.Routes, "\n", "\\n")

	_, port, _ := net.SplitHostPort(r.RemoteAddr)

	// Enrich PublicIP
	enrichedPublicIP := data.PublicIP
	if data.PublicIP != "" {
		pip := getParsedIP(data.PublicIP)
		if pip.ISPFull != "未知" {
			enrichedPublicIP = fmt.Sprintf("%s(%s)", pip.IP, pip.ISPFull)
		}
	}

	// Enrich ConfiguredDNS
	enrichedDNSStr := data.ConfiguredDNS
	if data.ConfiguredDNS != "" {
		dnsList := strings.Split(data.ConfiguredDNS, ", ")
		var enrichedDNS []string
		for _, d := range dnsList {
			d = strings.TrimSpace(d)
			if d != "" {
				pdns := getParsedIP(d)
				if pdns.ISPFull != "未知" {
					enrichedDNS = append(enrichedDNS, fmt.Sprintf("%s(%s)", pdns.IP, pdns.ISPFull))
				} else {
					enrichedDNS = append(enrichedDNS, d)
				}
			}
		}
		enrichedDNSStr = strings.Join(enrichedDNS, ", ")
	}

	// Enrich C4Result
	enrichedC4Result := data.C4Result
	if data.C4Result != "" && !strings.Contains(data.C4Result, "失败") {
		operator := ""
		if strings.Contains(data.C4Result, "112.0.0.139") {
			operator = "移动"
		} else if strings.Contains(data.C4Result, "218.0.0.189") {
			operator = "电信"
		} else if strings.Contains(data.C4Result, "221.0.0.130") {
			operator = "联通"
		} else if strings.Contains(data.C4Result, "166.111.0.61") {
			operator = "教育网"
		}

		if operator != "" {
			enrichedC4Result = fmt.Sprintf("%s(%s)", data.C4Result, operator)
		} else {
			pc4 := getParsedIP(data.C4Result)
			if pc4.ISPFull != "未知" {
				enrichedC4Result = fmt.Sprintf("%s(%s)", pc4.IP, pc4.ISPFull)
			}
		}
	}

	line := fmt.Sprintf("[%s] LocalIP: %s | PublicIP: %s | SourcePort: %s | ConfiguredDNS: %s | School: %s | OutboundIF: %s | C4Result: %s | InterfacesInfo: %s | Routes: %s\n",
		time.Now().Format("2006-01-02 15:04:05"),
		data.LocalIP, enrichedPublicIP, port, enrichedDNSStr, data.School, data.OutboundIF, enrichedC4Result, data.InterfacesInfo, escapedRoutes)

	log.Print("Client record collected (with routes & interfaces)")

	f, err := os.OpenFile("client_records.txt", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Printf("Failed to open client_records.txt: %v", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	defer f.Close()

	if _, err := f.WriteString(line); err != nil {
		log.Printf("Failed to write to client_records.txt: %v", err)
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"status": "success"})
}

func clientRecordsAPIHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("auth_token")
	if err != nil || cookie.Value != "super_secret_10086" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	file, err := os.Open("client_records.txt")
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode([]ClientRecord{})
		return
	}
	defer file.Close()

	var records []ClientRecord
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Split(line, " | ")
		if len(parts) < 3 {
			continue
		}

		rec := ClientRecord{}
		if strings.HasPrefix(parts[0], "[") {
			closeIdx := strings.Index(parts[0], "]")
			if closeIdx > 0 {
				rec.Time = parts[0][1:closeIdx]
				ipPart := parts[0][closeIdx+1:]
				rec.LocalIP = strings.TrimPrefix(strings.TrimSpace(ipPart), "LocalIP: ")
			}
		}

		for _, p := range parts[1:] {
			if strings.HasPrefix(p, "PublicIP: ") {
				rec.PublicIP = strings.TrimPrefix(p, "PublicIP: ")
			} else if strings.HasPrefix(p, "ConfiguredDNS: ") {
				rec.ConfiguredDNS = strings.TrimPrefix(p, "ConfiguredDNS: ")
			} else if strings.HasPrefix(p, "School: ") {
				rec.School = strings.TrimPrefix(p, "School: ")
			} else if strings.HasPrefix(p, "OutboundIF: ") {
				rec.OutboundIF = strings.TrimPrefix(p, "OutboundIF: ")
			} else if strings.HasPrefix(p, "SourcePort: ") {
				rec.SourcePort = strings.TrimPrefix(p, "SourcePort: ")
			} else if strings.HasPrefix(p, "C4Result: ") {
				rec.C4Result = strings.TrimPrefix(p, "C4Result: ")
			} else if strings.HasPrefix(p, "InterfacesInfo: ") {
				rec.InterfacesInfo = strings.TrimPrefix(p, "InterfacesInfo: ")
			} else if strings.HasPrefix(p, "Routes: ") {
				escapedRoutes := strings.TrimPrefix(p, "Routes: ")
				rec.Routes = strings.ReplaceAll(escapedRoutes, "\\n", "\n")
			}
		}

		records = append(records, rec)
	}

	for i, j := 0, len(records)-1; i < j; i, j = i+1, j-1 {
		records[i], records[j] = records[j], records[i]
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(records)
}

func normalizeISP(info IPInfo) (string, string, bool) {
	combined := strings.ToLower(info.ISP + " " + info.Org)
	var ispBase string
	matched := true
	switch {
	case strings.Contains(combined, "telecom") || strings.Contains(combined, "chinanet"):
		ispBase = "电信"
	case strings.Contains(combined, "unicom"):
		ispBase = "联通"
	case strings.Contains(combined, "mobile") || strings.Contains(combined, "cmcc"):
		ispBase = "移动"
	case strings.Contains(combined, "tietong"):
		ispBase = "铁通"
	case strings.Contains(combined, "cernet") || strings.Contains(combined, "education"):
		ispBase = "教育网"
	case strings.Contains(combined, "radio") || strings.Contains(combined, "broadcasting"):
		ispBase = "广电"
	default:
		ispBase = info.ISP
		if ispBase == "" {
			ispBase = info.Org
		}
		matched = false
	}

	region := regionMap[info.Region]
	if region == "" {
		region = info.Region // 没有命中则用英文
	}

	return region, ispBase, matched
}

var asnOverrideMap = map[uint]string{
	137702: "电信", // Chinanet Jiangsu Province Network
}

func fetchFromIpwhois(ip string) IPInfo {
	var info IPInfo
	client := http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(fmt.Sprintf("https://ipwhois.app/json/%s", ip))
	if err != nil {
		return info
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var res struct {
			Region string `json:"region"`
			ISP    string `json:"isp"`
			Org    string `json:"org"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err == nil {
			info.Region = res.Region
			info.ISP = res.ISP
			info.Org = res.Org
		}
	}
	return info
}

func getParsedIP(ip string) ParsedIP {
	res := ParsedIP{IP: ip, Display: ip, ISPFull: "未知", ISPBase: "未知"}
	if ip == "" || ip == "v6访问失败" || ip == "未检测到IPV6地址" || ip == "Not Detected / Timeout" || strings.Contains(ip, "未能获取") {
		return res
	}

	parsedIP := net.ParseIP(ip)
	if parsedIP == nil {
		return res
	}

	var info IPInfo

	cityRecord, err := cityDB.City(parsedIP)
	if err == nil && len(cityRecord.Subdivisions) > 0 {
		info.Region = cityRecord.Subdivisions[0].Names["en"]
	}

	asnRecord, err := asnDB.ASN(parsedIP)
	if err == nil {
		if overrideISP, ok := asnOverrideMap[uint(asnRecord.AutonomousSystemNumber)]; ok {
			info.ISP = overrideISP
			info.Org = overrideISP
		} else {
			info.ISP = asnRecord.AutonomousSystemOrganization
			info.Org = asnRecord.AutonomousSystemOrganization
		}
	}

	region, ispBase, matched := normalizeISP(info)

	if !matched || ispBase == "" || strings.Contains(strings.ToLower(ispBase), "p.r.china") {
		apiInfo := fetchFromIpwhois(ip)
		if apiInfo.ISP != "" || apiInfo.Org != "" {
			apiRegion, apiIspBase, apiMatched := normalizeISP(apiInfo)
			if apiMatched || ispBase == "" || strings.Contains(strings.ToLower(ispBase), "p.r.china") {
				if region == "" || apiRegion != "" {
					region = apiRegion
				}
				ispBase = apiIspBase
			}
		}
	}

	res.Region = region
	res.ISPBase = ispBase

	if ispBase != "" {
		res.ISPFull = ispBase
	} else if region != "" {
		res.ISPFull = region
	}

	if res.ISPFull != "未知" {
		res.Display = fmt.Sprintf("%s (%s)", ip, res.ISPFull)
	}
	return res
}

func findRecursiveIPFromLog(hash string) string {
	for i := 0; i < 10; i++ {
		ip := scanLogForHash(hash)
		if ip != "" {
			return ip
		}
		time.Sleep(1 * time.Second)
	}
	return ""
}

func scanLogForHash(hash string) string {
	file, err := os.Open(BindLogPath)
	if err != nil {
		log.Printf("Failed to open bind log %s: %v", BindLogPath, err)
		return ""
	}
	defer file.Close()

	targetQuery := strings.ToLower(fmt.Sprintf("query: %s.dns.dnscheck.cloud", hash))
	re := regexp.MustCompile(`client @[^\s]+ ([0-9a-fA-F:\.]+)#`)

	scanner := bufio.NewScanner(file)
	var lastMatchedIP string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(strings.ToLower(line), targetQuery) {
			matches := re.FindStringSubmatch(line)
			if len(matches) > 1 {
				lastMatchedIP = matches[1]
			}
		}
	}
	return lastMatchedIP
}

func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		return strings.TrimSpace(ips[0])
	}
	if realIp := r.Header.Get("X-Real-IP"); realIp != "" {
		return strings.TrimSpace(realIp)
	}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}
