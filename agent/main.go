package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

const ServerURL = "http://118.195.157.188:8080/"

type ClientData struct {
	School         string `json:"school"`
	LocalIP        string `json:"local_ip"`
	PublicIP       string `json:"public_ip"`
	ConfiguredDNS  string `json:"configured_dns"`
	InterfacesInfo string `json:"interfaces_info"`
	Routes         string `json:"routes"`
	OutboundIF     string `json:"outbound_if"`
	C4Result       string `json:"c4_result"`
}

type InterfaceDetails struct {
	Name string
	IPs  []string
	DNS  []string
}

func getPublicIP() string {
	client := http.Client{Timeout: 5 * time.Second}
	url := strings.TrimRight(ServerURL, "/") + "/api/ip"
	resp, err := client.Get(url)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		var res struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&res); err == nil {
			return res.IP
		}
	}
	return ""
}

func resolveDomain(domain string) string {
	ips, err := net.LookupIP(domain)
	if err != nil {
		return "解析失败: " + err.Error()
	}
	var ipStrs []string
	for _, ip := range ips {
		ipStrs = append(ipStrs, ip.String())
	}
	return strings.Join(ipStrs, ",")
}

func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return ""
	}
	defer conn.Close()
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP.String()
}

func getRoutes() string {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// 强制让 PowerShell 输出 UTF-8 编码，解决中文 Windows 下 route print 乱码问题
		cmd = exec.Command("powershell", "-Command", "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; route print -4")
	} else if runtime.GOOS == "darwin" {
		cmd = exec.Command("netstat", "-rn", "-f", "inet")
	} else {
		cmd = exec.Command("ip", "route")
		if err := cmd.Run(); err != nil { // Fallback if ip route fails
			cmd = exec.Command("netstat", "-rn")
		} else {
			cmd = exec.Command("ip", "route") // reset cmd to run again
		}
	}
	out, err := cmd.Output()
	if err != nil {
		return "无法获取路由表"
	}
	return string(out)
}

func getInterfacesInfo() ([]InterfaceDetails, string, string) {
	outboundIP := getOutboundIP()
	outboundIFName := "未知"

	var results []InterfaceDetails
	globalDNS := []string{}

	// MAC/LINUX: Get global DNS first
	if runtime.GOOS != "windows" {
		data, err := os.ReadFile("/etc/resolv.conf")
		if err == nil {
			lines := strings.Split(string(data), "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "nameserver ") {
					ipStr := strings.TrimSpace(strings.TrimPrefix(line, "nameserver "))
					if net.ParseIP(ipStr) != nil {
						globalDNS = append(globalDNS, ipStr)
					}
				}
			}
		}
	}

	if runtime.GOOS == "windows" {
		// Use PowerShell to get rich interface info
		psCmd := `Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object {$_.IPEnabled -eq $true} | Select-Object Description, IPAddress, DNSServerSearchOrder | ConvertTo-Json`
		cmd := exec.Command("powershell", "-Command", psCmd)
		out, err := cmd.Output()
		if err == nil && len(out) > 0 {
			var parsed []map[string]interface{}
			// It might be a single object or an array of objects
			if out[0] == '{' {
				var single map[string]interface{}
				if err := json.Unmarshal(out, &single); err == nil {
					parsed = append(parsed, single)
				}
			} else {
				json.Unmarshal(out, &parsed)
			}

			for _, p := range parsed {
				detail := InterfaceDetails{}
				if desc, ok := p["Description"].(string); ok {
					detail.Name = desc
				}

				// Parse IPAddress
				if ipAddrs, ok := p["IPAddress"].([]interface{}); ok {
					for _, ip := range ipAddrs {
						if ipStr, ok := ip.(string); ok {
							if net.ParseIP(ipStr).To4() != nil {
								detail.IPs = append(detail.IPs, ipStr)
								if ipStr == outboundIP {
									outboundIFName = detail.Name
								}
							}
						}
					}
				} else if ipStr, ok := p["IPAddress"].(string); ok {
					if net.ParseIP(ipStr).To4() != nil {
						detail.IPs = append(detail.IPs, ipStr)
						if ipStr == outboundIP {
							outboundIFName = detail.Name
						}
					}
				}

				// Parse DNSServerSearchOrder
				if dnsAddrs, ok := p["DNSServerSearchOrder"].([]interface{}); ok {
					for _, dns := range dnsAddrs {
						if dnsStr, ok := dns.(string); ok {
							detail.DNS = append(detail.DNS, dnsStr)
						}
					}
				} else if dnsStr, ok := p["DNSServerSearchOrder"].(string); ok {
					detail.DNS = append(detail.DNS, dnsStr)
				}

				if len(detail.IPs) > 0 {
					results = append(results, detail)
				}
			}
		}
	} else {
		// Mac/Linux native interfaces
		interfaces, err := net.Interfaces()
		if err == nil {
			for _, i := range interfaces {
				if i.Flags&net.FlagUp == 0 || i.Flags&net.FlagLoopback != 0 {
					continue
				}
				addrs, err := i.Addrs()
				if err != nil {
					continue
				}
				detail := InterfaceDetails{
					Name: i.Name,
					DNS:  globalDNS, // Use global DNS as fallback for Mac/Linux
				}
				for _, addr := range addrs {
					var ip net.IP
					switch v := addr.(type) {
					case *net.IPNet:
						ip = v.IP
					case *net.IPAddr:
						ip = v.IP
					}
					if ip == nil || ip.IsLoopback() {
						continue
					}
					ip4 := ip.To4()
					if ip4 != nil {
						ipStr := ip4.String()
						detail.IPs = append(detail.IPs, ipStr)
						if ipStr == outboundIP {
							outboundIFName = detail.Name
						}
					}
				}
				if len(detail.IPs) > 0 {
					results = append(results, detail)
				}
			}
		}
	}

	var infos []string
	for _, r := range results {
		infos = append(infos, fmt.Sprintf("%s|%s|%s", r.Name, strings.Join(r.IPs, ","), strings.Join(r.DNS, ",")))
	}
	
	outboundStr := ""
	if outboundIP != "" {
		outboundStr = fmt.Sprintf("%s (%s)", outboundIFName, outboundIP)
	}

	return results, strings.Join(infos, ";"), outboundStr
}

func main() {
	fmt.Println("=====================================")
	fmt.Println("    网络环境连通性与 DNS 自检工具")
	fmt.Println("=====================================")

	fmt.Print("请输入您的学校名称 (按回车确认): ")
	reader := bufio.NewReader(os.Stdin)
	schoolName, _ := reader.ReadString('\n')
	schoolName = strings.TrimSpace(schoolName)

	if schoolName == "" {
		schoolName = "未知学校"
	}

	fmt.Println("正在收集网络信息，请稍候...")

	ifDetails, infoStr, outIF := getInterfacesInfo()
	outIP := getOutboundIP()
	
	// Default configured DNS for backward compatibility
	var globalDNSList []string
	for _, d := range ifDetails {
		globalDNSList = append(globalDNSList, d.DNS...)
	}
	
	// Deduplicate
	dnsMap := make(map[string]bool)
	var uniqueDNS []string
	for _, dns := range globalDNSList {
		if !dnsMap[dns] && dns != "" {
			dnsMap[dns] = true
			uniqueDNS = append(uniqueDNS, dns)
		}
	}

	data := ClientData{
		School:         schoolName,
		LocalIP:        outIP,
		PublicIP:       getPublicIP(),
		ConfiguredDNS:  strings.Join(uniqueDNS, ", "),
		InterfacesInfo: infoStr,
		Routes:         getRoutes(),
		OutboundIF:     outIF,
		C4Result:       resolveDomain("c4.xhaoma.net"),
	}

	fmt.Printf("\n[结果]\n")
	fmt.Printf("- 学校名称:\t %s\n", data.School)
	fmt.Printf("- 出网网卡:\t %s\n", data.OutboundIF)
	fmt.Printf("- 公网 IP:\t %s\n", data.PublicIP)
	fmt.Printf("- 域名解析拨测:\t %s\n", data.C4Result)
	fmt.Printf("- 所有网卡信息:\n")
	for _, d := range ifDetails {
		fmt.Printf("  > %s\n", d.Name)
		fmt.Printf("    IP:  %s\n", strings.Join(d.IPs, ", "))
		fmt.Printf("    DNS: %s\n", strings.Join(d.DNS, ", "))
	}
	fmt.Println()

	fmt.Println("正在上报至服务器...")

	payload, _ := json.Marshal(data)
	url := strings.TrimRight(ServerURL, "/") + "/api/client_submit"
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(payload))
	if err != nil {
		fmt.Printf("上报失败: 连接服务器错误 (%v)\n", err)

		if runtime.GOOS == "windows" {
			fmt.Println("按回车键退出...")
			fmt.Scanln()
		}
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		fmt.Println("上报成功！感谢您的配合。")
	} else {
		body, _ := io.ReadAll(resp.Body)
		fmt.Printf("上报失败, 服务端返回异常状态码: %d, 信息: %s\n", resp.StatusCode, string(body))
	}

	if runtime.GOOS == "windows" {
		fmt.Println("按回车键退出...")
		fmt.Scanln()
	}
}
