package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
	"github.com/ilyakaznacheev/cleanenv"
	"github.com/projectdiscovery/goflags"
	"github.com/projectdiscovery/gologger"
	"io"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	//colorPurple := "\033[35m"
	//colorCyan := "\033[36m"
	//colorWhite := "\033[37m"
)

var wg sync.WaitGroup

type fetcher func(url string) []*net.IPNet
type CDN struct {
	url    string
	sender fetcher
}
type Config struct {
	SendRequest []string `yaml:"SendRequest"`
	ReadFileUrl []string `yaml:"ReadFileUrl"`
}

var config Config
var CDNS = []CDN{}
var input, output, savePath string
var isSilent, showVersion, activeMode, updateAll, updateRanges bool
var thread int

const VERSION = "1.0.28"

var homeDIR, _ = os.UserHomeDir()

func main() {
	var allRange []*net.IPNet
	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("Removing CDN IPs from the list of IP addresses")
	createGroup(flagSet, "input", "Input",
		flagSet.StringVarP(&input, "ip", "i", "", "Input [Filename | IP]"),
	)

	createGroup(flagSet, "rate-limit", "Rate-Limit",
		flagSet.IntVarP(&thread, "thread", "t", 1, "Number Of Thread [Number]"),
	)

	flagSet.CreateGroup("configs", "Configurations",
		flagSet.BoolVarP(&activeMode, "active", "a", false, "Active mode for check akamai"),
		flagSet.BoolVarP(&updateAll, "update-all", "ua", false, "Update CUT-CDN Data (providers & ranges)"),
		flagSet.BoolVarP(&updateRanges, "update-ranges", "ur", false, "Update CUT-CDN Data (just ranges)"),
	)

	createGroup(flagSet, "output", "Output",
		flagSet.StringVarP(&output, "output", "o", "CLI", "File to write output to (optional)"),
	)

	createGroup(flagSet, "debug", "Debug",
		flagSet.BoolVarP(&isSilent, "silent", "q", false, "Show only IPs in output"),
		flagSet.BoolVarP(&showVersion, "version", "v", false, "Show version of cut-cdn"),
	)

	_ = flagSet.Parse()
	baseConfig(updateAll, updateRanges)
	fi, err := os.Stdin.Stat()
	checkError(err)

	if showVersion {
		printText(false, "Current Version: v"+VERSION, "Info")
		os.Exit(0)
	}

	if input == "" && fi.Mode()&os.ModeNamedPipe == 0 && savePath == "" {
		printText(isSilent, "Input is empty!\n\n", "Error")
		flag.PrintDefaults()
		os.Exit(1)
	}
	checkUpdate(isSilent)

	printText(isSilent, "Loading All CDN Range", "Info")
	allRange = loadAllCDN()
	printText(isSilent, "All CDN Range Loaded", "Info")

	if input == "" && fi.Mode()&os.ModeNamedPipe == 0 {
		os.Exit(0)
	}

	if output != "CLI" {
		_, err := os.Create(output)
		checkError(err)
	}

	var allIpInput []string
	if fi.Mode()&os.ModeNamedPipe != 0 {
		allIpInput = readInput(isSilent, "STDIN")
	} else {
		allIpInput = readInput(isSilent, input)
	}
	channel := make(chan string, len(allIpInput))
	for _, ip := range allIpInput {
		channel <- ip
	}

	close(channel)

	printText(isSilent, "Start Checking IPs", "Info")
	if output == "CLI" {
		printText(isSilent, "", "Print")
		printText(isSilent, colorGreen+"[⚡] All IPs Not Behind CDN ⤵"+colorReset, "Print")
	}
	for i := 0; i < thread; i++ {
		wg.Add(1)
		go checkAndWrite(allRange, channel, output)
	}
	wg.Wait()

	printText(isSilent, "", "Print")
	printText(isSilent, "Github page: https://github.com/ImAyrix/cut-cdn", "Print")
}

func loadAllCDN() []*net.IPNet {
	var allRanges []*net.IPNet
	data, err := os.ReadFile(homeDIR + "/cut-cdn/ranges.txt")
	checkError(err)

	for _, cidr := range strings.Split(string(data), "\n") {
		if cidr != "" {
			_, cidr, _ := net.ParseCIDR(string(cidr))
			allRanges = append(allRanges, cidr)
		}
	}
	return allRanges
}

func loadAllCDNOnline() []*net.IPNet {
	var wg sync.WaitGroup
	var allRanges []*net.IPNet

	cleanenv.ReadConfig(homeDIR+"/cut-cdn/providers.yaml", &config)
	sendReqs := config.SendRequest
	readFiles := config.ReadFileUrl

	for _, v := range sendReqs {
		if v != "" {
			CDNS = append(CDNS, CDN{v, sendRequest})
		}
	}
	for _, v := range readFiles {
		if v != "" {
			CDNS = append(CDNS, CDN{v, readFileUrl})
		}
	}

	cidrChan := make(chan []*net.IPNet, len(CDNS)+1)
	wg.Add(len(CDNS))

	for _, cdn := range CDNS {
		cdn := cdn
		go func() {
			defer wg.Done()
			cidr := cdn.sender(cdn.url)
			cidrChan <- cidr
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		incapsulaIPUrl := "https://my.incapsula.com/api/integration/v1/ips"
		client := &http.Client{
			Timeout: 30 * time.Second,
		}
		resp, err := client.Post(incapsulaIPUrl, "application/x-www-form-urlencoded", bytes.NewBuffer([]byte("resp_format=text")))
		if !checkError(err) {
			body, err := io.ReadAll(resp.Body)
			checkError(err)
			cidr := regexIp(string(body))
			cidrChan <- cidr
		}
	}()

	wg.Wait()
	close(cidrChan)

	for cidr := range cidrChan {
		allRanges = append(allRanges, cidr...)
	}
	return allRanges
}

func sendRequest(url string) []*net.IPNet {
	req, err := http.NewRequest("GET", url, nil)
	checkError(err)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:103.0) Gecko/20100101 Firefox/103.0")
	client := &http.Client{
		Timeout: 30 * time.Second,
	}
	resp, err := client.Do(req)
	if checkError(err) {
		return []*net.IPNet{}
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		checkError(err)
	}(resp.Body)

	body, err := io.ReadAll(resp.Body)
	checkError(err)
	return regexIp(string(body))
}

func readFileUrl(url string) []*net.IPNet {
	client := http.Client{
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			r.URL.Opaque = r.URL.Path
			return nil
		},
		Timeout: 60 * time.Second,
	}
	// Put content on file
	resp, err := client.Get(url)
	if checkError(err) {
		return []*net.IPNet{}
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		checkError(err)
	}(resp.Body)

	data, err := io.ReadAll(resp.Body)
	checkError(err)
	return regexIp(string(data))
}

func regexIp(body string) []*net.IPNet {
	body = strings.Replace(body, "\\/", "/", -1)
	re, e := regexp.Compile(`(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])(\/(3[0-2]|[1-2][0-9]|[0-9]))`)
	checkError(e)

	var ranges []*net.IPNet
	for _, v := range re.FindAll([]byte(body), -1) {
		_, cidr, err := net.ParseCIDR(string(v))
		checkError(err)
		ranges = append(ranges, cidr)
	}
	return ranges
}

func checkAndWrite(allCidr []*net.IPNet, channel chan string, output string) {
	defer wg.Done()
	var isIpForCDN bool
	for ip := range channel {
		isIpForCDN = false
		for _, cidr := range allCidr {
			if cidr.Contains(net.ParseIP(ip)) {
				isIpForCDN = true
			}
		}
		if activeMode && !isIpForCDN {
			ptrRecords := getPtrRecord(string(ip))
			for _, v := range ptrRecords {
				if strings.Contains(v, "akamaitechnologies.com") {
					isIpForCDN = true
				}
			}
		}

		if activeMode && !isIpForCDN {
			http_server_header := getHttpHeader("http://" + string(ip))
			if http_server_header == "AkamaiGHost" {
				isIpForCDN = true
			}
		}

		if !isIpForCDN {
			if output == "CLI" {
				fmt.Println(ip)
			} else {
				file, err := os.OpenFile(output, os.O_APPEND|os.O_WRONLY, 0666)
				checkError(err)
				_, err = fmt.Fprintln(file, ip)
				checkError(err)
				err = file.Close()
				checkError(err)
			}
		}
	}
}

func readInput(isSilent bool, input string) []string {
	printText(isSilent, "Input Parsing", "Info")
	defer printText(isSilent, "Input Parsed", "Info")

	input = strings.TrimSpace(input)

	if _, err := os.Stat(input); err == nil {
		fileByte, err := os.ReadFile(input)
		checkError(err)

		var result []string
		fileData := strings.Split(string(fileByte), "\n")
		for _, v := range fileData {
			v = strings.TrimSpace(v)
			if v == "" {
				continue
			}

			if isValidIP(v) {
				result = append(result, v)
			} else {
				v = strings.TrimPrefix(v, "https://")
				v = strings.TrimPrefix(v, "http://")
				domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`)
				if domainRegex.MatchString(v) {
					ips, err := net.LookupIP(v)
					if err == nil {
						result = append(result, convertIPListToStringList(ips)...)
					}
				}
			}
		}
		return result
	}

	if input == "STDIN" {
		var result []string
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			ip := strings.TrimSpace(scanner.Text())
			if ip == "" {
				continue
			}
			if isValidIP(ip) {
				result = append(result, ip)
			} else {
				ip = strings.TrimPrefix(ip, "https://")
				ip = strings.TrimPrefix(ip, "http://")
				domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`)
				if domainRegex.MatchString(ip) {
					ips, err := net.LookupIP(ip)
					if err == nil {
						result = append(result, convertIPListToStringList(ips)...)
					}
				}
			}
		}
		return result
	}

	if isValidIP(input) {
		return []string{input}
	}

	input = strings.TrimPrefix(input, "https://")
	input = strings.TrimPrefix(input, "http://")
	domainRegex := regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$`)
	if domainRegex.MatchString(input) {
		ips, err := net.LookupIP(input)
		if err == nil {
			return convertIPListToStringList(ips)
		}
	}

	return nil
}

func checkUpdate(isSilent bool) {
	// Check Updates
	resp, err := http.Get("https://github.com/ImAyrix/cut-cdn")
	checkError(err)

	respByte, err := io.ReadAll(resp.Body)
	checkError(err)
	body := string(respByte)

	re, e := regexp.Compile(`cut-cdn\s+v(\d\.\d\.\d+)`)
	checkError(e)

	if re.FindStringSubmatch(body)[1] != VERSION {
		printText(isSilent, "", "Print")
		printText(isSilent, "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -", "Print")
		printText(isSilent, fmt.Sprintf("|    %v🔥  Please update Cut-CDN!%v                                      |", colorGreen, colorReset), "Print")
		printText(isSilent, "|    💣  Run: go install github.com/ImAyrix/cut-cdn@latest           |", "Print")
		printText(isSilent, "- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -", "Print")
		printText(isSilent, "", "Print")
	}

}

func checkError(e error) bool {
	if e != nil {
		gologger.Error().Msg(e.Error())
		return true
	}
	return false
}

func printText(isSilent bool, text string, textType string) {
	if !isSilent {
		if textType == "Info" {
			gologger.Info().Msg(text)
		} else if textType == "Print" {
			gologger.Print().Msg(text)
		} else if textType == "Error" {
			gologger.Error().Msg(text)
		}
	}
}
func createGroup(flagSet *goflags.FlagSet, groupName, description string, flags ...*goflags.FlagData) {
	flagSet.SetGroup(groupName, description)
	for _, currentFlag := range flags {
		currentFlag.Group(groupName)
	}
}

func getPtrRecord(ip string) []string {
	ptr, _ := net.LookupAddr(ip)
	return ptr
}

func getHttpHeader(url string) string {
	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:103.0) Gecko/20100101 Firefox/103.0")
	resp, err := http.Get(url)
	if err == nil {
		return resp.Header.Get("Server")
	}
	return ""
}

func convertIPListToStringList(ips []net.IP) []string {
	var result []string
	for _, ip := range ips {
		if !IsIPv6Valid(ip.String()) {
			result = append(result, ip.String())
		}
	}
	return result
}

func IsIPv6Valid(ip string) bool {
	parsedIP := net.ParseIP(ip)
	return parsedIP != nil && parsedIP.To16() != nil && parsedIP.To4() == nil
}

func isValidIP(ip string) bool {
	validatedIp := net.ParseIP(ip)
	return validatedIp != nil
}

func baseConfig(updateAll bool, updateRanges bool) {
	if updateAll {
		_ = os.Remove(homeDIR + "/cut-cdn/providers.yaml")
		_ = os.Remove(homeDIR + "/cut-cdn/ranges.txt")
	} else if updateRanges {
		_ = os.Remove(homeDIR + "/cut-cdn/ranges.txt")
	}
	func() {
		if _, err := os.Stat(homeDIR + "/cut-cdn"); os.IsNotExist(err) {
			printText(isSilent, "Create Cut-CDN DIR", "Info")
			_ = os.Mkdir(homeDIR+"/cut-cdn", os.ModePerm)
		}
	}()

	func() {
		if _, err := os.Stat(homeDIR + "/cut-cdn/providers.yaml"); os.IsNotExist(err) {
			printText(isSilent, "Create Cut-CDN Providers File", "Info")
			_, _ = os.Create(homeDIR + "/cut-cdn/providers.yaml")

			req, _ := http.NewRequest("GET", "https://raw.githubusercontent.com/ImAyrix/cut-cdn/master/static/providers.yaml", nil)
			req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:103.0) Gecko/20100101 Firefox/103.0")
			resp, _ := http.Get("https://raw.githubusercontent.com/ImAyrix/cut-cdn/master/static/providers.yaml")

			body, _ := io.ReadAll(resp.Body)
			_ = os.WriteFile(homeDIR+"/cut-cdn/providers.yaml", body, 0644)

		}
	}()

	func() {
		if _, err := os.Stat(homeDIR + "/cut-cdn/ranges.txt"); os.IsNotExist(err) {
			printText(isSilent, "Create CDN CIDRs File", "Info")
			file, _ := os.Create(homeDIR + "/cut-cdn/ranges.txt")
			allRanges := loadAllCDNOnline()
			data := ""
			for _, cidr := range allRanges {
				if !strings.Contains(data, cidr.String()) {
					data += cidr.String() + "\n"
				}
			}
			_, _ = file.WriteString(data)
		}
	}()
}
