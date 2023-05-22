package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"flag"
	"fmt"
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

var CDNS = []CDN{}
var input, output, savePath, cachePath, provider, providers, append_provider, append_providers string
var isSilent, showVersion, activeMode bool
var thread int

const VERSION = "1.0.25"

func main() {
	var allRange []*net.IPNet

	flagSet := goflags.NewFlagSet()
	flagSet.SetDescription("Removing CDN IPs from the list of IP addresses")
	createGroup(flagSet, "input", "Input",
		flagSet.StringVar(&input, "i", "", "Input [Filename | IP]"),
		flagSet.StringVar(&provider, "pu", "", "Provider CIDRs page [URL]"),
		flagSet.StringVar(&providers, "pl", "", "Providers CIDRs pages [File]"),
		flagSet.StringVar(&append_provider, "apu", "", "Append provider to the default providers [URL]"),
		flagSet.StringVar(&append_providers, "apl", "", "Append list of providers to the default providers [File]"),
		flagSet.StringVar(&cachePath, "c", "", "Use cache file (offline) [File]"),
	)

	createGroup(flagSet, "rate-limit", "Rate-Limit",
		flagSet.IntVar(&thread, "t", 1, "Number Of Thread [Number]"),
	)

	flagSet.CreateGroup("configs", "Configurations",
		flagSet.BoolVar(&activeMode, "active", false, "Active mode for check akamai"),
	)

	createGroup(flagSet, "output", "Output",
		flagSet.StringVar(&output, "o", "CLI", "File to write output to (optional)"),
		flagSet.StringVar(&savePath, "s", "", "Save all CIDRs [File]"),
	)

	createGroup(flagSet, "debug", "Debug",
		flagSet.BoolVar(&isSilent, "silent", false, "Show only IPs in output"),
		flagSet.BoolVar(&showVersion, "version", false, "Show version of cut-cdn"),
	)

	_ = flagSet.Parse()
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

	if provider != "" {
		CDNS = append(CDNS, CDN{provider, sendRequest})
	} else if providers != "" {
		fileByte, err := os.ReadFile(providers)
		checkError(err)
		fileData := strings.Split(string(fileByte), "\n")
		for _, v := range fileData {
			if v != "" {
				CDNS = append(CDNS, CDN{v, sendRequest})
			}
		}
	} else {
		CDNS = []CDN{
			{"https://api.fastly.com/public-ip-list", sendRequest},
			{"https://www.gstatic.com/ipranges/cloud.json", sendRequest},
			{"https://www.gstatic.com/ipranges/goog.json", sendRequest},
			{"https://ip-ranges.amazonaws.com/ip-ranges.json", sendRequest},
			{"https://www.cloudflare.com/ips-v4", sendRequest},
			{"https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips", sendRequest},
			{"https://support.maxcdn.com/hc/en-us/article_attachments/360051920551/maxcdn_ips.txt", sendRequest},
			{"https://www.bing.com/toolbox/bingbot.json", sendRequest},
			{"https://www.arvancloud.ir/en/ips.txt", readFileUrl},
			{"http://edge.sotoon.ir/ip-list.json", sendRequest},
			{"https://cachefly.cachefly.net/ips/rproxy.txt", sendRequest},
			{"https://docs.imperva.com/en-US/bundle/z-kb-articles-km/page/c85245b7.html", sendRequest},
			{"https://ayrix.info/cut-cdn-data/1/", sendRequest},
			{"https://ayrix.info/cut-cdn-data/2/", sendRequest},
			{"https://cdn.nuclei.sh", sendRequest},
			{"https://download.microsoft.com/download/7/1/D/71D86715-5596-4529-9B13-DA13A5DE5B63/ServiceTags_Public_20230515.json", readFileUrl},
			{"https://download.microsoft.com/download/0/1/8/018E208D-54F8-44CD-AA26-CD7BC9524A8C/PublicIPs_20200824.xml", readFileUrl},
			{"https://digitalocean.com/geo/google.csv", readFileUrl},
			{"https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json", readFileUrl},
		}
		if append_provider != "" {
			CDNS = append(CDNS, CDN{append_provider, sendRequest})
		}
		if append_providers != "" {
			fileByte, err := os.ReadFile(append_providers)
			checkError(err)
			fileData := strings.Split(string(fileByte), "\n")
			for _, v := range fileData {
				if v != "" {
					CDNS = append(CDNS, CDN{v, sendRequest})
				}
			}
		}
	}

	if cachePath != "" {
		printText(isSilent, "Loading Cache File", "Info")
		cache, err := os.ReadFile(cachePath)
		checkError(err)
		allRange = regexIp(string(cache))
		printText(isSilent, "Cache File Loaded", "Info")
	} else {
		printText(isSilent, "Loading All CDN Range", "Info")
		allRange = loadAllCDN()
		printText(isSilent, "All CDN Range Loaded", "Info")

		if savePath != "" {
			printText(isSilent, "Creating Cache File", "Info")
			f, err := os.Create(savePath)
			checkError(err)
			var allLineRange string
			for _, v := range allRange {
				if !strings.Contains(allLineRange, v.String()) {
					allLineRange += v.String() + "\n"
				}
			}

			_, err = f.WriteString(allLineRange)
			checkError(err)

			printText(isSilent, "Cache File Created", "Info")
		}
	}

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

	var wg sync.WaitGroup
	var allRanges []*net.IPNet
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

	input = strings.Trim(input, " ")
	if input == "STDIN" {
		var result []string
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			ip := scanner.Text()
			result = append(result, strings.Trim(ip, " "))
		}
		printText(isSilent, "Input Parsed", "Info")
		return result
	}
	ip := net.ParseIP(input)
	if ip != nil {
		printText(isSilent, "Input Parsed", "Info")
		return []string{ip.String()}
	}

	fileByte, err := os.ReadFile(input)
	checkError(err)
	printText(isSilent, "Input Parsed", "Info")
	var result []string
	fileData := strings.Split(string(fileByte), "\n")
	for _, v := range fileData {
		result = append(result, strings.Trim(v, " "))
	}
	return result
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
