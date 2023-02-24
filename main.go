package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"github.com/projectdiscovery/gologger"
	"io"
	"log"
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

const VERSION = "1.0.9"

func main() {
	var allRange []*net.IPNet

	input := flag.String("i", "", "Input [Filename | IP]")
	output := flag.String("o", "terminal", "Output [Filename]")
	savePath := flag.String("s", "", "Save all cidr [Path]")
	cachePath := flag.String("c", "", "Use cache file (offline) [Path]")
	thread := flag.Int("t", 1, "Number Of Thread [Number]")
	isSilent := flag.Bool("silent", false, "show only IPs in output")
	flag.Parse()

	fi, err := os.Stdin.Stat()
	checkError(err)

	if *input == "" && fi.Mode()&os.ModeNamedPipe == 0 && *savePath == "" {
		printText(*isSilent, "Input is empty!\n\n", "Error")
		flag.PrintDefaults()

		fmt.Println(output)

		os.Exit(1)
	}
	checkUpdate(*isSilent)

	if *cachePath != "" {
		printText(*isSilent, "Loading Cache File", "Info")
		cache, err := os.ReadFile(*cachePath)
		checkError(err)
		allRange = regexIp(string(cache))
		printText(*isSilent, "Cache File Loaded", "Info")
	} else {
		printText(*isSilent, "Loading All CDN Range", "Info")
		allRange = loadAllCDN()
		printText(*isSilent, "All CDN Range Loaded", "Info")

		if *savePath != "" {
			printText(*isSilent, "Creating Cache File", "Info")
			f, err := os.Create(*savePath)
			checkError(err)
			var allLineRange string
			for _, v := range allRange {
				allLineRange += v.String() + "\n"
			}

			_, err = f.WriteString(allLineRange)
			checkError(err)

			printText(*isSilent, "Cache File Created", "Info")
		}
	}

	if *input == "" && fi.Mode()&os.ModeNamedPipe == 0 {
		os.Exit(0)
	}

	if *output != "terminal" {
		_, err := os.Create(*output)
		checkError(err)
	}

	var allIpInput []string
	if fi.Mode()&os.ModeNamedPipe != 0 {
		allIpInput = readInput(*isSilent, "STDIN")
	} else {
		allIpInput = readInput(*isSilent, *input)
	}
	channel := make(chan string, len(allIpInput))
	for _, ip := range allIpInput {
		channel <- ip
	}

	close(channel)

	printText(*isSilent, "Start Checking IPs", "Info")
	if *output == "terminal" {
		printText(*isSilent, "", "Print")
		printText(*isSilent, colorGreen+"[⚡] All IPs Not Behind CDN ⤵"+colorReset, "Print")
	}
	for i := 0; i < *thread; i++ {
		wg.Add(1)
		go checkAndWrite(allRange, channel, *output)
	}
	wg.Wait()

	printText(*isSilent, "", "Print")
	printText(*isSilent, "Github page: https://github.com/ImAyrix/cut-cdn", "Print")
}

func loadAllCDN() []*net.IPNet {
	var wg sync.WaitGroup
	var allRanges []*net.IPNet
	cidrChan := make(chan []*net.IPNet, 23)

	wg.Add(1)
	go func() {
		cidr := sendRequest("https://api.fastly.com/public-ip-list")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := sendRequest("https://www.gstatic.com/ipranges/cloud.json")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := sendRequest("https://www.gstatic.com/ipranges/goog.json")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := sendRequest("https://ip-ranges.amazonaws.com/ip-ranges.json")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := sendRequest("https://www.cloudflare.com/ips-v4")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := sendRequest("https://d7uri8nf7uskq.cloudfront.net/tools/list-cloudfront-ips")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := sendRequest("https://support.maxcdn.com/hc/en-us/article_attachments/360051920551/maxcdn_ips.txt")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := sendRequest("https://www.bing.com/toolbox/bingbot.json")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := readFileUrl("https://www.arvancloud.ir/en/ips.txt")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := sendRequest("https://api.bgpview.io/asn/AS12222/prefixes")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := sendRequest("https://api.bgpview.io/asn/AS60626/prefixes")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := sendRequest("https://api.bgpview.io/asn/AS262254/prefixes")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := sendRequest("https://api.bgpview.io/asn/AS200449/prefixes")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := sendRequest("https://api.bgpview.io/asn/AS12989/prefixes")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := sendRequest("https://api.bgpview.io/asn/AS59796/prefixes")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := sendRequest("https://api.bgpview.io/asn/AS30148/prefixes")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := sendRequest("https://api.bgpview.io/asn/AS136165/prefixes")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := sendRequest("https://cdn.nuclei.sh")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := readFileUrl("https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := readFileUrl("https://download.microsoft.com/download/0/1/8/018E208D-54F8-44CD-AA26-CD7BC9524A8C/PublicIPs_20200824.xml")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := readFileUrl("https://digitalocean.com/geo/google.csv")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := readFileUrl("https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		incapsulaIPUrl := "https://my.incapsula.com/api/integration/v1/ips"
		resp, err := http.Post(incapsulaIPUrl, "application/x-www-form-urlencoded", bytes.NewBuffer([]byte("resp_format=text")))
		checkError(err)
		body, err := io.ReadAll(resp.Body)
		checkError(err)
		cidr := regexIp(string(body))
		cidrChan <- cidr
		wg.Done()
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
	checkError(err)
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
	checkError(err)

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
		if !isIpForCDN {
			if output == "terminal" {
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

	if input == "STDIN" {
		var result []string
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			ip := scanner.Text()
			result = append(result, ip)
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
	return strings.Split(string(fileByte), "\n")
}

func checkUpdate(isSilent bool) {
	// Check Updates
	resp, err := http.Get("https://github.com/ImAyrix/cut-cdn")
	checkError(err)

	respByte, err := io.ReadAll(resp.Body)
	checkError(err)
	body := string(respByte)

	re, e := regexp.Compile(`cut-cdn\s+v(\d\.\d\.\d)`)
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

func checkError(e error) {
	if e != nil {
		log.Fatal(e.Error())
	}
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
