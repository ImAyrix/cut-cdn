package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
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

func main() {
	var allRange []*net.IPNet

	input := flag.String("i", "", "Input [Filename | IP]")
	output := flag.String("o", "terminal", "Output [Filename]")
	savePath := flag.String("s", "", "Save all cidr [Path]")
	cachePath := flag.String("c", "", "Use cache file (offline) [Path]")
	thread := flag.Int("t", 1, "Number Of Thread [Number]")
	flag.Parse()

	if *input == "" {
		fmt.Println(colorRed + "[☓] Input is empty!\n" + colorReset)

		flag.PrintDefaults()
		fmt.Println(output)

		os.Exit(1)
	}

	if *cachePath != "" {
		fmt.Println(colorBlue + "[+] Loading Cache File" + colorReset)

		cache, err := os.ReadFile(*cachePath)
		checkError(err)

		allRange = regexIp(string(cache))

		fmt.Println(colorBlue + "[+] Cache File Loaded" + colorReset)
	} else {
		fmt.Println(colorBlue + "[+] Loading All CDN Range" + colorReset)

		allRange = loadAllCDN()
		fmt.Println(colorBlue + "[+] All CDN Range Loaded" + colorReset)

		if *savePath != "" {
			fmt.Println(colorBlue + "[+] Creating Cache File" + colorReset)
			f, err := os.Create(*savePath)
			checkError(err)
			var allLineRange string
			for _, v := range allRange {
				allLineRange += v.String() + "\n"
			}

			_, err = f.WriteString(allLineRange)
			if err != nil {
				return
			}
			fmt.Println(colorBlue + "[+] Cache File Created" + colorReset)
		}
	}

	if *output != "terminal" {
		_, err := os.Create(*output)
		checkError(err)
	}

	allIpInput := readInput(*input)
	channel := make(chan string, len(allIpInput))
	for _, ip := range allIpInput {
		channel <- ip
	}
	close(channel)

	fmt.Println(colorBlue + "[+] Start Checking IPs" + colorReset)
	if *output == "terminal" {
		fmt.Println()
		fmt.Println(colorGreen + "[⚡] All IPs Not Behind CDN ⤵" + colorReset)
	}
	for i := 0; i < *thread; i++ {
		wg.Add(1)
		go checkAndWrite(allRange, channel, *output)
	}
	wg.Wait()

	fmt.Println()
	fmt.Println(colorYellow + "Programmer: Amirabbas Ataei :)" + colorReset)
}

func loadAllCDN() []*net.IPNet {
	var wg sync.WaitGroup
	var allRanges []*net.IPNet
	cidrChan := make(chan []*net.IPNet, 17)

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
		cidr := sendRequest("https://asnlookup.com/asn/AS12222")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := sendRequest("https://asnlookup.com/asn/AS60626")
		cidrChan <- cidr
		wg.Done()
	}()

	wg.Add(1)
	go func() {
		cidr := sendRequest("https://asnlookup.com/asn/AS262254")
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
	client := &http.Client{}
	resp, err := client.Do(req)
	checkError(err)

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatal(err.Error())
		}

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
	}

	// Put content on file
	resp, err := client.Get(url)
	checkError(err)

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			log.Fatal(err.Error())
		}
	}(resp.Body)

	data, err := io.ReadAll(resp.Body)
	checkError(err)
	return regexIp(string(data))
}

func regexIp(body string) []*net.IPNet {
	re, e := regexp.Compile(`([0-9]{1,3}\.){3}[0-9]{1,3}(\/([0-9]|[1-2][0-9]|3[0-2]))?`)
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
				if err != nil {
					log.Fatal(err.Error())
				}

				err = file.Close()
				checkError(err)
			}
		}
	}
}

func readInput(input string) []string {
	fmt.Println(colorBlue + "[+] Input Parsing" + colorReset)
	ip := net.ParseIP(input)
	if ip != nil {
		fmt.Println(colorBlue + "[+] Input Parsed" + colorReset)
		return []string{ip.String()}
	}

	fileByte, err := os.ReadFile(input)
	checkError(err)
	fmt.Println(colorBlue + "[+] Input Parsed" + colorReset)
	return strings.Split(string(fileByte), "\n")
}

func checkError(e error) {
	if e != nil {
		log.Fatal(e)
	}
}
