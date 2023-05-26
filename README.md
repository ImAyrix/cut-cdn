<h4 align="center"> Removing CDN IPs from the list of IP addresses </h4>
<p align="center">
  <a href="#cdn-providers">CDN Providers</a> •
  <a href="#installation">Install</a> •
  <a href="#usage-parameters">Usage Parameters</a> •
  <a href="#preview">Preview</a> •
  <a href="#usage">Usage</a> •
  <a href="https://t.me/ImAyrix">Contact me</a>
</p>

---

The tool's basic functionality would involve taking the list of IP addresses as input and then checking to determine whether the IP is behind a CDN.
This tool will gather all CIDR of the most-known CDN providers and check your provided list with them.
This is a handy tool for bug hunters.

## CDN Providers
* Akamai
* Arvancloud
* Azure CDN
* Bing
* CacheFly
* CafeBazaar (sotoon)
* CDNetworks
* Cloudflare
* Cloudfront
* DDoS Guard
* Digitalocean
* Fastly
* Google cloud
* Imperva
* Incapsula
* Leaseweb
* Maxcdn
* Oracle
* Qrator
* StackPath
* StormWall
* Sucuri
* X4B

## Installation
```
go install github.com/ImAyrix/cut-cdn@latest
```


## Usage Parameters
```
cut-cdn -h
```
This will display help for the tool. Here are all the switches it supports.
```yaml
Removing CDN IPs from the list of IP addresses

Usage:
  cut-cdn [flags]

Flags:
INPUT:
  -i, -ip string  Input [Filename | IP]

RATE-LIMIT:
  -t, -thread int  Number Of Thread [Number] (default 1)

CONFIGURATIONS:
  -a, -active          Active mode for check akamai
  -ua, -update-all     Update CUT-CDN Data (providers & ranges)
  -ur, -update-ranges  Update CUT-CDN Data (just ranges)

OUTPUT:
  -o, -output string  File to write output to (optional) (default "CLI")

DEBUG:
  -q, -silent   Show only IPs in output
  -v, -version  Show version of cut-cdn

```

## Preview

![cut-cdn](https://user-images.githubusercontent.com/89543912/221229391-5bb70bb1-5b6f-43ae-a912-0d1663498cad.png)

## Usage

### Akamai
Most content delivery networks (CDNs) have their Classless Inter-Domain Routing (CIDR) blocks specified on a page on their website, which Cut CDN also receives and uses to determine whether the incoming IP is behind the CDN.
However, Akamai has not publicly specified its IP range. I attempted to find the Akamai CIDRs myself and added them to the tool, which is fairly comprehensive but not entirely foolproof, and I may have overlooked some CIDRs.
To ensure accuracy, you can use the "-active" key. When this switch is used, all providers are checked as before, but with the added step of actively checking for Akamai as well.

Note: If you want to check many IPs using this method, increase the number of threads so that it checks quickly and takes less time.

```bash
cut-cdn -i 127.0.0.1 -active
```

### Basic
Check your IP list with the IP ranges of CDN providers:

+ Single IP 
    ```bash
    cut-cdn -i 127.0.0.1
    echo "127.0.0.1" | cut-cdn
    ```
+ List of IPs 
    ```bash
    cut-cdn -i allIP.txt
    cat allIP.txt | cut-cdn
    ```
+ To store results use `-o` option 
    ```bash
    cut-cdn -i allIP.txt -o output.txt
    ```
+ To set concurrency use `-t` option (Default is 1)
    ```bash
    cut-cdn -i allIP.txt -o output.txt -t 20
    ```

### Providers
During the initial run of the tool after installation, two files are generated in the directory ~/cut-cdn. One of these files, providers.yaml, contains the link pages where providers have specified their CIDRs. The other file, ranges.txt, contains the CIDRs of these providers.

+ Update Ranges

    The tool will request the provider's pages again and check whether a new range has been added or not.
    ```bash
      cut-cdn -ur
    ```

+ Update Providers

  This tool will query the Cut-CDN GitHub page and check if a new provider has been added or not. And then it queries the providers and checks if a new range has been added or not.
  ```bash
  cut-cdn -ua
  ```

+ Manual update providers

  If you yourself added a new link from the provider to the providers.yaml file, you must update the ranges once.
  ```bash
  cut-cdn -ur
  ```
