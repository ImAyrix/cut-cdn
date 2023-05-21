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
* Amazon
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
  -i string    Input [Filename | IP]
  -pu string   Provider CIDRs page [URL]
  -pl string   Providers CIDRs pages [File]
  -apu string  Append provider to the default providers [URL]
  -apl string  Append list of providers to the default providers [File]
  -c string    Use cache file (offline) [File]

RATE-LIMIT:
  -t int  Number Of Thread [Number] (default 1)

CONFIGURATIONS:
  -active  Enable active mode for check akamai

OUTPUT:
  -o string  File to write output to (optional) (default "CLI")
  -s string  Save all CIDRs [File]

DEBUG:
  -silent   Show only IPs in output
  -version  Show version of cut-cdn

```

## Preview

![cut-cdn](https://user-images.githubusercontent.com/89543912/221229391-5bb70bb1-5b6f-43ae-a912-0d1663498cad.png)

## Usage

### Set Provider
If you do not utilize the `-pu` and `-pl` switches, the default providers will be employed ([list of providers](https://github.com/ImAyrix/cut-cdn#cdn-providers)). if you use these two switches, only the list of your input providers will be utilized. In case you wish to add a new link provider in addition to the default providers, make use of `-apu` and `-apl`.

+ Just one provider 
    ```bash
      cut-cdn -i 127.0.0.1 -pu https://www.cloudflare.com/ips-v4
    ```
+ List of provider
    ```bash
      cut-cdn -i 127.0.0.1 -pl providers.txt
    ```
+ Append one provider to the default providers
    ```bash
      cut-cdn -i 127.0.0.1 -apu https://www.cloudflare.com/ips-v4
    ```
+ Append list of providers to the default providers
    ```bash
      cut-cdn -i 127.0.0.1 -apl providers.txt
    ```

## Akamai
Most content delivery networks (CDNs) have their Classless Inter-Domain Routing (CIDR) blocks specified on a page on their website, which Cut CDN also receives and uses to determine whether the incoming IP is behind the CDN.
However, Akamai has not publicly specified its IP range. I attempted to find the Akamai CIDRs myself and added them to the tool, which is fairly comprehensive but not entirely foolproof, and I may have overlooked some CIDRs.
To ensure accuracy, you can use the "-active" key. When this switch is used, all providers are checked as before, but with the added step of actively checking for Akamai as well.

Note: If you want to check many IPs using this method, increase the number of threads so that it checks quickly and takes less time.

```bash
cut-cdn -i 127.0.0.1 -active
```

### Online mode
Check your IP list with the latest IP ranges of CDN providers:

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
+ To set concurrency use -t option (Default is 1)
  ```bash
  cut-cdn -i allIP.txt -o output.txt -t 20
  ```
### Offline mode
1. To check IPs in offline mode you should save CDNs IP ranges in a file
    ```bash
    cut-cdn -s allCIDR.txt
   ```
2. After that you can run it in offline mode by `-c` pointing to the CIDR file
    ```bash
   cut-cdn -i allIP.txt -o output.txt -t 20 -c allCIDR.txt
   ```
