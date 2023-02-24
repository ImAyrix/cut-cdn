<h4 align="center"> Removing CDN IPs from the list of IP addresses </h4>
<p align="center">
  <a href="#cdn-providers">CDN Providers</a> •
  <a href="#installation">Install</a> •
  <a href="#usage-parameters">Usage Parameters</a> •
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
* Cloudflare
* Cloudfront
* DDoS Guard
* Digitalocean
* Fastly
* Google cloud
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
  -c string
        Use cache file (offline) [Path]
  -i string
        Input [Filename | IP]
  -o string
        Output [Filename] (default "terminal")
  -s string
        Save all cidr [Path]
  -silent
        show only IPs in output
  -t int
        Number Of Thread [Number] (default 1)
```

## Usage

![cut-cdn](https://user-images.githubusercontent.com/89543912/221229391-5bb70bb1-5b6f-43ae-a912-0d1663498cad.png)


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
  cat IPlist.txt | cut-cdn
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
