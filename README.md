# Cut CDN
✂️ Striping CDN IPs from a list of IP Addresses

## CDN Providers
* Fastly
* Google cloud
* Azure CDN
* Amazon
* Cloudflare
* Cloudfront
* Maxcdn
* Bing
* Akamai
* Leaseweb
* DDoS Guard
* Digitalocean
* Oracle
* Incapsula
* Arvancloud 
* Qrator
* StackPath
* StormWall
* Sucuri
* X4B

## Installation
```
go install github.com/AbbasAtaei/cut-cdn@latest
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
Striping CDN IPs from file (Online)
```bash
cut-cdn -i allIP.txt -o output.txt -s allCIDR.txt -t 20
```

Striping CDN IPs from file (Offline)
```bash
cut-cdn -i allIP.txt -o output.txt -c allCIDR.txt -t 20
```

Striping CDN IPs from stdin
```bash
cat allIP.txt | cut-cdn -o output.txt -t 20
```

## More Info
For better results, you should start using your VPN/Proxy service if you live in a country that has been sanctioned/restricted by CDNs.
