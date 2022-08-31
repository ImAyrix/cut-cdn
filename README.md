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
  -t int
    	Number Of Thread [Number] (default 1)
```

## More Info
For better results, you should start using your VPN/Proxy service if you live in a country that has been sanctioned/restricted by CDNs.
