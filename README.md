# OrsuRecon
```bash
#modify API key at nano /home/vamsi/.config/subfinder/provider-config.yaml
#take API key from securitytrails.com, signup and move to api keys 
subfinder -d domain.com -o domains.txt

#using amass
# configure API KEY
#open https://github.com/owasp-amass/amass/blob/master/examples/config.yaml
#copy the whole data into config.yaml file
#comment everything from starting to end except options and datasources
#go through datasources.yaml in the same githubrepo, copy into datasources.yaml newfile
#configure your own api key like security trails copy that particular one
#add api key
amass enum -d domain.com >> domians.txt
cat domains.txt | grep -Eo '[a-zA-Z0-9_-]+\.domain\.com' | sort -u | tee finaldomains.txt

#sorting out everthing
cat finaldomains.txt | httprobe -prefer-https > alive_domains.txt

#live view
mkdir domainpics
# screenshot automation for each page
# need to remove 'https://' string from final subdomains file for gowitness to work
gowitness file -f alive_domains.txt -P domainpics --no-http
```

# Directory Busting

```bash
dirsearch -u "https://domain.com" --exclude-status=403,500 -v
dirsearch -u "https://domain.com" -x 403,500 -v

ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://10.0.0.10/FUZZ

dirb http://10.0.0.10
# scans recursively by default

# can use other tools as well like dirbuster and gobuster
```

# Content Discovery

```bash
echo "https://domain.com" | gau > gau.txt
cat gau.txt | grep "=" | sort -u

echo "https://domain.com" | waybackurls > way.txt
cat way.txt | grep "=" | sort -u

echo "https://domain.com" | gau > gau.txt && echo "https://domain.com" | waybackurls > way.txt && cat gau.txt way.txt | sort -u > sorted.txt

python3 paramspider -d hackerone.com

arjun -u https://hackerone.com

katana -u "https://domain.com" -jc -d 4 -o katana.txt
```
