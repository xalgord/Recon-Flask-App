#!/bin/bash

# File containing list of domains
domains_file=$(sort -R "$1")

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Signal trapping
trap "echo -e '${RED}Script interrupted. Exiting...${NC}'; exit 1" SIGINT SIGTERM
trap "echo -e '${RED}Script stopped. Exiting...${NC}'; exit 1" SIGTSTP

# Check if required tools are installed
required_tools=("assetfinder" "curl" "jq" "subfinder" "findomain" "httpx" "anew" "gf" "uro" "kxss" "naabu" "nf" "nuclei" "gau" "katana" "notify" "python3")
for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        echo -e "${RED}Error: $tool is not installed. Please install it and try again.${NC}"
        exit 1
    fi
done

# Loop through each domain in the file
echo -e "${YELLOW}Starting reconnaissance${NC}"

target_dir=/root/targets/all/recon
content_dir=/root/targets/all/discovery
mkdir -p "$target_dir"
mkdir -p "$content_dir"
cd "$target_dir" || { echo "Failed to change directory to $target_dir"; exit 1; }
rm -f ../all.txt

for domain in $domains_file
do
    # Clean up old files
    rm -rf *

    # Run subdomain enumeration tools
    assetfinder -subs-only "$domain" | grep "$domain" > assetfinder.txt || echo -e "${RED}assetfinder timed out or failed${NC}"
    subfinder -d "$domain" -all -recursive -t 200 -silent > subfinder-recursive.txt || echo -e "${RED}subfinder timed out or failed${NC}"
    findomain -t "$domain" -q > findomain.txt || echo -e "${RED}findomain timed out or failed${NC}"

    # Merge all subdomains into all.txt
    cat *.txt | sort -u >> ../all.txt
done

cd ..

cat all.txt | sort -u > subs.txt

# Running HTTPX
echo -e "${BLUE}-----------------------------------------"
echo -e "${GREEN}Running HTTPX on subs.txt...${NC}"
echo -e "${BLUE}-----------------------------------------${NC}"

httpx -t 175 -rl 200 -sc -title -cl -probe -l subs.txt | grep -v "FAILED" > live.txt
cat live.txt | anew juicy-live.txt | sed 's|^[^/]*//||' | cut -d '/' -f 1 | cut -d " " -f 1 > new.txt

# Extracting important subdomains
echo -e "${BLUE}-----------------------------------------"
echo -e "${GREEN}Extracting important subdomains...${NC}"
echo -e "${BLUE}-----------------------------------------${NC}"

python3 ~/tools/spyhunt/spyhunt.py -isubs new.txt

# Nuclei Fuzzer
# echo -e "${BLUE}-----------------------------------------"
# echo -e "${GREEN}Running Nuclei Fuzzer...${NC}"
# echo -e "${BLUE}-----------------------------------------${NC}"
# nf -d "$domain"

# Running Nuclei
echo -e "${BLUE}-----------------------------------------"
echo -e "${GREEN}Running Nuclei scan...${NC}"
echo -e "${BLUE}-----------------------------------------${NC}"

nuclei -l new.txt -nh -nmhe -nss -es info,low -headless -o vulns.txt
cat vulns.txt | notify

# Running FFUF
echo -e "${BLUE}-----------------------------------------"
echo -e "${GREEN}Running Dirsearch...${NC}"
echo -e "${BLUE}-----------------------------------------${NC}"

# for subdomain in $(cat new.txt)
# do
# 	ffuf -c -ac -w /root/lists/dirsearch.txt -mc 200 -rate 100 -recursion -r -u "https://$subdomain/FUZZ" >> "$ffuf_dir/result.txt"
# done

dirsearch -l juice_subs.txt --config ~/.config/dirsearch/config.ini -t 150 --skip-on-status 429 > "dirsearch.txt"

echo -e "${BLUE}-----------------------------------------"
echo -e "${GREEN}Checking for XSS...${NC}"
echo -e "${BLUE}-----------------------------------------${NC}"

while IFS= read -r domain; do
    python3 "/root/ParamSpider/paramspider.py" -l "$domain" --exclude "$excluded_extensions" --level high --quiet -o "${content_dir}/params.txt"
    cat "${content_dir}/params.txt" >> "${content_dir}/paramsall.txt"
done < "$domains_file"

echo "$domains_file" | katana -passive -pss waybackarchive,commoncrawl,alienvault -f qurl > "${content_dir}/katana.txt"
cat "$domains_file" | gau >> "${content_dir}/gau.txt"
cat "${content_dir}/"*.txt | uro > endpoints.txt

cat endpoints.txt | gf xss | uro | kxss | grep "\" ' <" | tee possible-xss.txt | notify

echo -e "${BLUE}-----------------------------------------"
echo -e "${YELLOW}Reconnaissance completed${NC}"
echo -e "${BLUE}-----------------------------------------${NC}"
