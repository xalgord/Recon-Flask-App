#!/bin/bash

# Script to automate bug bounty reconnaissance and vulnerability scanning
# Only processes domains with new or changed content (status codes, titles, etc.)

# Usage: ./bounty_script.sh domains.txt

# File containing list of domains
filename="$1"
domains_file=$(sort -R "$filename")

# Define directories
base_dir="/root/targets/$filename"
recon_dir="$base_dir/recon"
output_dir="$base_dir/output"
old_data_dir="$base_dir/old_data"
new_data_dir="$base_dir/new_data"

# Create necessary directories
mkdir -p "$recon_dir" "$output_dir" "$old_data_dir" "$new_data_dir"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Signal trapping
trap "echo -e '${YELLOW}Skipping current command...${NC}'" SIGINT
trap "echo -e '${RED}Script stopped. Exiting...${NC}'; exit 1" SIGTSTP

# Check if required tools are installed
required_tools=("assetfinder" "curl" "subfinder" "findomain" "httpx" "anew" "gf" "uro" "kxss" "naabu" "nuclei" "gau" "katana" "ffuf" "notify" "python3")
for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        echo -e "${RED}Error: $tool is not installed. Please install it and try again.${NC}"
        exit 1
    fi
done

echo -e "${YELLOW}Starting reconnaissance and vulnerability scanning...${NC}"

# Loop through each domain in the file
for domain in $domains_file; do
    echo -e "${BLUE}Processing domain: $domain${NC}"

    domain_recon_dir="$recon_dir/$domain"
    mkdir -p "$domain_recon_dir"

    old_data_file="$old_data_dir/$domain-data.txt"
    new_data_file="$new_data_dir/$domain-data.txt"

    # Subdomain Enumeration
    echo -e "${GREEN}Running subdomain enumeration...${NC}"
    subfinder -d "$domain" -all -recursive -nW -silent | anew "$new_data_file"
    findomain -t "$domain" -q | anew "$new_data_file"
    echo -e "${YELLOW}Total subdomains enumerated: $(wc -l < "$new_data_file")${NC}"

    # Run HTTPX on all current subdomains to capture changes in content, status codes, etc.
    echo -e "${GREEN}Running DNS resolution and HTTP probing on all current subdomains...${NC}"
    cat "$new_data_file" | httpx -t 170 -silent -status-code -title -location -tech-detect -nc > "$new_data_file"
    echo -e "${YELLOW}Total live URLs found: $(wc -l < "$new_data_file")${NC}"

    # Compare the new data file with the old data file to detect changes
    new_or_changed_domains_count=0
    if [ -f "$old_data_file" ]; then
        # Count new or changed domains based on differences in content
        new_or_changed_domains_count=$(diff "$old_data_file" "$new_data_file" | wc -l)
    else
        # If no old data file, all current subdomains are considered as new/changed
        new_or_changed_domains_count=$(wc -l < "$new_data_file")
    fi

    # Output the count of new or changed domains
    echo -e "${YELLOW}Total new or changed domains: $new_or_changed_domains_count${NC}"

    # Save the new subdomains and data as old for future runs
    mv "$new_data_file" "$old_data_file"

    # Proceed with further processing if there are any new or changed domains
    if [ "$new_or_changed_domains_count" -gt 0 ]; then
        echo -e "${GREEN}Proceeding with further tests for $domain...${NC}"

        # Port Scanning using Naabu on changed subdomains
        echo -e "${GREEN}Running port scanning...${NC}"
        cat "$old_data_file" | cut -d " " -f 1 | naabu -silent -o "$domain_recon_dir/naabu.txt"
        echo -e "${YELLOW}Total open ports found: $(wc -l < "$domain_recon_dir/naabu.txt")${NC}"

        # Vulnerability Scanning using Nuclei with custom templates
        echo -e "${GREEN}Running vulnerability scanning with Nuclei...${NC}"
        nuclei -l "$old_data_file" -t ~/nuclei-templates/ -severity high,critical -c 50 -rl 250 -o "$domain_recon_dir/nuclei_results.txt"
        cat "$domain_recon_dir/nuclei_results.txt" | notify
        echo -e "${YELLOW}Total vulnerabilities found: $(wc -l < "$domain_recon_dir/nuclei_results.txt")${NC}"

        # Content Discovery using httpx and Dirsearch on all new or changed subdomains
        echo -e "${GREEN}Running content discovery...${NC}"
        cat "$old_data_file" | httpx -mc 403,404,401 | awk '{print $NF, $0}' | sort -u -k1,1 | cut -d' ' -f2- | cut -d " " -f 1 > "$domain_recon_dir/fuzz.txt"
        dirsearch --config ~/.config/dirsearch/config.ini -t 100 -l "$domain_recon_dir/fuzz.txt" -o "$domain_recon_dir/dirsearch.txt"
        echo -e "${YELLOW}Total URLs discovered by Dirsearch: $(wc -l < "$domain_recon_dir/dirsearch.txt")${NC}"

        # Parameter Discovery using GAU and KATANA
        echo -e "${GREEN}Running parameter discovery...${NC}"
        cat "$old_data_file" | gau --subs | anew "$domain_recon_dir/urls.txt"
        cat "$old_data_file" | katana -mode passive -fs urls -silent -o "$domain_recon_dir/katana_results.txt"
        cat "$domain_recon_dir/katana_results.txt" | anew "$domain_recon_dir/urls.txt"
        echo -e "${YELLOW}Total URLs discovered by GAU and Katana: $(wc -l < "$domain_recon_dir/urls.txt")${NC}"

        # XSS Testing with KXSS and GF Patterns
        echo -e "${GREEN}Running XSS testing...${NC}"
        cat "$domain_recon_dir/urls.txt" | gf xss | kxss | tee "$domain_recon_dir/xss_results.txt"
        cat "$domain_recon_dir/xss_results.txt" | notify
        echo -e "${YELLOW}Total XSS endpoints identified: $(wc -l < "$domain_recon_dir/xss_results.txt")${NC}"
    else
        echo -e "${YELLOW}No significant changes detected for $domain. Skipping further tests.${NC}"
    fi

    # Save results to output directory
    cp "$domain_recon_dir"/* "$output_dir/"

done

echo -e "${GREEN}Reconnaissance and scanning completed!${NC}"
echo -e "${YELLOW}Results saved in $output_dir${NC}"
