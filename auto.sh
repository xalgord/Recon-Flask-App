#!/bin/bash

# Usage: ./bounty_script.sh domains.txt

# Input file containing the list of domains
input_file="$1"
shuffled_domains=$(shuf "$input_file")

# Directory setup
base_dir="/root/targets/$(basename "$input_file" .txt)"
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

# Ensure all required tools are installed
required_tools=("assetfinder" "curl" "subfinder" "findomain" "httpx" "anew" "gf" "uro" "kxss" "naabu" "nuclei" "gau" "katana" "ffuf" "notify" "python3")
for tool in "${required_tools[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        echo -e "${RED}Error: $tool is not installed. Please install it and try again.${NC}"
        exit 1
    fi
done

echo -e "${YELLOW}Starting reconnaissance and vulnerability scanning...${NC}"

total_domains=0
total_new_or_changed=0
total_live_urls=0
total_open_ports=0
total_vulnerabilities=0
total_xss_endpoints=0
total_discovered_directories=0

# Loop through each domain
for domain in $shuffled_domains; do
    total_domains=$((total_domains + 1))
    echo -e "${BLUE}Processing domain: $domain${NC}"
    
    domain_recon_dir="$recon_dir/$domain"
    mkdir -p "$domain_recon_dir"

    old_data_file="$old_data_dir/$domain-data.txt"
    new_data_file="$new_data_dir/$domain-data.txt"
    
    # Subdomain Enumeration
    echo -e "${GREEN}Running subdomain enumeration...${NC}"
    subfinder -d "$domain" -all -recursive -nW -silent | anew "$new_data_file"
    findomain -t "$domain" -q | anew "$new_data_file"

    # Deduplicate subdomains
    sort -u "$new_data_file" -o "$new_data_file"

    # HTTPX for content changes (using -nc to suppress output)
    echo -e "${GREEN}Running HTTP probing...${NC}"
    cat "$new_data_file" | httpx -nc -t 170 -status-code -title -location -tech-detect > "$new_data_file"

    # Check for new or changed domains
    if [ -f "$old_data_file" ]; then
        new_or_changed_domains_count=$(comm -13 <(sort "$old_data_file") <(sort "$new_data_file") | wc -l)
    else
        new_or_changed_domains_count=$(wc -l < "$new_data_file")
    fi

    if [ "$new_or_changed_domains_count" -gt 0 ]; then
        total_new_or_changed=$((total_new_or_changed + new_or_changed_domains_count))
        echo -e "${YELLOW}Total new or changed subdomains: ${new_or_changed_domains_count}${NC}"

        # Save the new data as old data for future comparison
        cp "$new_data_file" "$old_data_file"

        # Run Naabu (with suppressed output)
        echo -e "${GREEN}Running port scanning...${NC}"
        cat "$new_data_file" | naabu -silent > "$domain_recon_dir/naabu.txt"
        open_ports=$(wc -l < "$domain_recon_dir/naabu.txt")
        total_open_ports=$((total_open_ports + open_ports))

        # Run Nuclei (with suppressed output)
        echo -e "${GREEN}Running vulnerability scanning...${NC}"
        nuclei -l "$new_data_file" -t ~/nuclei-templates/ -severity high,critical -c 50 -rl 250 > "$domain_recon_dir/nuclei_results.txt"
        vulnerabilities=$(wc -l < "$domain_recon_dir/nuclei_results.txt")
        total_vulnerabilities=$((total_vulnerabilities + vulnerabilities))
        cat "$domain_recon_dir/nuclei_results.txt" | notify

        # Run KXSS and GF (with suppressed output)
        echo -e "${GREEN}Running XSS testing...${NC}"
        cat "$new_data_file" | gf xss | kxss > "$domain_recon_dir/xss_results.txt"
        xss_endpoints=$(wc -l < "$domain_recon_dir/xss_results.txt")
        total_xss_endpoints=$((total_xss_endpoints + xss_endpoints))
        cat "$domain_recon_dir/xss_results.txt" | notify

        # Content Discovery using Dirsearch (with suppressed output)
        echo -e "${GREEN}Running content discovery...${NC}"
        cat "$new_data_file" | dirsearch -t 100 > "$domain_recon_dir/dirsearch.txt"
        discovered_directories=$(wc -l < "$domain_recon_dir/dirsearch.txt")
        total_discovered_directories=$((total_discovered_directories + discovered_directories))
    else
        echo -e "${YELLOW}No new or changed subdomains for $domain. Skipping...${NC}"
    fi

    # Copy results to the output directory
    cp -r "$domain_recon_dir"/* "$output_dir/$domain/"
done

# Summary of Results
echo -e "${YELLOW}Summary of results:${NC}"
echo -e "${BLUE}Total domains processed: ${total_domains}${NC}"
echo -e "${BLUE}Total new or changed domains: ${total_new_or_changed}${NC}"
echo -e "${BLUE}Total live URLs found: ${total_live_urls}${NC}"
echo -e "${BLUE}Total open ports identified: ${total_open_ports}${NC}"
echo -e "${BLUE}Total vulnerabilities found: ${total_vulnerabilities}${NC}"
echo -e "${BLUE}Total XSS endpoints identified: ${total_xss_endpoints}${NC}"
echo -e "${BLUE}Total directories discovered: ${total_discovered_directories}${NC}"

echo -e "${GREEN}Reconnaissance and scanning completed!${NC}"
echo -e "${YELLOW}Results saved in $output_dir${NC}"
