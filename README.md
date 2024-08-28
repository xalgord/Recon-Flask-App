# Key Sections of the Script:

1. **Initial Setup**: The script sets up directories and checks if the required tools are installed.
2. **Domain Processing**: For each domain:
   - Subdomains are enumerated and probed with httpx to gather details like status codes and titles.
   - The new httpx output is compared with the old one to detect changes.
   - If changes are detected, the script proceeds with further reconnaissance, including port scanning, vulnerability scanning, content discovery, and XSS testing.
3. **Further Tests**: Only executed if the comparison shows that there are new or changed domains.
4. **Final Summary**: The script saves the results and provides a summary of the findings.

This script efficiently focuses on new or changed content while automating further testing based on detected changes.
