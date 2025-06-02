import requests
from bs4 import BeautifulSoup
import socket
import re
import dns.resolver
import whois
import csv
from urllib.parse import urljoin, urlparse
import time
import os
from colorama import Fore, Style, init


init(autoreset=True)

def get_links_and_text(url):
    internal_links = []
    external_links = []
    page_text_content = ""

    try:
        response = requests.get(url, timeout=10)
        response.raise_for_status()

        if 'text/html' in response.headers.get('Content-Type', ''):
            soup = BeautifulSoup(response.text, 'html.parser')
            page_text_content = soup.get_text()

            base_domain = urlparse(url).netloc
            for tag in soup.find_all('a', href=True):
                link = urljoin(url, tag['href'])
                
                cleaned_link = link.split('#')[0]
                cleaned_link = cleaned_link.split('?')[0]

                if cleaned_link.startswith("http://") or cleaned_link.startswith("https://"):
                    if urlparse(cleaned_link).netloc == base_domain:
                        if cleaned_link not in internal_links:
                            internal_links.append(cleaned_link)
                    else:
                        if cleaned_link not in external_links:
                            external_links.append(cleaned_link)
    except requests.exceptions.RequestException:
        pass
    except Exception:
        pass

    return internal_links, external_links, page_text_content

def crawl_website(start_url, max_depth=1):
    visited_urls = set()
    urls_to_visit = [start_url]
    all_gathered_internal_links = []
    all_gathered_external_links = []
    total_text_content = []

    current_depth = 0

    while urls_to_visit and current_depth <= max_depth:
        next_urls_to_visit = []

        for url in urls_to_visit:
            if url in visited_urls:
                continue

            visited_urls.add(url)

            internal, external, text = get_links_and_text(url)
            total_text_content.append(text)

            for i_link in internal:
                if i_link not in all_gathered_internal_links:
                    all_gathered_internal_links.append(i_link)
                if i_link not in visited_urls and i_link not in next_urls_to_visit:
                    next_urls_to_visit.append(i_link)

            for e_link in external:
                if e_link not in all_gathered_external_links:
                    all_gathered_external_links.append(e_link)
            
            time.sleep(0.5)

        urls_to_visit = next_urls_to_visit
        current_depth += 1

    return all_gathered_internal_links, all_gathered_external_links, " ".join(total_text_content)

def read_subdomain_wordlist(filepath="sub.txt"):
    words = []
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            for line in f:
                word = line.strip()
                if word:
                    words.append(word)
    except FileNotFoundError:
        pass
    except Exception as e:
        pass
    return words

def resolve_ip(hostname):
    try:
        ip_address = socket.gethostbyname(hostname)
        return ip_address
    except socket.gaierror:
        return None
    except Exception:
        return None

def scan_common_ports(ip):
    common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 993, 995, 3389, 8080]
    open_ports = []
    for port in common_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.1)
            result = s.connect_ex((ip, port))
            if result == 0:
                open_ports.append(port)
            s.close()
        except Exception:
            pass
    return open_ports

def find_subdomains(main_domain, wordlist):
    found_subdomains = {}
    if not wordlist:
        return found_subdomains

    for word in wordlist:
        subdomain_candidate = f"{word}.{main_domain}"
        ip_address = resolve_ip(subdomain_candidate)
        if ip_address:
            found_subdomains[subdomain_candidate] = {'ip': ip_address, 'status': 'Unknown', 'title': 'Unknown'}
        time.sleep(0.05)
    return found_subdomains

def extract_emails_and_phones(text):
    emails = list(set(re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)))
    
    phone_pattern = r'\b(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b'
    raw_phones = re.findall(phone_pattern, text)
    
    clean_phones = []
    for p in raw_phones:
        cleaned = re.sub(r'[^0-9]', '', p)
        if len(cleaned) >= 7 and cleaned not in clean_phones:
            clean_phones.append(cleaned)

    return emails, clean_phones

def get_whois_info(domain):
    whois_data = {}
    try:
        info = whois.whois(domain)
        for key, value in info.items():
            if value is not None:
                whois_data[key] = str(value)
            else:
                whois_data[key] = "N/A"
    except whois.parser.PywhoisError as e:
        whois_data['Error'] = f"WHOIS Lookup Failed: {str(e)}"
    except Exception as e:
        whois_data['Error'] = f"WHOIS Lookup Failed: {str(e)}"
    return whois_data

def save_results(results_data, domain_name):
    output_filename = f"{domain_name}_recon_results.csv"
    
    with open(output_filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)

        writer.writerow(["--- Website Recon Results ---"])

        writer.writerow(["Target URL", results_data.get('target_url', '')])
        writer.writerow(["Domain", results_data.get('domain', '')])

        writer.writerow([])
        writer.writerow(["--- Internal Links ---"])
        if results_data.get('internal_links'):
            for link in results_data['internal_links']:
                writer.writerow([link])
        else:
            writer.writerow(["Not found."])

        writer.writerow([])
        writer.writerow(["--- External Links ---"])
        if results_data.get('external_links'):
            for link in results_data['external_links']:
                writer.writerow([link])
        else:
            writer.writerow(["Not found."])

        writer.writerow([])
        writer.writerow(["--- Subdomains ---"])
        if results_data.get('subdomains'):
            writer.writerow(["Subdomain", "IP Address"])
            for sub, data in results_data['subdomains'].items():
                writer.writerow([sub, data.get('ip', '')])
        else:
            writer.writerow(["Not found."])
        
        writer.writerow([])
        writer.writerow(["--- Main Domain IP & Open Ports ---"])
        if results_data.get('main_ip'):
            writer.writerow(["Main IP", results_data['main_ip']])
            if results_data.get('open_ports'):
                writer.writerow(["Open Ports", ", ".join(map(str, results_data['open_ports']))])
            else:
                writer.writerow(["Open Ports", "Not found."])
        else:
            writer.writerow(["Main IP", "Not found."])

        writer.writerow([])
        writer.writerow(["--- Contacts ---"])
        if results_data.get('emails'):
            writer.writerow(["Emails", ", ".join(results_data['emails'])])
        else:
            writer.writerow(["Emails", "Not found."])
        if results_data.get('phones'):
            writer.writerow(["Phones", ", ".join(results_data['phones'])])
        else:
            writer.writerow(["Phones", "Not found."])

        writer.writerow([])
        writer.writerow(["--- WHOIS Information ---"])
        if results_data.get('whois_info'):
            for key, value in results_data['whois_info'].items():
                writer.writerow([key.replace('_', ' ').title(), value])
        else:
            writer.writerow(["Not found."])
    
    return output_filename

if __name__ == "__main__":
    print(Style.BRIGHT + Fore.CYAN + "Welcome to Recon Tool!" + Style.RESET_ALL)
    print(Fore.GREEN + "="*30 + Style.RESET_ALL)

    start_url = input("Enter the website URL: ").strip()

    parsed_url = urlparse(start_url)
    domain_name = parsed_url.netloc
    if not domain_name and parsed_url.path:
        domain_name = parsed_url.path.split('/')[0]

    if not domain_name:
        print(Fore.RED + "Error: Could not identify domain from the provided URL." + Style.RESET_ALL)
        exit()

    all_results = {
        'target_url': start_url,
        'domain': domain_name,
        'internal_links': [],
        'external_links': [],
        'all_crawled_text': "",
        'subdomains': {},
        'main_ip': None,
        'open_ports': [],
        'emails': [],
        'phones': [],
        'whois_info': {}
    }

    internal_links, external_links, crawled_text = crawl_website(start_url, max_depth=1)
    all_results['internal_links'] = internal_links
    all_results['external_links'] = external_links
    all_results['all_crawled_text'] = crawled_text

    main_ip_address = resolve_ip(domain_name)
    if main_ip_address:
        all_results['main_ip'] = main_ip_address
        open_ports_found = scan_common_ports(main_ip_address)
        all_results['open_ports'] = open_ports_found
    else:
        pass

    wordlist_for_subdomains = read_subdomain_wordlist()
    found_subdomains_data = find_subdomains(domain_name, wordlist_for_subdomains)
    all_results['subdomains'] = found_subdomains_data

    extracted_emails, extracted_phones = extract_emails_and_phones(crawled_text)
    all_results['emails'] = extracted_emails
    all_results['phones'] = extracted_phones

    whois_data = get_whois_info(domain_name)
    all_results['whois_info'] = whois_data

    output_file = save_results(all_results, domain_name)

    print("\n" + Style.BRIGHT + Fore.GREEN + "Task completed!" + Style.RESET_ALL)
    print(Fore.YELLOW + f"Check the file: {output_file}" + Style.RESET_ALL)