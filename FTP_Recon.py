#!/usr/bin/env python3

import argparse
import subprocess
import os
import ftplib
import threading
import queue
from colorama import Fore, Style, init
from pyfiglet import Figlet

# Initialize colorama for cross-platform color output
init(autoreset=True)

# Lock for thread-safe print
lock = threading.Lock()

def print_banner():
    f = Figlet(font='small')
    banner = f.renderText('DEFAULT FTP SLAYER')
    print(f"{Fore.MAGENTA}{banner}{Style.RESET_ALL}")

def run_subfinder(domain, output_file):
    print(f"{Fore.CYAN}[+] Running subfinder for domain: {domain}")
    try:
        subprocess.run(["subfinder", "-d", domain, "-o", output_file], check=True)
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[-] subfinder failed: {e}")
        exit(1)

def run_httpx(input_file, output_file):
    print(f"{Fore.CYAN}[+] Running httpx to find live hosts")
    try:
        subprocess.run(["httpx", "-silent", "-ip", "-l", input_file, "-o", output_file], check=True)
    except subprocess.CalledProcessError as e:
        print(f"{Fore.RED}[-] httpx failed: {e}")
        exit(1)

def extract_ips(httpx_file):
    ips = set()
    try:
        with open(httpx_file, "r") as f:
            for line in f:
                parts = line.strip().split(" ")
                if len(parts) >= 2:
                    ip = parts[-1]
                    ips.add(ip)
    except FileNotFoundError:
        print(f"{Fore.RED}[-] httpx output file not found")
        exit(1)
    return ips

def check_ftp_anonymous(ip, output_queue):
    try:
        ftp = ftplib.FTP(ip, timeout=5)
        ftp.login()
        ftp.quit()
        with lock:
            print(f"{Fore.GREEN}[!] Anonymous FTP login SUCCESS on {ip}")
            output_queue.put(ip)
    except Exception:
        with lock:
            print(f"{Fore.YELLOW}[-] Anonymous FTP login failed on {ip}")

def ftp_worker(ip_queue, output_queue):
    while True:
        ip = ip_queue.get()
        if ip is None:
            break
        check_ftp_anonymous(ip, output_queue)
        ip_queue.task_done()

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description="HAPPY S1NGH Recon + FTP Anonymous Login Checker"
    )
    parser.add_argument(
        "-d", "--domain", help="Target domain for subfinder + httpx", required=False
    )
    parser.add_argument(
        "-u", "--url", help="Single URL to check with httpx", required=False
    )
    parser.add_argument(
        "-i", "--ip", help="Single IP to check FTP anonymous login", required=False
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=10, help="Number of FTP threads (default: 10)"
    )
    args = parser.parse_args()

    os.makedirs("output", exist_ok=True)
    output_queue = queue.Queue()

    if args.domain:
        subdomains_file = f"output/{args.domain}_subdomains.txt"
        httpx_file = f"output/{args.domain}_livehosts.txt"
        ftp_success_file = f"output/{args.domain}_ftp_anonymous.txt"

        run_subfinder(args.domain, subdomains_file)
        run_httpx(subdomains_file, httpx_file)

        ips = extract_ips(httpx_file)

    elif args.url:
        httpx_file = f"output/single_url_livehosts.txt"
        ftp_success_file = f"output/single_url_ftp_anonymous.txt"

        with open("temp_url.txt", "w") as f:
            f.write(args.url)

        run_httpx("temp_url.txt", httpx_file)
        ips = extract_ips(httpx_file)
        os.remove("temp_url.txt")

    elif args.ip:
        ips = {args.ip}
        ftp_success_file = f"output/single_ip_ftp_anonymous.txt"

    else:
        print(f"{Fore.RED}[-] Please provide --domain, --url, or --ip")
        parser.print_help()
        exit(1)

    print(f"{Fore.CYAN}[+] Total unique IPs to check: {len(ips)}")

    ip_queue = queue.Queue()
    for ip in ips:
        ip_queue.put(ip)

    threads = []
    for _ in range(args.threads):
        t = threading.Thread(target=ftp_worker, args=(ip_queue, output_queue))
        t.start()
        threads.append(t)

    ip_queue.join()

    for _ in threads:
        ip_queue.put(None)
    for t in threads:
        t.join()

    with open(ftp_success_file, "w") as f:
        while not output_queue.empty():
            f.write(output_queue.get() + "\n")

    print(f"{Fore.GREEN}[+] All done! Valid anonymous FTP IPs saved in {ftp_success_file}")

if __name__ == "__main__":
    main()
