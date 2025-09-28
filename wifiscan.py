#!/usr/bin/env python3
import subprocess
import nmap
import socket
import argparse
import json
import csv
import sys
import time
from datetime import datetime

# Try to import requests for webhook posting; handle gracefully if not installed
try:
    import requests
    HAVE_REQUESTS = True
except Exception:
    HAVE_REQUESTS = False

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        s.close()
    return local_ip

def get_network_range(local_ip):
    ip_parts = local_ip.split('.')
    if len(ip_parts) < 4:
        return "192.168.1.0/24"
    return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.0/24"

def get_os_info(host_info):
    if 'osmatch' in host_info and len(host_info['osmatch']) > 0:
        return host_info['osmatch'][0]['name']
    else:
        # sometimes nmap stores fingerprint as 'osclass' entries
        if 'osclass' in host_info and len(host_info['osclass']) > 0:
            try:
                oc = host_info['osclass'][0]
                return f"{oc.get('osfamily','')}/{oc.get('type','')}/{oc.get('vendor','')}"
            except Exception:
                return 'Unknown OS'
        return 'Unknown OS'

def get_device_type(os_fingerprint):
    if not os_fingerprint:
        return "Unknown Device"
    if "Android" in os_fingerprint:
        return "Android"
    elif "Windows" in os_fingerprint:
        return "Windows"
    elif "iPhone" in os_fingerprint or "iOS" in os_fingerprint:
        return "iOS"
    elif "Linux" in os_fingerprint:
        return "Linux"
    elif "Mac" in os_fingerprint or "Darwin" in os_fingerprint:
        return "MacOS"
    else:
        return "Unknown Device"

def display_device_info(devices):
    for i, device in enumerate(devices, 1):
        print(f"\n[{i}] Device: {device.get('name') or 'unknown'}")
        print(f"    IP Address: {device.get('ip')}")
        print(f"    MAC: {device.get('mac') or 'N/A'}")
        print(f"    Vendor: {device.get('vendor') or 'N/A'}")
        print(f"    OS: {device.get('os')}")
        print(f"    Status: {device.get('status')}")
        print(f"    Device Type: {get_device_type(device.get('os'))}")

def run_nmap_scan(target_ip_range, timeout=30, fast=False, min_parallel=10):
    nm = nmap.PortScanner()
    print("[*] Starting Nmap scan (discovery)...")
    # Choose flags based on fast or default
    if fast:
        arguments = f'-sn --host-timeout {timeout}s --max-retries 1 --min-parallelism {min_parallel}'
    else:
        arguments = f'-O --host-timeout {timeout}s --max-retries 1 --min-parallelism {min_parallel}'
    try:
        nm.scan(hosts=target_ip_range, arguments=arguments)
    except KeyboardInterrupt:
        print("\n[!] Scan interrupted by user.")
        return []
    except Exception as e:
        print(f"[!] Scan error: {e}")
        return []

    devices = []
    hosts = nm.all_hosts()
    total = len(hosts)

    if total == 0:
        print("[!] No hosts returned by nmap.")
        return []

    for idx, host in enumerate(hosts, 1):
        percent = (idx / total) * 100 if total > 0 else 100
        print(f"[{idx}/{total}] {host} scanned ({percent:.1f}%)")

        # gather vendor/mac if available from nmap
        mac = None
        vendor = None
        try:
            if 'addresses' in nm[host] and 'mac' in nm[host]['addresses']:
                mac = nm[host]['addresses'].get('mac')
            # vendor sometimes lives at nm[host]['vendor'] as dict or string
            if 'vendor' in nm[host] and nm[host]['vendor']:
                if isinstance(nm[host]['vendor'], dict):
                    vendor_vals = list(nm[host]['vendor'].values())
                    vendor = vendor_vals[0] if vendor_vals else None
                else:
                    vendor = nm[host]['vendor']
        except Exception:
            pass

        # hostname() and state() are available via PortScannerHostDict interface
        try:
            hostname = nm[host].hostname()
        except Exception:
            hostname = ''
        try:
            state = nm[host].state()
        except Exception:
            state = ''

        device = {
            'ip': host,
            'name': hostname,
            'os': get_os_info(nm[host]) if isinstance(nm[host], dict) else get_os_info(nm[host]),
            'status': state,
            'mac': mac,
            'vendor': vendor
        }
        devices.append(device)
    return devices

def run_vuln_scan(ip, extra_args=None):
    """
    Runs nmap vulnerability script scan (--script vuln) against the given IP.
    extra_args: list of additional nmap args to append (e.g. ['-p', '80,443'])
    """
    print(f"[*] Running vulnerability scan (--script vuln) on {ip}")
    cmd = ['nmap', '-sV', '--script', 'vuln', '-Pn', ip]
    if extra_args:
        cmd = cmd + extra_args
    try:
        # Use subprocess.run so output streams to console directly
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n[!] Vulnerability scan interrupted by user.")
    except Exception as e:
        print(f"[!] Error running vulnerability scan: {e}")

def save_json(devices, filename):
    try:
        with open(filename, 'w') as f:
            json.dump({'scanned_at': datetime.utcnow().isoformat() + 'Z', 'devices': devices}, f, indent=2)
        print(f"[✓] Saved JSON results to {filename}")
    except Exception as e:
        print(f"[!] Failed to save JSON: {e}")

def save_csv(devices, filename):
    try:
        keys = ['ip', 'name', 'mac', 'vendor', 'os', 'status']
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=keys)
            writer.writeheader()
            for d in devices:
                writer.writerow({k: d.get(k, '') for k in keys})
        print(f"[✓] Saved CSV results to {filename}")
    except Exception as e:
        print(f"[!] Failed to save CSV: {e}")

def post_webhook(devices, url):
    payload = {'scanned_at': datetime.utcnow().isoformat() + 'Z', 'devices': devices}
    if not HAVE_REQUESTS:
        print("[!] requests module not installed; cannot post webhook. Install with: pip install requests")
        return
    try:
        r = requests.post(url, json=payload, timeout=15)
        print(f"[✓] Webhook POST returned status: {r.status_code}")
    except Exception as e:
        print(f"[!] Webhook POST failed: {e}")

def main():
    parser = argparse.ArgumentParser(description="wifiscanmad1fy - network discovery and vuln-scan helper")
    parser.add_argument('-j', '--save-json', help='Save results as JSON file')
    parser.add_argument('-c', '--save-csv', help='Save results as CSV file')
    parser.add_argument('-w', '--webhook', help='POST JSON results to webhook URL')
    parser.add_argument('--fast', action='store_true', help='Use faster nmap flags (less accurate discovery)')
    parser.add_argument('--timeout', type=int, default=30, help='nmap host timeout in seconds (default 30)')
    parser.add_argument('--no-interactive', action='store_true', help='Skip interactive selection and do not run vuln scans')
    parser.add_argument('--range', help='Target network range e.g. 192.168.1.0/24 (overrides auto detection)')
    parser.add_argument('--vuln-args', help='Additional arguments for vuln scan (quoted string, split by space)', default=None)
    args = parser.parse_args()

    print(r"""
                  ███     ██████   ███                                       
                 ░░░     ███░░███ ░░░                                        
 █████ ███ █████ ████   ░███ ░░░  ████   █████   ██████   ██████   ████████  
░░███ ░███░░███ ░░███  ███████   ░░███  ███░░   ███░░███ ░░░░░███ ░░███░░███ 
 ░███ ░███ ░███  ░███ ░░░███░     ░███ ░░█████ ░███ ░░░   ███████  ░███ ░███ 
 ░░███████████   ░███   ░███      ░███  ░░░░███░███  ███ ███░░███  ░███ ░███ 
  ░░████░████    █████  █████     █████ ██████ ░░██████ ░░████████ ████ █████
   ░░░░ ░░░░    ░░░░░  ░░░░░     ░░░░░ ░░░░░░   ░░░░░░   ░░░░░░░░ ░░░░ ░░░░░ 
                                                                             
                                                                             
                                                                             
 ██████   ██████   █████████   ██████████   ████  ███████████ █████ █████    
░░██████ ██████   ███░░░░░███ ░░███░░░░███ ░░███ ░░███░░░░░░█░░███ ░░███     
 ░███░█████░███  ░███    ░███  ░███   ░░███ ░███  ░███   █ ░  ░░███ ███      
 ░███░░███ ░███  ░███████████  ░███    ░███ ░███  ░███████     ░░█████       
 ░███ ░░░  ░███  ░███░░░░░███  ░███    ░███ ░███  ░███░░░█      ░░███        
 ░███      ░███  ░███    ░███  ░███    ███  ░███  ░███  ░        ░███        
 █████     █████ █████   █████ ██████████   █████ █████          █████    ██ 
░░░░░     ░░░░░ ░░░░░   ░░░░░ ░░░░░░░░░░   ░░░░░ ░░░░░          ░░░░░    ░░  
                                                                             
                                                                             
                                                                             
This code is made/edited by mad1fy.
This tool is designed to find all the devices wired or wireless on the network.
https://mad1fyjourn3y.github.io/
""")

    local_ip = get_local_ip()
    if args.range:
        network_range = args.range
    else:
        network_range = get_network_range(local_ip)

    print(f"[*] Local IP: {local_ip}")
    print(f"[*] Scanning local network: {network_range}")
    devices = run_nmap_scan(network_range, timeout=args.timeout, fast=args.fast)

    if not devices:
        print("No devices found on the network.")
        return

    display_device_info(devices)

    # Save outputs if requested
    if args.save_json:
        save_json(devices, args.save_json)
    if args.save_csv:
        save_csv(devices, args.save_csv)
    if args.webhook:
        post_webhook(devices, args.webhook)

    if args.no_interactive:
        print("[*] non-interactive mode set -> exiting after save/post operations.")
        return

    # Interactive mode (discovery completed). When user chooses, perform vuln scans.
    print("\nChoose scan mode:")
    print("  1 - Auto Vulnerability Scan All Devices (nmap --script vuln)")
    print("  2 - Manual Vulnerability Scan (Pick one device to vuln-scan)")
    mode = input("Enter your choice: ").strip()

    # prepare extra args for vuln scan if provided
    extra_vuln_args = None
    if args.vuln_args:
        extra_vuln_args = args.vuln_args.split()

    if mode == '1':
        for device in devices:
            print(f"\n[*] Running vulnerability scan on {device['ip']} ({device['name']})")
            run_vuln_scan(device['ip'], extra_args=extra_vuln_args)
        print("\n[✓] Auto vulnerability scans completed.")
    elif mode == '2':
        while True:
            print("\nOptions:")
            print("  0 - Exit")
            print("  Select device number to run vulnerability scan on it")
            choice = input("Enter your choice: ").strip()

            if choice == '0':
                print("Exiting...")
                break

            if choice.isdigit():
                choice_num = int(choice)
                if 1 <= choice_num <= len(devices):
                    ip = devices[choice_num - 1]['ip']
                    run_vuln_scan(ip, extra_args=extra_vuln_args)
                else:
                    print("Invalid device number.")
            else:
                print("Invalid input. Enter 0 or a device number.")
    else:
        print("[!] Invalid mode selected. Exiting.")

if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] User aborted. Exiting.")
        sys.exit(0)
