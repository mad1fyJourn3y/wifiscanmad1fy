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
import ipaddress
import os
import platform
import shutil
from concurrent.futures import ThreadPoolExecutor, as_completed

try:
    import requests
    HAVE_REQUESTS = True
except Exception:
    HAVE_REQUESTS = False

try:
    import psutil
    HAVE_PSUTIL = True
except Exception:
    HAVE_PSUTIL = False

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = '127.0.0.1'
    finally:
        try:
            s.close()
        except Exception:
            pass
    return local_ip

def parse_ip_j_addr(local_ip):
    try:
        out = subprocess.check_output(['ip', '-j', 'addr'], stderr=subprocess.DEVNULL)
        data = json.loads(out.decode('utf-8'))
        for iface in data:
            for addr in iface.get('addr_info', []):
                if addr.get('family') == 'inet' and addr.get('local') == local_ip:
                    prefix = addr.get('prefixlen')
                    network = ipaddress.IPv4Network(f"{local_ip}/{prefix}", strict=False)
                    return str(network)
    except Exception:
        return None

def parse_ifconfig(local_ip):
    try:
        out = subprocess.check_output(['ifconfig'], stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
        lines = out.splitlines()
        cur_iface = None
        for line in lines:
            if line and not line.startswith((' ', '\t')):
                parts = line.split()
                if parts:
                    cur_iface = parts[0]
            if 'inet ' in line or 'inet:' in line:
                tokens = line.replace('\t', ' ').split()
                iptok = None
                netmask = None
                for i, t in enumerate(tokens):
                    if t == 'inet' and i+1 < len(tokens):
                        iptok = tokens[i+1]
                    if t.startswith('inet:'):
                        iptok = t.split(':',1)[1]
                    if t == 'netmask' and i+1 < len(tokens):
                        netmask = tokens[i+1]
                    if t.startswith('netmask') and '=' in t:
                        netmask = t.split('=',1)[1]
                if iptok == local_ip:
                    if netmask:
                        try:
                            network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
                            return str(network)
                        except Exception:
                            continue
    except Exception:
        return None

def parse_ipconfig_windows(local_ip):
    try:
        out = subprocess.check_output(['ipconfig'], stderr=subprocess.DEVNULL).decode('utf-8', errors='ignore')
        blocks = out.split('\r\n\r\n')
        for block in blocks:
            if local_ip in block:
                lines = [l.strip() for l in block.splitlines() if l.strip()]
                ip_found = False
                ip_addr = None
                netmask = None
                for line in lines:
                    low = line.lower()
                    if low.startswith('ipv4 address') or low.startswith('ip address'):
                        parts = line.split(':', 1)
                        if len(parts) >= 2:
                            ip_addr = parts[1].strip()
                            ip_found = ip_addr == local_ip or ip_addr.startswith(local_ip)
                    if low.startswith('subnet mask'):
                        parts = line.split(':', 1)
                        if len(parts) >= 2:
                            netmask = parts[1].strip()
                if ip_found and netmask:
                    try:
                        network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
                        return str(network)
                    except Exception:
                        continue
        for block in blocks:
            lines = [l.strip() for l in block.splitlines() if l.strip()]
            ip_addr = None
            netmask = None
            for line in lines:
                low = line.lower()
                if low.startswith('ipv4 address') or low.startswith('ip address'):
                    parts = line.split(':', 1)
                    if len(parts) >= 2:
                        ip_addr = parts[1].strip()
                if low.startswith('subnet mask'):
                    parts = line.split(':', 1)
                    if len(parts) >= 2:
                        netmask = parts[1].strip()
            if ip_addr == local_ip and netmask:
                try:
                    network = ipaddress.IPv4Network(f"{local_ip}/{netmask}", strict=False)
                    return str(network)
                except Exception:
                    continue
    except Exception:
        return None

def get_network_range(local_ip):
    system = platform.system().lower()
    if system in ('linux',):
        r = parse_ip_j_addr(local_ip)
        if r:
            return r
        r = parse_ifconfig(local_ip)
        if r:
            return r
    elif system in ('darwin', 'freebsd', 'openbsd'):
        r = parse_ifconfig(local_ip)
        if r:
            return r
    elif system in ('windows',):
        r = parse_ipconfig_windows(local_ip)
        if r:
            return r
    if HAVE_PSUTIL:
        try:
            addrs = psutil.net_if_addrs()
            for iface, addr_list in addrs.items():
                for addr in addr_list:
                    family = getattr(addr, 'family', None)
                    try:
                        import socket as _s
                        fam_ok = family == _s.AF_INET
                    except Exception:
                        fam_ok = getattr(family, '__name__', '') == 'AF_INET'
                    if not fam_ok:
                        continue
                    a = getattr(addr, 'address', None) or getattr(addr, 'addr', None)
                    nm = getattr(addr, 'netmask', None)
                    if a == local_ip and nm:
                        try:
                            network = ipaddress.IPv4Network(f"{local_ip}/{nm}", strict=False)
                            return str(network)
                        except Exception:
                            continue
        except Exception:
            pass
    parts = local_ip.split('.')
    if len(parts) >= 4:
        return f"{parts[0]}.{parts[1]}.{parts[2]}.0/24"
    return "192.168.1.0/24"

def get_os_info(host_info):
    try:
        if isinstance(host_info, dict):
            if 'osmatch' in host_info and len(host_info['osmatch']) > 0:
                return host_info['osmatch'][0].get('name', 'Unknown OS')
            if 'osclass' in host_info and len(host_info['osclass']) > 0:
                oc = host_info['osclass'][0]
                return f"{oc.get('osfamily','')}/{oc.get('type','')}/{oc.get('vendor','')}"
    except Exception:
        pass
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

def build_nmap_arguments(fast, timeout, min_parallel, is_root, no_root_mode):
    if fast:
        args = f'-sn --host-timeout {timeout}s --max-retries 1 --min-parallelism {min_parallel}'
    else:
        if is_root and not no_root_mode:
            args = f'-O --host-timeout {timeout}s --max-retries 1 --min-parallelism {min_parallel}'
        else:
            args = f'-sT -Pn --host-timeout {timeout}s --max-retries 1 --min-parallelism {min_parallel}'
    return args

def run_nmap_scan(target_ip_range, timeout=30, fast=False, min_parallel=10, is_root=True, no_root_mode=False):
    nm = nmap.PortScanner()
    print("[*] Starting Nmap scan (discovery)...")
    arguments = build_nmap_arguments(fast, timeout, min_parallel, is_root, no_root_mode)
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
        mac = None
        vendor = None
        try:
            if 'addresses' in nm[host] and 'mac' in nm[host]['addresses']:
                mac = nm[host]['addresses'].get('mac')
            if 'vendor' in nm[host] and nm[host]['vendor']:
                if isinstance(nm[host]['vendor'], dict):
                    vendor_vals = list(nm[host]['vendor'].values())
                    vendor = vendor_vals[0] if vendor_vals else None
                else:
                    vendor = nm[host]['vendor']
        except Exception:
            pass
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

def run_vuln_scan_single(ip, extra_args=None, no_root_mode=False):
    cmd = ['nmap', '-sV', '--script', 'vuln', '-Pn', ip]
    if no_root_mode:
        cmd = ['nmap', '-sT', '-sV', '--script', 'vuln', '-Pn', ip]
    if extra_args:
        cmd = cmd + extra_args
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        print("\n[!] Vulnerability scan interrupted by user.")
    except Exception as e:
        print(f"[!] Error running vulnerability scan on {ip}: {e}")

def run_vuln_scans_concurrent(devices, extra_args=None, max_workers=6, no_root_mode=False):
    if not devices:
        return
    workers = min(max_workers, len(devices))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        futures = {ex.submit(run_vuln_scan_single, d['ip'], extra_args, no_root_mode): d for d in devices}
        for fut in as_completed(futures):
            d = futures[fut]
            try:
                fut.result()
            except Exception as e:
                print(f"[!] Error scanning {d['ip']}: {e}")

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

def is_running_as_root():
    system = platform.system().lower()
    if system in ('linux', 'darwin') or hasattr(os, 'geteuid'):
        try:
            return os.geteuid() == 0
        except Exception:
            pass
    if system == 'windows':
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            pass
    return False

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
    group = parser.add_mutually_exclusive_group()
    group.add_argument('--no-root', action='store_true', help='Run without root privileges and avoid root-only nmap options')
    group.add_argument('--no-root-nogui', action='store_true', help='Run without root privileges and avoid any GUI-related features')
    parser.add_argument('--min-parallel', type=int, default=10, help='Min parallelism for nmap (default 10)')
    parser.add_argument('--vuln-workers', type=int, default=6, help='Concurrent workers for vuln scans (default 6)')
    args = parser.parse_args()
    local_ip = get_local_ip()
    if args.range:
        network_range = args.range
    else:
        network_range = get_network_range(local_ip)
    root_state = is_running_as_root()
    no_root_mode = bool(args.no_root or args.no_root_nogui)
    print(r"""
                  ███     ██████   ███                                       
                 ░░░     ███░░███ ░░░                                        
 █████ ███ █████ ████   ░███ ░░░  ████   █████   ██████   ██████   ████████  
░░███ ░███░░███ ░░███  ███████   ░░███  ███░░   ███░░███ ░░░░░███ ░░███░░███ 
 ░███ ░███ ░███  ░███ ░░░███░     ░███ ░░█████ ░███ ░░░   ███████  ░███ ░███ 
 ░░███████████   ░███   ░███      ░███  ░░░░███░███  ███ ███░░███  ░███ ░███ 
  ░░████░████    █████  █████     █████ ██████ ░░██████ ░░████████ ████ █████
   ░░░░ ░░░░    ░░░░░  ░░░░░     ░░░░░ ░░░░░░   ░░░░░░   ░░░░░░░░ ░░░░ ░░░░░ 
This code is made/edited by mad1fy.
This tool is designed to find all the devices wired or wireless on the network.
https://mad1fyjourn3y.github.io/
""")
    if not root_state and not no_root_mode:
        print("[!] Warning: not running as root. For full capability run with sudo / admin or use --no-root to force non-root mode.")
    print(f"[*] Local IP: {local_ip}")
    print(f"[*] Scanning local network: {network_range}")
    devices = run_nmap_scan(network_range, timeout=args.timeout, fast=args.fast, min_parallel=args.min_parallel, is_root=root_state, no_root_mode=no_root_mode)
    if not devices:
        print("No devices found on the network.")
        return
    display_device_info(devices)
    if args.save_json:
        save_json(devices, args.save_json)
    if args.save_csv:
        save_csv(devices, args.save_csv)
    if args.webhook:
        post_webhook(devices, args.webhook)
    if args.no_interactive:
        print("[*] non-interactive mode set -> exiting after save/post operations.")
        return
    print("\nChoose scan mode:")
    print("  1 - Auto Vulnerability Scan All Devices (nmap --script vuln)")
    print("  2 - Manual Vulnerability Scan (Pick one device to vuln-scan)")
    mode = input("Enter your choice: ").strip()
    extra_vuln_args = None
    if args.vuln_args:
        extra_vuln_args = args.vuln_args.split()
    if mode == '1':
        print("[*] Starting concurrent vulnerability scans")
        run_vuln_scans_concurrent(devices, extra_args=extra_vuln_args, max_workers=args.vuln_workers, no_root_mode=no_root_mode)
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
                    run_vuln_scan_single(ip, extra_args=extra_vuln_args, no_root_mode=no_root_mode)
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
