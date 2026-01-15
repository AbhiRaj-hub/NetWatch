import nmap
import requests
import csv
import time
import datetime


def get_scan_choice():
    print("SELECT SCAN TYPE:")
    print("[1] Ping Scan          : Fast (Only discovers active devices")
    print("[2] TCP SYN Scan       : Stealthy port scan")
    print("[3] UDP Scan           : Service port scan (Slow)")
    print("[4] Intense Scan       : OS & Script detection ")
    print("*Some scans require sudo/Admin rights*")
    print("----------------------------------------------------------------")

    while True:
        choice = input("Enter choice (1-4): ")
        if choice == '1':
            return '-sn'
        elif choice == '2':
            return '-sS -T4'
        elif choice == '3':
            return '-sU -T4'
        elif choice == '4':
            return '-A -T4'
        else:
            print("\n[!] Invalid choice")

def scan_network(ip, scan_arguments):
    print(f"[+]Scanning {ip}")
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=ip, arguments=scan_arguments)
    except nmap.PortScannerError:
        print("[!]Nmap NOT Found. Exiting.")
        return []
    except Exception as e:
        print(f"[!]Error: {e}")
        return []
    client_list = []

    is_intense = '-A' in scan_arguments
    is_port_scan = '-sn' not in scan_arguments
    if is_intense:
        print(f"{'IP Address':<16}{'MAC Address':<18}{'Manufacturer':<22}{'OS':<20}{'Open Ports'}")
        print("-" * 100)
    elif is_port_scan:
        print(f"{'IP Address':<16}{'MAC Address':<18}{'Manufacturer':<22}{'Open Ports'}")
        print("-" * 80)
    else:
        print(f"{'IP Address':<20}{'MAC Address':<20}{'Manufacturer'}")
        print("-"*75)

    for host in nm.all_hosts():
         if 'mac' in nm[host]['addresses']:
             ip_addr = nm[host]['addresses']['ipv4']
             mac_addr = nm[host]['addresses']['mac']

             vendor = get_vendor(mac_addr)

             client_dict = {"IP": ip_addr, "MAC": mac_addr, "Vendor": vendor}

             if is_port_scan:
                 open_ports = get_open_ports(nm[host])
                 client_dict["Ports"] = open_ports

             if is_intense:
                 os_name = "Unknown"
                 if 'osmatch' in nm[host] and len(nm[host]['osmatch']) > 0:
                     os_name = nm[host]['osmatch'][0]['name']
                 client_dict["OS"] = os_name

             if is_intense:
                 print(f"{ip_addr:<16}{mac_addr:<18}{vendor[:20]:<22}{client_dict.get('OS', 'Unknown')[:18]:<20}{client_dict.get('Ports', 'N/A')[:20]}")

             elif is_port_scan:
                 print(f"{ip_addr:<16}{mac_addr:<18}{vendor[:20]:<22}{client_dict.get('Ports', 'N/A')[:20]}")

             else:
                 print(f"{ip_addr:<20}{mac_addr:<20}{vendor}")

             client_list.append(client_dict)
             time.sleep(1.0)

    return client_list


def get_open_ports(host_data):
    ports = []
    if 'tcp' in host_data:
        for port in host_data['tcp']:
            if host_data['tcp'][port]['state'] == 'open':
                ports.append(str(port))

    if 'udp' in host_data:
        for port in host_data['udp']:
            if host_data['udp'][port]['state'] == 'open':
                ports.append(f"{port}(UDP)")

    if ports:
        return ", ".join(ports)
    return "None Found"


def get_vendor(mac_address):
    url = f"https://api.maclookup.app/v2/macs/{mac_address}"
    try:
        response = requests.get(url, timeout=2)
        if response.status_code == 200:
            data = response.json()
            company = data.get('company', 'Unknown')
            if company and len(company.strip()) > 0:
               return company
            else:
               return "Unknown"
        elif response.status_code == 204:
            return "Unknown"
    except Exception:
        pass
    return "Unknown"


def save_to_csv(result_list):
    if not result_list:
        return

    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    filename = f"NetWatch_scan_{timestamp}.csv"
    keys = ["IP", "MAC", "Vendor"]
    if any('Ports' in device for device in result_list):
        keys.append("Ports")
    if any('OS' in device for device in result_list):
        keys.append("OS")

    with open(filename, 'w', newline='') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=keys, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(result_list)

    print(f"Scan result saved in {filename}")


def show_banner():
    ascii_art = r"""
    _   _      _ __        __    _       _     
   | \ | | ___| |\ \      / /_ _| |_ ___| |__  
   |  \| |/ _ \ __\ \ /\ / / _` | __/ __| '_ \ 
   | |\  |  __/ |_ \ V  V / (_| | || (__| | | |
   |_| \_|\___|\__| \_/\_/ \__,_|\__\___|_| |_|
    """
    print(ascii_art)
    print("_"*50)
    print(" Network Scanning Tool ")
    print("_"*50 + "\n")

if __name__ == "__main__":
    show_banner()
    target_ip = input("Enter the Target IP Range: ")

    if target_ip:
        scan_args = get_scan_choice()

        if '-sS' in scan_args or '-A' in scan_args or '-sU' in scan_args:
            print("[*] Note: You selected a Port Scan. Ensure you have sudo/admin rights.")

        scan_results = scan_network(target_ip, scan_args)

        if scan_results:
            save_to_csv(scan_results)
        else:
            print("[-] No Devices found or Scan failed.")
    else:
        print("[-] No IP entered. Exiting.")
