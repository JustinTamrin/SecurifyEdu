import nmap
from ipwhois import IPWhois
import requests
import socket
from concurrent.futures import ThreadPoolExecutor
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def scan_host(ip, ports):
    try:
        nm = nmap.PortScanner()
        result = nm.scan(hosts=ip, ports=ports, arguments='-sS -Pn')  # TCP SYN scan, no ping

        if nm[ip].state() == 'up':
            return {'host': ip, 'status': 'up', 'open_ports': nm[ip]['tcp'].keys()}
        else:
            return {'host': ip, 'status': 'down', 'open_ports': []}

    except Exception as e:
        logger.error(f"Error scanning {ip}: {str(e)}")
        return {'host': ip, 'status': 'error', 'open_ports': []}

def scan_network(ip_range, num_threads=5, ports='22-80'):
    try:
        result = []
        ip_list = ip_range.split('-')
        start_ip = ip_list[0].strip()
        end_ip = ip_list[1].strip() if len(ip_list) > 1 else start_ip

        start_ip = socket.gethostbyname(start_ip)
        end_ip = socket.gethostbyname(end_ip)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(scan_host, ip, ports) for ip in range(int(ip_to_int(start_ip)),
                                                                              int(ip_to_int(end_ip)) + 1)]

            for future in futures:
                result.append(future.result())

        return result
    except Exception as e:
        logger.error(f"Error scanning network: {str(e)}")
        return str(e)

def ip_to_int(ip):
    return sum(int(x) << (24 - i * 8) for i, x in enumerate(ip.split('.')))

def get_ip_info(ip):
    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap()
        return result
    except Exception as e:
        logger.error(f"Error getting IP information for {ip}: {str(e)}")
        return str(e)

def get_phone_location(phone_number):
    # You need to integrate with a phone number location API
    # Example: Replace 'YOUR_API_KEY' with the actual API key from a service like Numverify
    api_key = 'YOUR_API_KEY'
    url = f'http://apilayer.net/api/validate?access_key={api_key}&number={phone_number}'

    response = requests.get(url)
    data = response.json()

    if 'valid' in data and data['valid']:
        return data['country_name']
    else:
        return 'Location not available'

if __name__ == "__main__":
    while True:
        print("Cyber Security Chatbot")
        print("1. Scan Network")
        print("2. Get IP Information")
        print("3. Get Phone Number Location")
        print("4. Exit")

        choice = input("Enter your choice: ")

        if choice == '1':
            ip_range = input("Enter IP range (e.g., 192.168.1.1 - 192.168.1.10): ")
            num_threads = int(input("Enter the number of threads for scanning (default is 5): ") or 5)
            ports = input("Enter the range of ports to scan (default is 22-80): ") or '22-80'
            result = scan_network(ip_range, num_threads=num_threads, ports=ports)
            print("Scan Results:")
            for host_info in result:
                print(f"Host: {host_info['host']}, Status: {host_info['status']}, Open Ports: {host_info['open_ports']}")

        elif choice == '2':
            ip = input("Enter IP address: ")
            result = get_ip_info(ip)
            print("IP Information:", result)

        elif choice == '3':
            phone_number = input("Enter phone number: ")
            result = get_phone_location(phone_number)
            print("Phone Number Location:", result)

        elif choice == '4':
            print("Exiting...")
            break

        else:
            print("Invalid choice. Please try again.")
