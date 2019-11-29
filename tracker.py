import requests
import re
import platform
import argparse
import subprocess
import socket

from prettytable import PrettyTable
from ipaddress import IPv4Address


def ipinfo_request(address: str) -> dict:
    url = f'https://ipinfo.io/{address}/json'
    data = requests.get(url)
    data = data.json()
    keys = ("org", "city", "country")
    return {key: data[key] if key in data.keys() else '?' for key in keys}


def ip_api_request(address: str) -> dict:
    url = f'http://ip-api.com/json/{address}'
    data = requests.get(url)
    data = data.json()
    # if 'isp' in data.keys():
    #     print(data['isp'])
    keys = ("org", "city", "country")
    return {key: data[key] if (key in data.keys() and data[key]) else '?' for key in keys}


def request_ip_data(address: str) -> dict:
    ip_apis = (ip_api_request,
               ipinfo_request)
    for api in ip_apis:
        try:
            data = api(address)
        except requests.RequestException:
            continue
        else:
            break
    else:
        return {}
    return data


def trace_win(address: str, use_icmp=False, max_hops=30) -> tuple:
    p = subprocess.Popen(('tracert', "-d", address), stdout=subprocess.PIPE)
    ip = list()
    while True:
        line = p.stdout.readline().decode('cp1256')
        if 'ms' in line:
            ip.append(line.split(' ')[-2])
        if not line:
            break
    return tuple(ip)


def trace_linux(address: str, use_icmp=False, max_hops=30) -> tuple:
    try:
        traceroute = f"{'sudo' if use_icmp else ''} traceroute {'-I' if use_icmp else ''} -m {max_hops} {address}"
        result = str(subprocess.check_output(traceroute,
                                             shell=True,
                                             stderr=subprocess.DEVNULL))
    except subprocess.CalledProcessError:
        raise ConnectionError
    else:
        ip_pattern = re.compile('\([0-9]+(?:\.[0-9]+){3}\)')
        ip_addresses = list()
        for line in result.split('\\n'):
            ip = re.findall(ip_pattern, line)
            ip = ip[0][1:-1] if ip else ''
            ip_addresses.append(ip)
        return tuple(ip_addresses[1:-1])


def get_domain_name_by_ip(address: str) -> str:
    try:
        domain_name = socket.gethostbyaddr(address)[0]
    except socket.herror:
        return ''
    else:
        return domain_name


def main():
    parser = argparse.ArgumentParser("AS-Tracker")
    parser.add_argument('host',
                        action='store')
    parser.add_argument('-m', '--max-ttl',
                        action='store',
                        type=int,
                        default=30,
                        dest='max_hops')
    parser.add_argument('-I',
                        action='store_true',
                        default=False,
                        dest='use_icmp')

    args = parser.parse_args()
    system = platform.system()
    if system == 'Windows':
        route = trace_win(args.host,
                          max_hops=args.max_hops)
    elif system == 'Linux':
        route = trace_linux(args.host,
                            use_icmp=args.use_icmp,
                            max_hops=args.max_hops)
    else:
        print("Unknown OS")
        return

    table = PrettyTable(("Number", "IP", "DOMAIN NAME", "AS", "CITY", "COUNTRY"))
    for counter, ip in enumerate(route):
        if ip:
            data = request_ip_data(ip)
            domain_name = get_domain_name_by_ip(ip)
            table.add_row((counter + 1, ip, domain_name, data['org'], data['city'], data['country']))
        else:
            table.add_row((counter + 1, '*', '*', '*', '*', '*'))
    print(table)


if __name__ == "__main__":
    main()
