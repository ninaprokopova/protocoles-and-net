import sys
import os
import re
from prettytable import PrettyTable
from urllib.request import urlopen

reProvider = re.compile(r'mnt-by: *([\w\d-]+?)\n')
reCountry = re.compile(r'[Cc]ountry: *([\w]+?)\n')
reAS = re.compile(r'[Oo]riginA?S?: *([\d\w]+?)\n')
reIP = re.compile(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}')


def parse(site, reg):
    try:
        a = reg.findall(site)
        return a[0]
    except:
        return ''


def is_grey_ip(ip: str) -> bool:
    return ip.startswith('10.') or \
           ip.startswith('192.168.') or \
           (ip.startswith('172.') and 15 < int(ip.split('.')[1]) < 32)


def get_table(ips_data: list) -> PrettyTable:
    head = [' ', 'IP', 'AS', 'Country', 'Provider']
    table = PrettyTable()
    table.field_names = head
    for el in ips_data:
        table.add_row(el)
    return table


def get_info_by_ip(ip: str):
    if is_grey_ip(ip):
        return [ip, '', '', '']
    url = f'https://www.nic.ru/whois/?searchWord={ip}'
    try:
        with urlopen(url) as f:
            site = f.read().decode('utf-8')
        a_sys = parse(site, reAS)
        country = parse(site, reCountry)
        provider = parse(site, reProvider)
        return [ip, a_sys, country, provider]
    except:
        return [ip, '', '', '']


def get_IP_data(ips: list):
    ips_data = []
    for i, ip in enumerate(ips):
        info = get_info_by_ip(ip)
        info.insert(0, i)
        ips_data.append(info)
    return ips_data


def get_IP_tracert(name: str) -> list:
    cmd_line = f"tracert {name}"
    cmd = os.popen(cmd_line)
    stdout = cmd.read()
    return reIP.findall(stdout)


def main():
    if len(sys.argv) < 2:
        print(f'Usage: python traceAS.py *name or ip*')
        sys.exit(1)
    ips = get_IP_tracert(sys.argv[1])
    ips_data = get_IP_data(ips)
    table = get_table(ips_data)
    with open('traceAS.txt', 'w', ) as f:
        f.write(str(table))


if __name__ == '__main__':
    main()
