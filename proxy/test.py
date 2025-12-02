import base64
import binascii

import requests

ip = "65.181.175.113"
port = 63302
proxy_user = "fpjzammc"
proxy_pass = "0hxwV8z3E5"

proxies = {
    "http": f"http://{ip}:{port}",
    "https": f"https://{ip}:{port}"
}
credentials = base64.b64encode(f"{proxy_user}:{proxy_pass}".encode()).decode()
headers = {"Proxy-Authorization": f"Basic {credentials}"}

response = requests.get("https://dkpg-web.payments.kakao.com", proxies=proxies, headers=headers)