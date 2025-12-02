import tls_client
import requests
from curl_cffi import requests as cffi_requests


session = tls_client.Session(client_identifier="chrome_124")

proxies = {
    "http":  "http://aaaa:bbbb@127.0.0.1:8866",
    "https": "http://aaaa:bbbb@127.0.0.1:8866",
}

kwargs = {
    "proxies": proxies or {},
    "headers": {
            "Accept": "image/webp,image/apng,image/*,*/*;q=0.8",
            "Accept-Encoding": "gzip, deflate, br",
            "Sec-Fetch-Dest": "image",
            "Sec-Fetch-Mode": "no-cors",
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        },
    "impersonate": "chrome120",
    "verify": False
}

# resp = session.get("https://cdnticket.melon.co.kr/resource/image/upload/product/2025/10/202510141635284f935950-f2fe-4d40-9346-6bfe4c833b91.png/melon/strip/true/quality/50", **kwargs)
resp = cffi_requests.get("https://ip125.com/api/myip", **kwargs)
# resp = requests.get("https://cdnticket.melon.co.kr/resource/image/upload/product/2025/10/202510141635284f935950-f2fe-4d40-9346-6bfe4c833b91.png/melon/strip/true/quality/50")
# print("文件头:", resp.content[:8].hex())

print("xxxxxxxxxxxx", resp.text)
body = resp.content
print("len:", len(body))
print("first 32 bytes:", body[:32])
print("as text snippet:", body[:80].decode("utf-8", errors="ignore"))

with open("debug_tls_client.png", "wb") as f:
    f.write(resp.content)
