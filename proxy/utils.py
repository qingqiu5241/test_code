import re
import base64
import random
from pathlib import Path
from curl_cffi import requests as cffi_requests

import mitmproxy
from mitmproxy import http
from mitmproxy import exceptions
from mitmproxy.utils import strutils


def mkdir_path(file_path):
    proxy_path = Path(file_path)
    # 判断文件是否存在，不存在则创建
    if not proxy_path.exists():
        proxy_path.touch()  # 创建空文件
    return proxy_path

def build_proxy(proxy_path):
    proxy_list = []
    with open(proxy_path, "r", encoding="utf-8") as f:
        for line in f:
            # print(line.strip())  # 去除换行符
            proxy_list.append(line.strip())
    return proxy_list


def match_proxy_args(argv):
    matches = [x for x in argv if (len(x.split(':')) == 4 and 'upstream:' not in x) or '.txt' in x]
    return matches


def build_proxy_param(argv, size):
    proxy_argv = match_proxy_args(argv)
    proxy_list = []
    proxy_arr = []
    if len(proxy_argv) > size:
        param_proxy = proxy_argv[size]
        if '.txt' in param_proxy:
            proxy_list.extend(build_proxy(mkdir_path(param_proxy)))
        else:
            proxy_list.append(param_proxy)
        custom_proxy = random.choice(proxy_list)
        if size == 0:
            print("main proxy: " + custom_proxy)
        else:
            print("secondary proxy: " + custom_proxy)
        proxy_arr = custom_proxy.split(':')
    return proxy_arr


def check_sysproxy(argv):
    result = next((x for x in argv if "sysproxy=" in x), None)
    if result is not None:
        return result.lower().replace("sysproxy=", "") == "true"
    return result


def check_tls(argv):
    result = next((x for x in argv if "tls=" in x), None)
    if result is not None:
        return result.lower().replace("tls=", "") == "true"
    return result


def parse_upstream_auth(auth: str) -> bytes:
    pattern = re.compile(".+:")
    if pattern.search(auth) is None:
        raise exceptions.OptionsError("Invalid upstream auth specification: %s" % auth)
    return b"Basic" + b" " + base64.b64encode(strutils.always_bytes(auth))



def build_proxies(proxy: tuple[str, int, str, str]) -> dict[str, str]:
    return {
        "http": f"http://{proxy[2]}:{proxy[3]}@{proxy[0]}:{proxy[1]}",
        "https": f"http://{proxy[2]}:{proxy[3]}@{proxy[0]}:{proxy[1]}",
    }


def build_tls_request(flow: mitmproxy.http.HTTPFlow, session: cffi_requests.session.Session, proxies):
    # 提取原始请求信息
    url = flow.request.url
    headers = dict(flow.request.headers)
    body = flow.request.raw_content  # bytes

    # 一些头可以考虑清理掉由 tls-client / 服务器重新生成
    # 防止某些代理或服务器因为这些头出问题
    headers.pop("Proxy-Connection", None)

    try:
        # 用 curl_cffi 代替 mitmproxy 出网, tls-client库在访问图片时有bug会导致图片显示异常
        # 注意：timeout 可以根据需求调整
        resp = session.request(
            method=flow.request.method,
            url=url,
            headers=flow.request.headers,
            proxies=proxies,
            data=body if body else None,
            timeout=40,
        )
    except Exception as e:
        flow.response = mitmproxy.http.Response.make(
            502,
            b"Upstream tls-client error",
            {"Content-Type": "text/plain"},
        )
        return

    # 将 curl_cffi 的响应写回 mitmproxy 的 flow
    # 注意：这里用 resp.content（bytes），而不是 resp.text
    resp_headers = []
    for k, v in resp.headers.items():
        # 统一把 key 变成 str 再 encode
        if str(k).lower() == "content-length":
            continue

        k_bytes = str(k).encode("latin-1", "ignore")

        if isinstance(v, list):
            values = v
        else:
            values = [v]

        for item in values:
            v_bytes = str(item).encode("latin-1", "ignore")
            resp_headers.append((k_bytes, v_bytes))

    flow.response = mitmproxy.http.Response.make(
        resp.status_code,
        resp.content,
        resp_headers,
    )