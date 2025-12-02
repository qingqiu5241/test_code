
import sys
import os
import subprocess
from proxy.utils import build_proxy_param, check_sysproxy, check_tls

file_path = os.path.abspath(os.path.dirname(__file__))

main_proxy_arr = build_proxy_param(sys.argv, 0)
second_proxy_arr = build_proxy_param(sys.argv, 1)
is_sysproxy = check_sysproxy(sys.argv)
is_tls = check_tls(sys.argv)

process_params = ['mitmdump', '-s', file_path + '/proxy/filter.py"',
    '--set', 'upstream_cert=false',
    '--set', 'connection_strategy=lazy',
    '--set', 'anticache=true',
    '--ssl-insecure',
    '-p', '8087',
]
if len(main_proxy_arr) > 0:
    process_params.extend([
        "--mode", f"upstream:http://default-upstream-proxy:8080/",
        "--set", f"{main_proxy_arr[0]}:{main_proxy_arr[1]}:{main_proxy_arr[2]}:{main_proxy_arr[3]}"
    ])
if len(second_proxy_arr) > 0:
    process_params.extend([
        "--set", f"{second_proxy_arr[0]}:{second_proxy_arr[1]}:{second_proxy_arr[2]}:{second_proxy_arr[3]}"
    ])
if is_sysproxy is not None:
    process_params.extend([
        "--set", f"sysproxy={is_sysproxy}"
    ])
if is_tls is not None:
    process_params.extend([
        "--set", f"tls={is_tls}"
    ])
subprocess.run(process_params)

