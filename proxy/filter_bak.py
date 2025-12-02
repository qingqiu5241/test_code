import base64
import re

import mitmproxy.http
import json
import sys
from urllib.parse import urlparse, parse_qs
from mitmproxy import ctx
from mitmproxy.connection import Server
from mitmproxy.proxy import mode_specs
from mitmproxy.proxy.mode_specs import ProxyMode
from mitmproxy.utils import strutils

cap_create_task = '/createTask'
xbot_token = 'xbotapp.io/token'
nocap_create_task = '/cloudflare/universal'
concert_socket_url = '.firebasedatabase.app'

proxy_arr = []
if len(sys.argv) > 15:
    custom_proxy = sys.argv[15]
    proxy_arr = custom_proxy.split(':')

pattern = r'<script[^>]*>.*?</script>'


class CaptchaProxy:
    def request(self, flow: mitmproxy.http.HTTPFlow):
        if cap_create_task in flow.request.url:
            request_json = json.loads(flow.request.text)
            if 'proxyAddress' in request_json['task'] and (request_json['task']['proxyAddress'] == '127.0.0.1' or request_json['task']['proxyAddress'] == 'localhost'):
                request_json['task']['proxyAddress'] = proxy_arr[0]
                request_json['task']['proxyPort'] = proxy_arr[1]
                request_json['task']['proxyLogin'] = proxy_arr[2]
                request_json['task']['proxyPassword'] = proxy_arr[3]
                request_text = json.dumps(request_json, ensure_ascii=False)
                flow.request.text = request_text
            elif (request_json['task']['type'] == 'ReCaptchaV3EnterpriseTask' or request_json['task']['type'] == 'ReCaptchaV3Task') and 'proxy' in request_json['task'] and ('127.0.0.1' in request_json['task']['proxy'] or 'localhost' in request_json['task']['proxy']):
                request_json['task']['proxy'] = f'{proxy_arr[0]}:{proxy_arr[1]}:{proxy_arr[2]}:{proxy_arr[3]}'
                print('xxxx', request_json['task']['proxy'])
                request_text = json.dumps(request_json, ensure_ascii=False)
                flow.request.text = request_text
            elif request_json['task']['type'] == 'CloudFlareTaskS2' and 'proxy' in request_json['task'] and ('127.0.0.1' in request_json['task']['proxy'] or 'localhost' in request_json['task']['proxy']):
                request_json['task']['proxy'] = f'http://{proxy_arr[2]}:{proxy_arr[3]}@{proxy_arr[0]}:{proxy_arr[1]}'
                request_text = json.dumps(request_json, ensure_ascii=False)
                flow.request.text = request_text
            elif 'proxy' in request_json['task'] and ('127.0.0.1' in request_json['task']['proxy'] or 'localhost' in request_json['task']['proxy']):
                request_json['task']['proxy'] = f'http:{proxy_arr[0]}:{proxy_arr[1]}:{proxy_arr[2]}:{proxy_arr[3]}'
                request_text = json.dumps(request_json, ensure_ascii=False)
                flow.request.text = request_text
        elif xbot_token in flow.request.url:
            request_json = json.loads(flow.request.text)
            if 'proxy' in request_json and ('127.0.0.1' in request_json['proxy'] or 'localhost' in request_json['proxy']):
                request_json['proxy'] = f'http://{proxy_arr[2]}:{proxy_arr[3]}@{proxy_arr[0]}:{proxy_arr[1]}'
                request_text = json.dumps(request_json, ensure_ascii=False)
                flow.request.text = request_text
        elif nocap_create_task in flow.request.url: # 请求不走upstream 直接发送到服务器
            flow.request.scheme = 'http'
            flow.request.host = flow.request.pretty_host
            flow.request.port = 80
            request_json = json.loads(flow.request.text)
            request_json['proxy'] = f'{proxy_arr[2]}:{proxy_arr[3]}@{proxy_arr[0]}:{proxy_arr[1]}'
            request_text = json.dumps(request_json, ensure_ascii=False)
            flow.request.text = request_text
        elif '/cookies?url=' in flow.request.url and ('@127.0.0.1' in flow.request.url or '@localhost' in flow.request.url):
            cur_proxy = flow.request.url.split('&proxy=')[1]
            flow.request.url = flow.request.url.replace(cur_proxy, f'http://{proxy_arr[2]}:{proxy_arr[3]}@{proxy_arr[0]}:{proxy_arr[1]}')
            flow.request.scheme = 'http'
            flow.request.host = flow.request.pretty_host
            flow.request.port = 80
            print('aaaaa', flow.request.url)
        # elif '?evfw=' in flow.request.url:
        #     # 解析URL
        #     parsed_url = urlparse(flow.request.url)
        #     # 提取查询参数
        #     query_params = parse_qs(parsed_url.query)
        #     evfw_value = query_params.get('evfw', [None])[0]
        #     flow.request.url = flow.request.url.replace(evfw_value, 'srfwWkh0mmvyDzO2')
        # elif '/inc/check_user_signin.php' or '/1/zones.php' in flow.request.url:
        #     flow.request.scheme = 'http'
            # flow.request.host = flow.request.pretty_host
            # flow.request.port = 80
        # elif 's.clarity.ms/collect' in flow.request.url:
        #     print('clarity', flow.request.url)
        #     flow.request.stream = True
        # elif 's.clarity.ms/collect' in flow.request.url:
        #     print('clarity', flow.request.url)
        #     flow.request.stream = True

    def response(self, flow: mitmproxy.http.HTTPFlow):
        # new_tmsg_filter.response(flow)
        # new_ttm_filter.response(flow)
        # if '/login/initkeystr.nhn' in flow.request.url:
        #     print('1111111')
        #     flow.response.text = "keystr = '5291f31b93cd403993ef284bbeaf2216,8132a3defca389a4335284bc480cfe36e8bfa927ad6077416d4f1796428ce4e3dc70f606c7abced0248b7a8d91ab1d4d550a7f9dd2c7ac4f80642f28aa5ff90eab473896314ad82de50186d7e58d7729d249b00fe293baacea734ee2e0277ca6a259796a64de46b0105b93a330d50f9dfd5d3938919b44dd44708f33c16577bd,010001';"
        if '/static/js/action-tracer-1.2.0.js' in flow.request.url or '/static/js/action-tracer-1.3.0.js' in flow.request.url:
            flow.response.text = flow.response.text.replace('setInterval(()=>{console.log("%c ",c),r||a()},1e3);', ';')
        elif '/js/tk.pcweb.product.reserve.seat.gradeAndSeat.common.min.js' in flow.request.url:
            flow.response.text = flow.response.text.replace('dfd.resolve(resource, textStatus, jqXHR);', 'debugger;dfd.resolve(resource, textStatus, jqXHR);').replace('alert("시스템에서 비정상적인 활동이 감지되었습니다', 'debugger;alert("시스템에서 비정상적인 활동이 감지되었습니다').replace("var callAjax = $.ajax(defaultOptions);", "debugger;var callAjax = $.ajax(defaultOptions);").replace('alert("오류가 발생했습니다', '//alert("오류가 발생했습니다')
            flow.response.text = "const originalAlert=window.alert;window.alert=function(message){console.log('Alert 被触发，内容：',message);debugger;originalAlert.call(this,message)};window.alert.toString=()=>'function alert() { [native code] }';" + flow.response.text
        elif '?evfw=' in flow.request.url:
            # 该下面一行 是启动js检测的语句，注释掉可以禁用js检测 每天都不一样
            # flow.response.text = flow.response.text.replace('window[__SstyO(__gIGcm[0x32e+0x376-0x504])]();', '//window[__SstyO(__gIGcm[0x32e+0x376-0x504])]();')
            # flow.response.text = flow.response.text.replace('window[__cPirx(__ViEjo[0x295-0x2ba+0x2ba])]();', '//window[__cPirx(__ViEjo[0x295 - 0x2ba + 0x2ba])]();')
            flow.response.text = flow.response.text.replace(",setInterval(__lbexp['__zHaIG'],(648^539)+103);", ";")
            flow.response.text = flow.response.text.replace("__pzOiM['__hQNnY']();setInterval(__pzOiM['__hQNnY'],0x341-0x239+0x2e0);", "")
            # flow.response.text = flow.response.text.replace(",setInterval(__nDgQA['__wnhVd'],191*334-63544);", ';')

            flow.response.text = flow.response.text.replace('.length-1;i>0;', '.length-1;i<-100;')

            # flow.response.text = 'window.oncontextmenu={};Object.defineProperty(window,"oncontextmenu",{set:function(val){debugger;this.oncontextmenu=val},get:function(){return this.oncontextmenu}});' + flow.response.text
            # flow.response.text = "Function=new Proxy(Function,{construct(target,args){if(args.toString().indexOf('debugger')>=0){return{}}return new target(...args)}});" + flow.response.text
            # flow.response.text = flow.response.text.replace("setInterval(__gGeTh['__Achsf'],", "debugger,setInterval(__gGeTh['__Achsf'],")
        elif '/en/reserve/plan/schedule/' in flow.request.url:
            # 使用正则表达式匹配查询字符串中的数字
            pattern = r'/tk.pcweb.product.reserve.seat.gradeAndSeat.common.min\.js\?(\d+)'
            match = re.search(pattern, flow.response.text)
            if match:
                print("提取的数字是：", match.group(1))
                flow.response.text = flow.response.text.replace('.js?'+match.group(1), '.js?1739773547287')
        elif '/captcha/compareCaptcha' in flow.request.url:
            response_json = json.loads('{"flg": "Y", "cardCode": "22", "resultCode": "0000"}')
            response_text = json.dumps(response_json, ensure_ascii=False)
            flow.response.text = response_text



addons = [CaptchaProxy()]
