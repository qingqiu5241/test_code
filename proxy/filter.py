import time

import mitmproxy.http
import json
import sys
import re

from mitmproxy import http
from mitmproxy import ctx
from mitmproxy.connection import Server
from mitmproxy.net.server_spec import ServerSpec
from curl_cffi import requests as cffi_requests

from system_proxy_utils import set_windows_proxy, unset_windows_proxy
from utils import build_proxy_param, check_sysproxy, check_tls, build_tls_request, build_proxies, parse_upstream_auth

tkl_pattern = r'<script[^>]*>.*?</script>'

cap_create_task = '/createTask'
xbot_token = 'xbotapp.io/token'
nocap_create_task = '/cloudflare/universal'
cf_cookie_form = '/cookies_by_form'
concert_socket_url = '.firebasedatabase.app'

print('filter len', len(sys.argv))
main_proxy_arr = build_proxy_param(sys.argv, 0)
second_proxy_arr = build_proxy_param(sys.argv, 1)
is_sysproxy = check_sysproxy(sys.argv)
print("is sys proxy", is_sysproxy)
is_tls = check_tls(sys.argv)
print("is tls", is_tls)

bb = 88


def configure(updated):
    print('updated', updated, 'upstream_auth', ctx.options.upstream_auth)
    if is_sysproxy is not None:
        if is_sysproxy:
            set_windows_proxy("127.0.0.1", 8087)
        else:
            unset_windows_proxy()


def match_proxy(host):
    if len(second_proxy_arr) > 0 and ('.payments.kakao.' in host or '.inicis.' in host):
        return second_proxy_arr
    return main_proxy_arr


def proxy_address(flow: http.HTTPFlow) -> tuple[str, int, str, str]:
    # Poor man's loadbalancing: route every second domain through the alternative proxy.
    proxy_arr = match_proxy(flow.request.host)
    if len(proxy_arr) > 0:
        return (proxy_arr[0], int(proxy_arr[1]), proxy_arr[2], proxy_arr[3])
    return ("", 0, "", "")


def http_connect_upstream(flow: http.HTTPFlow):
    proxy_arr = match_proxy(flow.request.host)
    if len(proxy_arr) > 0:
        flow.request.headers["proxy-authorization"] = parse_upstream_auth(f"{proxy_arr[2]}:{proxy_arr[3]}")



def requestheaders(flow: http.HTTPFlow):
    proxy_arr = match_proxy(flow.request.host)
    if len(proxy_arr) > 0:
        flow.request.headers["proxy-authorization"] = parse_upstream_auth(f"{proxy_arr[2]}:{proxy_arr[3]}")


tls_session = cffi_requests.Session(impersonate="chrome124")
# 禁用 SSL 验证
tls_session.verify = False

def request(flow: mitmproxy.http.HTTPFlow):
    choice_address = proxy_address(flow)
    print(f"{choice_address[0]}:{choice_address[1]}:{choice_address[2]}:{choice_address[3]}", flow.request.url)
    if choice_address[1] != 0:
        address = (choice_address[0], choice_address[1])
        is_proxy_change = address != flow.server_conn.via[1]
        server_connection_already_open = flow.server_conn.timestamp_start is not None
        if is_proxy_change and server_connection_already_open:
            flow.server_conn = Server(address=flow.server_conn.address)
        flow.server_conn.via = ServerSpec(("http", address))

    if cap_create_task in flow.request.url:
        request_json = json.loads(flow.request.text)
        if 'proxyAddress' in request_json['task'] and (request_json['task']['proxyAddress'] == '127.0.0.1' or request_json['task']['proxyAddress'] == 'localhost'):
            request_json['task']['proxyAddress'] = main_proxy_arr[0]
            request_json['task']['proxyPort'] = main_proxy_arr[1]
            request_json['task']['proxyLogin'] = main_proxy_arr[2]
            request_json['task']['proxyPassword'] = main_proxy_arr[3]
            request_text = json.dumps(request_json, ensure_ascii=False)
            flow.request.text = request_text
        elif (request_json['task']['type'] == 'ReCaptchaV3EnterpriseTask' or request_json['task']['type'] == 'ReCaptchaV3Task') and 'proxy' in request_json['task'] and ('127.0.0.1' in request_json['task']['proxy'] or 'localhost' in request_json['task']['proxy']):
            request_json['task']['proxy'] = f'{main_proxy_arr[0]}:{main_proxy_arr[1]}:{main_proxy_arr[2]}:{main_proxy_arr[3]}'
            print('xxxx', request_json['task']['proxy'])
            request_text = json.dumps(request_json, ensure_ascii=False)
            flow.request.text = request_text
        elif request_json['task']['type'] == 'CloudFlareTaskS2' and 'proxy' in request_json['task'] and ('127.0.0.1' in request_json['task']['proxy'] or 'localhost' in request_json['task']['proxy']):
            request_json['task']['proxy'] = f'http://{main_proxy_arr[2]}:{main_proxy_arr[3]}@{main_proxy_arr[0]}:{main_proxy_arr[1]}'
            request_text = json.dumps(request_json, ensure_ascii=False)
            flow.request.text = request_text
        elif 'proxy' in request_json['task'] and ('127.0.0.1' in request_json['task']['proxy'] or 'localhost' in request_json['task']['proxy']) and 'api.ez-captcha.com' in flow.request.url:
            request_json['task']['proxy'] = f'http://{main_proxy_arr[2]}:{main_proxy_arr[3]}@{main_proxy_arr[0]}:{main_proxy_arr[1]}'
            request_text = json.dumps(request_json, ensure_ascii=False)
            flow.request.text = request_text
        elif 'proxy' in request_json['task'] and ('127.0.0.1' in request_json['task']['proxy'] or 'localhost' in request_json['task']['proxy']):
            request_json['task']['proxy'] = f'http:{main_proxy_arr[0]}:{main_proxy_arr[1]}:{main_proxy_arr[2]}:{main_proxy_arr[3]}'
            request_text = json.dumps(request_json, ensure_ascii=False)
            flow.request.text = request_text
    elif xbot_token in flow.request.url or cf_cookie_form in flow.request.url or '/task/submit' in flow.request.url:
        request_json = json.loads(flow.request.text)
        if 'proxy' in request_json and ('127.0.0.1' in request_json['proxy'] or 'localhost' in request_json['proxy']):
            request_json['proxy'] = f'http://{main_proxy_arr[2]}:{main_proxy_arr[3]}@{main_proxy_arr[0]}:{main_proxy_arr[1]}'
            request_text = json.dumps(request_json, ensure_ascii=False)
            flow.request.text = request_text
    elif '/wanda/akamai/v2' in flow.request.url:
        request_json = json.loads(flow.request.text)
        if 'proxy' in request_json and ('127.0.0.1' in request_json['proxy'] or 'localhost' in request_json['proxy']):
            request_json['proxy'] = f'{main_proxy_arr[2]}:{main_proxy_arr[3]}@{main_proxy_arr[0]}:{main_proxy_arr[1]}'
            request_text = json.dumps(request_json, ensure_ascii=False)
            flow.request.text = request_text
    elif nocap_create_task in flow.request.url: # 请求不走upstream 直接发送到服务器
        flow.request.scheme = 'http'
        flow.request.host = flow.request.pretty_host
        flow.request.port = 80
        request_json = json.loads(flow.request.text)
        request_json['proxy'] = f'{main_proxy_arr[2]}:{main_proxy_arr[3]}@{main_proxy_arr[0]}:{main_proxy_arr[1]}'
        request_text = json.dumps(request_json, ensure_ascii=False)
        flow.request.text = request_text
    elif '/cookies?url=' in flow.request.url and ('@127.0.0.1' in flow.request.url or '@localhost' in flow.request.url):
        cur_proxy = flow.request.url.split('&proxy=')[1]
        flow.request.url = flow.request.url.replace(cur_proxy, f'http://{main_proxy_arr[2]}:{main_proxy_arr[3]}@{main_proxy_arr[0]}:{main_proxy_arr[1]}')
        flow.request.scheme = 'http'
        flow.request.host = flow.request.pretty_host
        flow.request.port = 80
        print('aaaaa', flow.request.url)
    elif '/api/melon' in flow.request.url:
        flow.request.url = flow.request.url.replace('127.0.0.1:12306', "image-kr.xbotaio.com")
        print(flow.request.url)
        print(flow.request.headers)
    elif '?evfw=' in flow.request.url and ('sxcwGn0UdzWeauas' in flow.request.url or 'scgIhmxF6P0eek2Y' in flow.request.url):
        flow.request.url = flow.request.url + '&_t=' + str(int(time.time()))
    elif '/payMain/pay' in flow.request.url:
        if flow.request.headers["origin"]:
            flow.request.headers["referer"] = flow.request.headers["origin"] + '/'
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
    # elif ('/en/reserve/plan/schedule/' in flow.request.url and '?evfw=du/' in flow.request.url) or '/seat-soldout/area' in flow.request.url:
    #     flow.request.headers["accept"] = 'application/json, text/javascript, */*; q=0.01'

    if 'https://auth.ticketmaster.com/epsf/asset/iamNotaRobot.js' in flow.request.url:
        flow.request.headers["cookie"] = 'eps_sid=8bc1476b85db223052a6c1385cc5b53f7dde3bbb'
        print('222222222222222 iamNotaRobot.js')
    elif 'https://auth.ticketmaster.com/epsf/asset/abuse-component.js' in flow.request.url:
        flow.request.headers["cookie"] = 'eps_sid=8bc1476b85db223052a6c1385cc5b53f7dde3bbb'
        print('222222222222222 abuse-component.js')
    elif 'https://auth.ticketmaster.com/epsf/asset/nd.js' in flow.request.url:
        flow.request.headers["cookie"] = 'eps_sid=8bc1476b85db223052a6c1385cc5b53f7dde3bbb'
        print('222222222222222 /asset/nd.js')
    elif 'https://auth.ticketmaster.com/eps/log?hasPublicKeyCredential=' in flow.request.url:
        flow.request.headers["cookie"] = 'eps_sid=8bc1476b85db223052a6c1385cc5b53f7dde3bbb'
        print('222222222222222 hasPublicKeyCredential')
    elif 'https://auth.ticketmaster.com/epsf/asset/abuse-component.css' in flow.request.url:
        flow.request.headers["cookie"] = 'eps_sid=8bc1476b85db223052a6c1385cc5b53f7dde3bbb'
        print('222222222222222 abuse-component.css')
    elif 'https://nudata.ticketmaster.com/2.2/w/w-481390/sync/js/' in flow.request.url:
        flow.request.headers["cookie"] = 'eps_sid=8bc1476b85db223052a6c1385cc5b53f7dde3bbb'
        print('222222222222222 /sync/js/')
    elif 'https://nudata.ticketmaster.com/2.2/w/w-481390/init/js/?q=' in flow.request.url:
        flow.request.headers["cookie"] = 'eps_sid=8bc1476b85db223052a6c1385cc5b53f7dde3bbb'
        print('222222222222222 /init/js/?q=')

    # elif 'https://www.googletagmanager.com/gtm.js?' in flow.request.url:
    #     flow.request.url = 'https://www.googletagmanager.com/gtm.js?id=GTM-K4QMLG'

    if is_tls and flow.request.headers.get("upgrade", "").lower() != "websocket":
        build_tls_request(flow, tls_session, build_proxies(choice_address))



pre_evfw_hook_js = ""

pre_evfw_hook_js = pre_evfw_hook_js + """Math.random=function(){return 0.5};"""
# pre_evfw_hook_js = pre_evfw_hook_js + """Date.prototype.getTime=function(){return 1747362096570};"""
# pre_evfw_hook_js = pre_evfw_hook_js + """Date.now=new Proxy(Date.now,{apply:function(target,thisArg,argumentsList){return 1747362096570}});"""
pre_evfw_hook_js = pre_evfw_hook_js + """console.debug=function(){};console.table=function(){};console.clear=function(){};"""
pre_evfw_hook_js = pre_evfw_hook_js + "Function.prototype.constructor=function(){console.log('function constructor',arguments);debugger;const fnBody=arguments[0];if(fnBody.indexOf('debugger')>-1){debugger;return function(){}}return new Function(...arguments)};"
pre_evfw_hook_js = pre_evfw_hook_js + """const originalEval=window.eval;window.eval=function(){console.log('eval args',arguments);debugger;return originalEval.apply(this,arguments)};"""
pre_evfw_hook_js = pre_evfw_hook_js + """const originalSetInterval=window.setInterval;window.setInterval=function(){console.log('setInterval args',arguments);if(arguments[0].toString().includes('debugger')){console.log('检测到恶意定时器，已拦截');return null}return originalSetInterval.apply(this,arguments)};window.setInterval.toString=()=>'function setInterval() { [native code] }';"""
# pre_evfw_hook_js = pre_evfw_hook_js + """const originalAlert=window.alert;window.alert=function(){console.log('Alert 被触发，内容：',arguments);debugger;originalAlert.apply(this,arguments)};"""
pre_evfw_hook_js = pre_evfw_hook_js + """const originalWorker=window.Worker;window.Worker=function(scriptURL,options){console.log('[Hook] 创建 Worker，路径:',scriptURL);const customCode=`const originalFunction=Function;Function=function(){console.log('function constructor',arguments);const fnBody=arguments[0];if(fnBody.indexOf('debugger')>-1){return function(){}}return new originalFunction(...arguments)};`;const blob=new Blob([customCode],{type:'application/javascript'});const newScriptUrl=URL.createObjectURL(blob);return new originalWorker(newScriptUrl,options)};const originalPostMessage=Worker.prototype.postMessage;Worker.prototype.postMessage=function(){console.log('[Hook] 主线程发送消息给 Worker:',arguments);debugger;originalPostMessage.apply(this,arguments)};const originalOnmessage=Object.getOwnPropertyDescriptor(Worker.prototype,'onmessage');Object.defineProperty(Worker.prototype,'onmessage',{set:function(callback){const wrappedCallback=(event)=>{console.log('[Hook] 主线程接收 Worker 的消息:',event.data);debugger;event.data={...event.data,intercepted:true};callback(event)};originalOnmessage.set.call(this,wrappedCallback)},get:function(){return originalOnmessage.get.call(this)}});"""
pre_evfw_hook_js = pre_evfw_hook_js + """var open_=window.XMLHttpRequest.prototype.open;window.XMLHttpRequest.prototype.open=function(method,url,async){if(url.indexOf("/reserve/product/")>-1){debugger}return open_.apply(this,arguments)};"""
# pre_evfw_hook_js = ""
kkk = True

def response(flow: mitmproxy.http.HTTPFlow):
    # new_tmsg_filter.response(flow)
    # new_ttm_filter.response(flow)
    if '/js/ads.js' in flow.request.url:
        flow.response.text = flow.response.text.replace('adblockModal.show();', '')

    elif '/static/js/action-tracer-1.2.0.js' in flow.request.url or '/static/js/action-tracer-1.3.0.js' in flow.request.url:
        flow.response.text = flow.response.text.replace('setInterval(()=>{console.log("%c ",c),r||a()},1e3);', ';')
    elif '/js/tk.pcweb.product.reserve.seat.gradeAndSeat.common.min.js' in flow.request.url:
        flow.response.text = flow.response.text.replace('dfd.resolve(resource, textStatus, jqXHR);', 'debugger;dfd.resolve(resource, textStatus, jqXHR);').replace('alert("시스템에서 비정상적인 활동이 감지되었습니다', 'debugger;alert("시스템에서 비정상적인 활동이 감지되었습니다').replace("var callAjax = $.ajax(defaultOptions);", "debugger;var callAjax = $.ajax(defaultOptions);")
        flow.response.text = "const originalAlert=window.alert;window.alert=function(message){console.log('Alert 被触发，内容：',message);debugger;originalAlert.call(this,message)};window.alert.toString=()=>'function alert() { [native code] }';" + flow.response.text
    elif '?evfw=' in flow.request.url and ('sxcwGn0UdzWeauas' in flow.request.url or 'scgIhmxF6P0eek2Y' in flow.request.url):
        # 该下面一行 是启动js检测的语句，注释掉可以禁用js检测 每天都不一样
        # flow.response.text = flow.response.text.replace('window[__SstyO(__gIGcm[0x32e+0x376-0x504])]();', '//window[__SstyO(__gIGcm[0x32e+0x376-0x504])]();')
        # flow.response.text = flow.response.text.replace('window[__cPirx(__ViEjo[0x295-0x2ba+0x2ba])]();', '//window[__cPirx(__ViEjo[0x295 - 0x2ba + 0x2ba])]();')
        # flow.response.text = flow.response.text.replace(",setInterval(__lbexp['__zHaIG'],(648^539)+103);", ";")
        # flow.response.text = flow.response.text.replace("__pzOiM['__hQNnY']();setInterval(__pzOiM['__hQNnY'],0x341-0x239+0x2e0);", "")

        flow.response.text = pre_evfw_hook_js + flow.response.text
        flow.response.text = flow.response.text.replace(",setInterval(__GQStg['__hOWNi'],88-319+481);", ";")
        flow.response.text = flow.response.text.replace("__bbSUd['__dsvBW']();setInterval(__bbSUd['__dsvBW'],0x1e4-0x21f+0x423);", "")
        flow.response.text = flow.response.text.replace("__KRZvm['__QwKuU']();setInterval(__KRZvm['__QwKuU'],0x1a2*0xc6-0x13f64);", "")
        if "__fusto['__IJfXn'][__Sleau(__xDlyv[475*14-6419])](__zoNlo['__aVpOl']);" in flow.response.text:
            flow.response.text = flow.response.text.replace("__fusto['__IJfXn'][__Sleau(__xDlyv[475*14-6419])](__zoNlo['__aVpOl']);", "")
            print("KKKKKKKKKKKKKK111")
        # flow.response.text = flow.response.text.replace("setInterval(_", "//setInterval(_")
        # flow.response.text = flow.response.text.replace(",setInterval(__nDgQA['__wnhVd'],191*334-63544);", ';')

        flow.response.text = flow.response.text.replace('.length-1;i>0;', '.length-1;i<-100;')

        # flow.response.text = 'window.oncontextmenu={};Object.defineProperty(window,"oncontextmenu",{set:function(val){debugger;this.oncontextmenu=val},get:function(){return this.oncontextmenu}});' + flow.response.text
        # flow.response.text = "Function=new Proxy(Function,{construct(target,args){if(args.toString().indexOf('debugger')>=0){return{}}return new target(...args)}});" + flow.response.text
        # flow.response.text = flow.response.text.replace("setInterval(__gGeTh['__Achsf'],", "debugger,setInterval(__gGeTh['__Achsf'],")

        # 新混淆模板



    elif '/frontend/ticketlink/latest/main-DO7oAK-q@2.7.4.js' in flow.request.url or '/frontend/ticketlink/latest/main-BWwyBkQD@2.10.0.js' in flow.request.url:
        flow.response.text = pre_evfw_hook_js + flow.response.text
    elif '/en/reserve/plan/schedule/' in flow.request.url:
        # 使用正则表达式匹配查询字符串中的数字
        tkl_pattern = r'/tk.pcweb.product.reserve.seat.gradeAndSeat.common.min\.js\?(\d+)'
        match = re.search(tkl_pattern, flow.response.text)
        if match:
            flow.response.text = flow.response.text.replace('.js?'+match.group(1), '.js?1739773547287')

    elif '/base_info' in flow.request.url:
        flow.response.text = flow.response.text.replace('"captcha_type":0,', '"captcha_type":3,')

    # elif '/captcha/compareCaptcha' in flow.request.url:
    #     response_json = json.loads('{"flg": "Y", "cardCode": "22", "resultCode": "0000"}')
    #     response_text = json.dumps(response_json, ensure_ascii=False)
    #     flow.response.text = response_text
    # elif '/grades?productClassCode=' in flow.request.url:
    #     request_json = json.loads(flow.response.text)
    #     for x in request_json['data']:
    #         x["remainCnt"]= 99
    #     request_text = json.dumps(request_json, ensure_ascii=False)
    #     flow.response.text = request_text
    # if ('/en/reserve/plan/schedule/' in flow.request.url and '?evfw=du/' in flow.request.url) or '/seat-soldout/area' in flow.request.url:
    #     request_json = json.loads(flow.response.text)
    #     if isinstance(request_json.get("data"), dict):
    #         data_dict = request_json.get("data")
    #         for x in data_dict:
    #             # if x == "1612168350":
    #             data_dict[x] = False
    #         request_text = json.dumps(request_json, ensure_ascii=False)
    #         flow.response.text = request_text
    # elif '/Book/BookConfirm.asp' in flow.request.url:
    #     flow.response.text = flow.response.text.replace("$(function ()", "window.onload = function ()").replace("})", "}").replace("if ($(\"#CancelAgree\").is(':checked') && $('#CancelAgree2').is(':checked') ){", "if (1==1) {")
    #     flow.response.text = flow.response.text.replace("parent.fnSetNextImage(\"P\");", "parent.fnSetNextImage(\"P\");debugger;")
    #     flow.response.text = flow.response.text.replace("if (!$(\"#CancelAgree\").is(':checked') || !$(\"#CancelAgree2\").is(':checked')) {", "if (2==1) {").replace("var objForm = $(\"#formConfirm\");", "//var objForm = $(\"#formConfirm\");")


def websocket_message(flow: mitmproxy.http.HTTPFlow):
    msg = flow.websocket.messages[-1]
    print("WS:", msg.content)
    # # 修改
    # msg.content = msg.content.replace(b"ping", b"pong")