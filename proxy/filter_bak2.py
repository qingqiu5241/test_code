import base64
import time

import mitmproxy.http
import json
import sys
import re
from mitmproxy import http
from mitmproxy import ctx
from mitmproxy import exceptions
from mitmproxy.utils import strutils
from mitmproxy.connection import Server
from mitmproxy.net.server_spec import ServerSpec

from system_proxy_utils import set_windows_proxy, unset_windows_proxy
from utils import build_proxy_param, check_sysproxy

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



def parse_upstream_auth(auth: str) -> bytes:
    pattern = re.compile(".+:")
    if pattern.search(auth) is None:
        raise exceptions.OptionsError("Invalid upstream auth specification: %s" % auth)
    return b"Basic" + b" " + base64.b64encode(strutils.always_bytes(auth))


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



def request(flow: mitmproxy.http.HTTPFlow):
    print(flow.request.url)
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
        elif 'proxy' in request_json['task'] and ('127.0.0.1' in request_json['task']['proxy'] or 'localhost' in request_json['task']['proxy']):
            request_json['task']['proxy'] = f'http:{main_proxy_arr[0]}:{main_proxy_arr[1]}:{main_proxy_arr[2]}:{main_proxy_arr[3]}'
            request_text = json.dumps(request_json, ensure_ascii=False)
            flow.request.text = request_text
    elif xbot_token in flow.request.url or cf_cookie_form in flow.request.url:
        request_json = json.loads(flow.request.text)
        if 'proxy' in request_json and ('127.0.0.1' in request_json['proxy'] or 'localhost' in request_json['proxy']):
            request_json['proxy'] = f'http://{main_proxy_arr[2]}:{main_proxy_arr[3]}@{main_proxy_arr[0]}:{main_proxy_arr[1]}'
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
    elif '?evfw=' in flow.request.url and ('sBzOiJWkG9txZIPW' in flow.request.url or 'sBzOiJWkG9txZIPW' in flow.request.url):
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
    elif ('/en/reserve/plan/schedule/' in flow.request.url and '?evfw=du/' in flow.request.url) or '/seat-soldout/area' in flow.request.url:
        flow.request.headers["accept"] = 'application/json, text/javascript, */*; q=0.01'



# pre_evfw_hook_js = "Function.prototype.constructor=function(){console.log('function constructor',arguments);debugger;const fnBody=arguments[0];if(fnBody.indexOf('debugger')>-1){debugger;return function(){}}return new Function(...arguments)};const originalEval=window.eval;window.eval=function(){console.log('eval args',arguments);debugger;return originalEval.apply(this,arguments)};const originalSetInterval=window.setInterval;window.setInterval=function(){console.log('setInterval args',arguments);if(arguments[0].toString().includes('debugger')){console.log('检测到恶意定时器，已拦截');return null}return originalSetInterval.apply(this,arguments)};window.setInterval.toString=()=>'function setInterval() { [native code] }';const originalAlert=window.alert;window.alert=function(message){console.log('Alert 被触发，内容：',message);debugger;originalAlert.call(this,message)};window.alert.toString=()=>'function alert() { [native code] }';const OriginalWorker=window.Worker;window.Worker=class HookedWorker extends OriginalWorker{constructor(scriptURL,options){console.log('[Hook] 创建 Worker，路径:',scriptURL);debugger;fetch(scriptURL).then(res=>res.text()).then(script=>{const hijackedScript=`Function.prototype.constructor=function(){console.log('function constructor',arguments);debugger;const fnBody=arguments[0];if(fnBody.indexOf('debugger')>-1){debugger;return function(){}}return new Function(...arguments)}${script}`;const blob=new Blob([hijackedScript],{type:'application/javascript'});super(URL.createObjectURL(blob),options)})}};const originalPostMessage=Worker.prototype.postMessage;Worker.prototype.postMessage=function(){console.log('[Hook] 主线程发送消息给 Worker:',arguments);debugger;originalPostMessage.apply(this,arguments)};const originalOnmessage=Object.getOwnPropertyDescriptor(Worker.prototype,'onmessage');Object.defineProperty(Worker.prototype,'onmessage',{set:function(callback){const wrappedCallback=(event)=>{console.log('[Hook] 主线程接收 Worker 的消息:',event.data);debugger;event.data={...event.data,intercepted:true};callback(event)};originalOnmessage.set.call(this,wrappedCallback)},get:function(){return originalOnmessage.get.call(this)}});"
pre_evfw_hook_js = ""
# pre_evfw_hook_js = """Date.now=new Proxy(Date.now,{apply:function(target,thisArg,argumentsList){return 1747362096570}});Date.prototype.getTime=function(){return 1747362096570};Math.random=function(){return 0.5};"""
# pre_evfw_hook_js = """Date.prototype.getTime=function(){return 1747362096570};Math.random=function(){return 0.5};Object.defineProperty(window,"lGM2M0Ry2t0rage",{get:function(){debugger;return function(){}},set:function(){debugger},enumerable:false,configurable:true});"""
# pre_evfw_hook_js = """Date.prototype.getTime=function(){return 1747362096570};Math.random=function(){return 0.5};"""
pre_evfw_hook_js = """Math.random=function(){return 0.5};"""
# pre_evfw_hook_js = pre_evfw_hook_js + """console.log=function(){};console.debug=function(){};console.table=function(){};console.clear=function(){};const originalEval=window.eval;window.eval=function(){console.log('eval args',arguments);debugger;return originalEval.apply(this,arguments)};const originalSetInterval=window.setInterval;window.setInterval=function(){console.log('setInterval args',arguments);if(arguments[0].toString().includes('debugger')){console.log('检测到恶意定时器，已拦截');return null}return originalSetInterval.apply(this,arguments)};window.setInterval.toString=()=>'function setInterval() { [native code] }';const originalAlert=window.alert;window.alert=function(message){console.log('Alert 被触发，内容：',message);debugger;originalAlert.call(this,message)};window.alert.toString=()=>'function alert() { [native code] }';const originalWorker=window.Worker;window.Worker=function(scriptURL,options){console.log('[Hook] 创建 Worker，路径:',scriptURL);const customCode=`const originalFunction=Function;Function=function(){console.log('function constructor',arguments);const fnBody=arguments[0];if(fnBody.indexOf('debugger')>-1){return function(){}}return new originalFunction(...arguments)};function __hKKM_(__wyLV_){return decodeURIComponent(escape(atob(__wyLV_)))}__hKKM_("dXNlIHN0cmljdA==");onmessage=__WKgm_=>{var __olBY_={__DhVz_:{},__BCry_:{}};if(__WKgm_[__hKKM_("ZGF0YQ==")]&&__WKgm_[__hKKM_("ZGF0YQ==")][__hKKM_("dQ==")]){URL[__hKKM_("cmV2b2tlT2JqZWN0VVJM")](__WKgm_[__hKKM_("ZGF0YQ==")][__hKKM_("dQ==")]),this[__hKKM_("Y2xvc2U=")]();return};__olBY_["__DhVz_"]=Date[__hKKM_("bm93")]();postMessage({iob:!!!!!!!![],id:__olBY_["__DhVz_"]});new Function(__hKKM_("ZGVi")+__hKKM_("dWdnZXI="))();for(__olBY_["__BCry_"]=(855^613)-306;__olBY_["__BCry_"]<__WKgm_[__hKKM_("ZGF0YQ==")][__hKKM_("bW9yZURlYnVncw==")];__olBY_["__BCry_"]++){new Function(__hKKM_("ZGU=")+__hKKM_("YnU=")+__hKKM_("Z2dlcg=="))()}postMessage({iob:!!!!!!!!![],id:__olBY_["__DhVz_"]})};`;const blob=new Blob([customCode],{type:'application/javascript'});const newScriptUrl=URL.createObjectURL(blob);return new originalWorker(newScriptUrl,options)};const originalPostMessage=Worker.prototype.postMessage;Worker.prototype.postMessage=function(){console.log('[Hook] 主线程发送消息给 Worker:',arguments);debugger;originalPostMessage.apply(this,arguments)};const originalOnmessage=Object.getOwnPropertyDescriptor(Worker.prototype,'onmessage');Object.defineProperty(Worker.prototype,'onmessage',{set:function(callback){const wrappedCallback=(event)=>{console.log('[Hook] 主线程接收 Worker 的消息:',event.data);debugger;event.data={...event.data,intercepted:true};callback(event)};originalOnmessage.set.call(this,wrappedCallback)},get:function(){return originalOnmessage.get.call(this)}});"""
pre_evfw_hook_js = pre_evfw_hook_js + """console.debug=function(){};console.table=function(){};console.clear=function(){};const originalEval=window.eval;window.eval=function(){console.log('eval args',arguments);debugger;return originalEval.apply(this,arguments)};const originalSetInterval=window.setInterval;window.setInterval=function(){console.log('setInterval args',arguments);if(arguments[0].toString().includes('debugger')){console.log('检测到恶意定时器，已拦截');return null}return originalSetInterval.apply(this,arguments)};window.setInterval.toString=()=>'function setInterval() { [native code] }';const originalAlert=window.alert;window.alert=function(message){console.log('Alert 被触发，内容：',message);debugger;originalAlert.call(this,message)};window.alert.toString=()=>'function alert() { [native code] }';const originalWorker=window.Worker;window.Worker=function(scriptURL,options){console.log('[Hook] 创建 Worker，路径:',scriptURL);const customCode=`const originalFunction=Function;Function=function(){console.log('function constructor',arguments);const fnBody=arguments[0];if(fnBody.indexOf('debugger')>-1){return function(){}}return new originalFunction(...arguments)};function __hKKM_(__wyLV_){return decodeURIComponent(escape(atob(__wyLV_)))}__hKKM_("dXNlIHN0cmljdA==");onmessage=__WKgm_=>{var __olBY_={__DhVz_:{},__BCry_:{}};if(__WKgm_[__hKKM_("ZGF0YQ==")]&&__WKgm_[__hKKM_("ZGF0YQ==")][__hKKM_("dQ==")]){URL[__hKKM_("cmV2b2tlT2JqZWN0VVJM")](__WKgm_[__hKKM_("ZGF0YQ==")][__hKKM_("dQ==")]),this[__hKKM_("Y2xvc2U=")]();return};__olBY_["__DhVz_"]=Date[__hKKM_("bm93")]();postMessage({iob:!!!!!!!![],id:__olBY_["__DhVz_"]});new Function(__hKKM_("ZGVi")+__hKKM_("dWdnZXI="))();for(__olBY_["__BCry_"]=(855^613)-306;__olBY_["__BCry_"]<__WKgm_[__hKKM_("ZGF0YQ==")][__hKKM_("bW9yZURlYnVncw==")];__olBY_["__BCry_"]++){new Function(__hKKM_("ZGU=")+__hKKM_("YnU=")+__hKKM_("Z2dlcg=="))()}postMessage({iob:!!!!!!!!![],id:__olBY_["__DhVz_"]})};`;const blob=new Blob([customCode],{type:'application/javascript'});const newScriptUrl=URL.createObjectURL(blob);return new originalWorker(newScriptUrl,options)};const originalPostMessage=Worker.prototype.postMessage;Worker.prototype.postMessage=function(){console.log('[Hook] 主线程发送消息给 Worker:',arguments);debugger;originalPostMessage.apply(this,arguments)};const originalOnmessage=Object.getOwnPropertyDescriptor(Worker.prototype,'onmessage');Object.defineProperty(Worker.prototype,'onmessage',{set:function(callback){const wrappedCallback=(event)=>{console.log('[Hook] 主线程接收 Worker 的消息:',event.data);debugger;event.data={...event.data,intercepted:true};callback(event)};originalOnmessage.set.call(this,wrappedCallback)},get:function(){return originalOnmessage.get.call(this)}});"""

kkk = True

def response(flow: mitmproxy.http.HTTPFlow):
    # new_tmsg_filter.response(flow)
    # new_ttm_filter.response(flow)
    # if '/login/initkeystr.nhn' in flow.request.url:
    #     print('1111111')
    #     flow.response.text = "keystr = '5291f31b93cd403993ef284bbeaf2216,8132a3defca389a4335284bc480cfe36e8bfa927ad6077416d4f1796428ce4e3dc70f606c7abced0248b7a8d91ab1d4d550a7f9dd2c7ac4f80642f28aa5ff90eab473896314ad82de50186d7e58d7729d249b00fe293baacea734ee2e0277ca6a259796a64de46b0105b93a330d50f9dfd5d3938919b44dd44708f33c16577bd,010001';"

    if '/js/ads.js' in flow.request.url:
        flow.response.text = flow.response.text.replace('adblockModal.show();', '')
    elif '/static/js/action-tracer-1.2.0.js' in flow.request.url or '/static/js/action-tracer-1.3.0.js' in flow.request.url:
        flow.response.text = flow.response.text.replace('setInterval(()=>{console.log("%c ",c),r||a()},1e3);', ';')
    elif '/js/tk.pcweb.product.reserve.seat.gradeAndSeat.common.min.js' in flow.request.url:
        flow.response.text = flow.response.text.replace('dfd.resolve(resource, textStatus, jqXHR);', 'debugger;dfd.resolve(resource, textStatus, jqXHR);').replace('alert("시스템에서 비정상적인 활동이 감지되었습니다', 'debugger;alert("시스템에서 비정상적인 활동이 감지되었습니다').replace("var callAjax = $.ajax(defaultOptions);", "debugger;var callAjax = $.ajax(defaultOptions);").replace('alert("오류가 발생했습니다', '//alert("오류가 발생했습니다')
        # flow.response.text = "const originalAlert=window.alert;window.alert=function(message){console.log('Alert 被触发，内容：',message);debugger;originalAlert.call(this,message)};window.alert.toString=()=>'function alert() { [native code] }';" + flow.response.text
    # elif '?evfw=' in flow.request.url and ('sBzOiJWkG9txZIPW' in flow.request.url or 'sBzOiJWkG9txZIPW' in flow.request.url):
    #     # 该下面一行 是启动js检测的语句，注释掉可以禁用js检测 每天都不一样
    #     # flow.response.text = flow.response.text.replace('window[__SstyO(__gIGcm[0x32e+0x376-0x504])]();', '//window[__SstyO(__gIGcm[0x32e+0x376-0x504])]();')
    #     # flow.response.text = flow.response.text.replace('window[__cPirx(__ViEjo[0x295-0x2ba+0x2ba])]();', '//window[__cPirx(__ViEjo[0x295 - 0x2ba + 0x2ba])]();')
    #     # flow.response.text = flow.response.text.replace(",setInterval(__lbexp['__zHaIG'],(648^539)+103);", ";")
    #     # flow.response.text = flow.response.text.replace("__pzOiM['__hQNnY']();setInterval(__pzOiM['__hQNnY'],0x341-0x239+0x2e0);", "")
    #
    #     flow.response.text = pre_evfw_hook_js + flow.response.text
    #     flow.response.text = flow.response.text.replace(",setInterval(__fusto['__Gjios'],241%636+9);", ";")
    #     flow.response.text = flow.response.text.replace("__dwQxF['__ctWwv']();setInterval(__dwQxF['__ctWwv'],0x2f9%0x10b+0x305);", "")
    #     if "__fusto['__IJfXn'][__Sleau(__xDlyv[475*14-6419])](__zoNlo['__aVpOl']);" in flow.response.text:
    #         flow.response.text = flow.response.text.replace("__fusto['__IJfXn'][__Sleau(__xDlyv[475*14-6419])](__zoNlo['__aVpOl']);", "")
    #         print("KKKKKKKKKKKKKK111")
    #     # flow.response.text = flow.response.text.replace("setInterval(_", "//setInterval(_")
    #     # flow.response.text = flow.response.text.replace(",setInterval(__nDgQA['__wnhVd'],191*334-63544);", ';')
    #
    #     flow.response.text = flow.response.text.replace('.length-1;i>0;', '.length-1;i<-100;')
    #
    #     # flow.response.text = 'window.oncontextmenu={};Object.defineProperty(window,"oncontextmenu",{set:function(val){debugger;this.oncontextmenu=val},get:function(){return this.oncontextmenu}});' + flow.response.text
    #     # flow.response.text = "Function=new Proxy(Function,{construct(target,args){if(args.toString().indexOf('debugger')>=0){return{}}return new target(...args)}});" + flow.response.text
    #     # flow.response.text = flow.response.text.replace("setInterval(__gGeTh['__Achsf'],", "debugger,setInterval(__gGeTh['__Achsf'],")
    # elif '/en/reserve/plan/schedule/' in flow.request.url:
    #     # 使用正则表达式匹配查询字符串中的数字
    #     tkl_pattern = r'/tk.pcweb.product.reserve.seat.gradeAndSeat.common.min\.js\?(\d+)'
    #     match = re.search(tkl_pattern, flow.response.text)
    #     if match:
    #         print("提取的数字是：", match.group(1))
    #         flow.response.text = flow.response.text.replace('.js?'+match.group(1), '.js?1739773547287')
    # elif '/captcha/compareCaptcha' in flow.request.url:
    #     response_json = json.loads('{"flg": "Y", "cardCode": "22", "resultCode": "0000"}')
    #     response_text = json.dumps(response_json, ensure_ascii=False)
    #     flow.response.text = response_text
    elif '/grades?productClassCode=' in flow.request.url:
        request_json = json.loads(flow.response.text)
        for x in request_json['data']:
            x["remainCnt"]= 99
        request_text = json.dumps(request_json, ensure_ascii=False)
        flow.response.text = request_text
    # if ('/en/reserve/plan/schedule/' in flow.request.url and '?evfw=du/' in flow.request.url) or '/seat-soldout/area' in flow.request.url:
    #     request_json = json.loads(flow.response.text)
    #     if isinstance(request_json.get("data"), dict):
    #         data_dict = request_json.get("data")
    #         for x in data_dict:
    #             # if x == "1612168350":
    #             data_dict[x] = False
    #         request_text = json.dumps(request_json, ensure_ascii=False)
    #         flow.response.text = request_text
    # elif '/schedule/1152609829?evfw=du/' in flow.request.url:
    #     global kkk
    #     if kkk:
    #         print('lock seat response:', flow.response.text)
    #         flow.response.text = '{"result":{"code":9998,"message":"좌석 선점에 실패했습니다.","errorMessage":"좌석 선점에 실패했습니다."},"success":false}'
    #         kkk = False

