import base64
import urllib.parse
import yaml
import json
import requests
import re
import ssl
ssl._create_default_https_context = ssl._create_unverified_context
import warnings
# 禁止所有警告信息
warnings.filterwarnings('ignore')
from requests_html import HTMLSession

headers = {
    'Accept-Charset': 'utf-8',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
    'Accept-Encoding': 'gzip, deflate, br',
    'DNT': '1',
    'Connection': 'keep-alive',
    'Upgrade-Insecure-Requests': '1'
}

# Clash 配置文件的基础结构
clash_config_template = {
    "port": 7890,
    "socks-port": 7891,
    "redir-port": 7892,
    "allow-lan": True,
    "mode": "Rule",
    "log-level": "info",
    "external-controller": "127.0.0.1:9090",
    "proxies": [],
    "proxy-groups": [
        {
            "name": "自动选择",
            "type": "url-test",
            "proxies": [],
            "url": "http://www.gstatic.com/generate_204",
            "interval": 300
        }
    ],
    "rules": [
        "DOMAIN-SUFFIX,google.com,DIRECT",
        "DOMAIN-KEYWORD,ad,DIRECT",
        "GEOIP,CN,DIRECT",
        "MATCH,自动选择"
    ]
}

# 解析 Hysteria2 链接
def parse_hysteria2_link(link):
    link = link[14:]
    parts = link.split('@')
    uuid = parts[0]
    server_info = parts[1].split('?')
    server = server_info[0].split(':')[0]
    port = int(server_info[0].split(':')[1].split('/')[0].strip())
    query_params = urllib.parse.parse_qs(server_info[1] if len(server_info) > 1 else '')
    insecure = '1' in query_params.get('insecure', ['0'])
    sni = query_params.get('sni', [''])[0]
    name = urllib.parse.unquote(link.split('#')[-1].strip())

    return {
        "name": f"🇺🇸 {name}",
        "server": server,
        "port": port,
        "type": "hysteria2",
        "password": uuid,
        "auth": uuid,
        "sni": sni,
        "skip-cert-verify": not insecure,
        "client-fingerprint": "chrome"
    }

# 解析 Shadowsocks 链接
def parse_ss_link(link):
    link = link[5:]
    if "#" in link:
        config_part, name = link.split('#')
    else:
        config_part, name = link, ""
    decoded = base64.urlsafe_b64decode(config_part.split('@')[0] + '=' * (-len(config_part.split('@')[0]) % 4)).decode('utf-8')
    method_passwd = decoded.split(':')
    cipher, password = method_passwd if len(method_passwd) == 2 else (method_passwd[0], "")
    server_info = config_part.split('@')[1]
    server, port = server_info.split(':') if ":" in server_info else (server_info, "")

    return {
        "name": urllib.parse.unquote(name),
        "type": "ss",
        "server": server,
        "port": int(port),
        "cipher": cipher,
        "password": password,
        "udp": True
    }

# 解析 Trojan 链接
def parse_trojan_link(link):
    link = link[9:]
    config_part, name = link.split('#')
    user_info, host_info = config_part.split('@')
    username, password = user_info.split(':') if ":" in user_info else ("", user_info)
    host, port_and_query = host_info.split(':') if ":" in host_info else (host_info, "")
    port, query = port_and_query.split('?', 1) if '?' in port_and_query else (port_and_query, "")

    return {
        "name": urllib.parse.unquote(name),
        "type": "trojan",
        "server": host,
        "port": int(port),
        "password": password,
        "sni": urllib.parse.parse_qs(query).get("sni", [""])[0],
        "skip-cert-verify": urllib.parse.parse_qs(query).get("skip-cert-verify", ["false"])[0] == "true"
    }

# 解析 VLESS 链接
def parse_vless_link(link):
    link = link[8:]
    config_part, name = link.split('#')
    user_info, host_info = config_part.split('@')
    uuid = user_info
    host, query = host_info.split('?', 1) if '?' in host_info else (host_info, "")
    port = host.split(':')[-1] if ':' in host else ""
    host = host.split(':')[0] if ':' in host else ""

    return {
        "name": urllib.parse.unquote(name),
        "type": "vless",
        "server": host,
        "port": int(port),
        "uuid": uuid,
        "security": urllib.parse.parse_qs(query).get("security", ["none"])[0],
        "tls": urllib.parse.parse_qs(query).get("security", ["none"])[0] == "tls",
        "sni": urllib.parse.parse_qs(query).get("sni", [""])[0],
        "skip-cert-verify": urllib.parse.parse_qs(query).get("skip-cert-verify", ["false"])[0] == "true",
        "network": urllib.parse.parse_qs(query).get("type", ["tcp"])[0],
        "ws-opts": {
            "path": urllib.parse.parse_qs(query).get("path", [""])[0],
            "headers": {
                "Host": urllib.parse.parse_qs(query).get("host", [""])[0]
            }
        } if urllib.parse.parse_qs(query).get("type", ["tcp"])[0] == "ws" else {}
    }

# 解析 VMESS 链接
def parse_vmess_link(link):
    link = link[8:]
    decoded_link = base64.urlsafe_b64decode(link + '=' * (-len(link) % 4)).decode("utf-8")
    vmess_info = json.loads(decoded_link)

    return {
        "name": urllib.parse.unquote(vmess_info.get("ps", "vmess")),
        "type": "vmess",
        "server": vmess_info["add"],
        "port": int(vmess_info["port"]),
        "uuid": vmess_info["id"],
        "alterId": int(vmess_info.get("aid", 0)),
        "cipher": "auto",
        "network": vmess_info.get("net", "tcp"),
        "tls": vmess_info.get("tls", "") == "tls",
        "sni": vmess_info.get("sni", ""),
        "ws-opts": {
            "path": vmess_info.get("path", ""),
            "headers": {
                "Host": vmess_info.get("host", "")
            }
        } if vmess_info.get("net", "tcp") == "ws" else {}
    }

def js_render(url):
    # 获取js渲染页面源代码
    timeout = 4
    if timeout > 15:
        timeout = 15
    browser_args = ['--no-sandbox', '--disable-dev-shm-usage', '--disable-gpu', '--disable-software-rasterizer','--disable-setuid-sandbox']
    session = HTMLSession(browser_args=browser_args)
    r = session.get(f'{url}', headers=headers, timeout=timeout, verify=False)
    # 等待页面加载完成，Requests-HTML 会自动等待 JavaScript 执行完成
    r.html.render(timeout=timeout)
    return r

def match_nodes(text):
    # 正则表达式匹配proxies下的所有代理节点
    # proxy_pattern = r"\{[^}]*name\s*:\s*'[^']+'[^}]*server\s*:\s*[^,]+[^}]*\}"
    proxy_pattern = r"\{[^}]*name\s*:\s*['\"][^'\"]+['\"][^}]*server\s*:\s*[^,]+[^}]*\}"
    nodes = re.findall(proxy_pattern, text, re.DOTALL)

    # 将每个节点字符串转换为字典
    proxies_list = []
    for node in nodes:
        # 使用yaml.safe_load来加载每个节点
        node_dict = yaml.safe_load(node)
        proxies_list.append(node_dict)

    yaml_data = {"proxies": proxies_list}
    return yaml_data

# link非代理协议时，请求url解析
def process_url(url):
    isyaml = False
    try:
        # 发送GET请求
        response = requests.get(url, headers=headers, verify=False)
        # 确保响应状态码为200
        if response.status_code == 200:
            content = response.text
            if 'external-controller' in content:
                # YAML格式
                yaml_data = yaml.safe_load(content)
                if 'proxies' in yaml_data:
                    isyaml = True
                    return yaml_data['proxies'],isyaml
            else:
                # 尝试Base64解码
                try:
                    decoded_bytes = base64.b64decode(content)
                    decoded_content = decoded_bytes.decode('utf-8')
                    return decoded_content.splitlines(),isyaml
                except Exception as e:
                    try:
                        res = js_render(url)
                        # print(333, res.html.text)
                        if 'external-controller' in res.html.text:
                            # YAML格式
                            try:
                                yaml_data = yaml.safe_load(res.html.text)
                            except Exception as e:
                                yaml_data = match_nodes(res.html.text)
                            finally:
                                if 'proxies' in yaml_data:
                                    isyaml = True
                                    return yaml_data['proxies'], isyaml

                        else:
                            pattern = r'([A-Za-z0-9_+/\-]+={0,2})'
                            matches = re.findall(pattern, res.html.text)
                            stdout = matches[-1] if matches else []
                            decoded_bytes = base64.b64decode(stdout)
                            decoded_content = decoded_bytes.decode('utf-8')
                            return decoded_content.splitlines(), isyaml
                    except Exception as e:
                        # 如果不是Base64编码，直接按行处理
                        return [],isyaml

        else:
            print(f"Failed to retrieve data from {url}, status code: {response.status_code}")
            return [],isyaml
    except requests.RequestException as e:
        print(f"An error occurred while requesting {url}: {e}")
        return [],isyaml

# 解析不同的代理链接
def parse_proxy_link(link):
    if link.startswith("hysteria2://"):
        return parse_hysteria2_link(link)
    elif link.startswith("trojan://"):
        return parse_trojan_link(link)
    elif link.startswith("ss://"):
        return parse_ss_link(link)
    elif link.startswith("vless://"):
        return parse_vless_link(link)
    elif link.startswith("vmess://"):
        return parse_vmess_link(link)
    return None

def deduplicate_proxies(proxies_list):
    unique_proxies = []
    seen = set()
    for proxy in proxies_list:
        key = (proxy['server'], proxy['port'])
        if key not in seen:
            seen.add(key)
            unique_proxies.append(proxy)
    return unique_proxies

# 生成 Clash 配置文件
def generate_clash_config(links):
    final_nodes = []
    config = clash_config_template.copy()

    for link in links:
        node = None
        if link.startswith(("hysteria2://", "trojan://", "ss://", "vless://", "vmess://")):
            node = parse_proxy_link(link)
            final_nodes.append(node)
        else:
            # 处理非特定协议的链接
            new_links,isyaml = process_url(link)
            if isyaml:
                final_nodes+=new_links
            else:
                for new_link in new_links:
                    if new_link.startswith(("hysteria2://", "trojan://", "ss://", "vless://", "vmess://")):
                        node = parse_proxy_link(new_link)
                        if node:
                            final_nodes.append(node)
                    else:
                        print(f"跳过无效或不支持的链接: {new_link}")
    final_nodes = deduplicate_proxies(final_nodes)
    for node in final_nodes:
        config["proxy-groups"][0]["proxies"].append(node["name"])
    config["proxies"] = final_nodes
    if config["proxies"]:
        with open("clash_config.yaml", "w", encoding="utf-8") as f:
            yaml.dump(config, f, allow_unicode=True, default_flow_style=False)
        print("Clash config file generated as clash_config.yaml")
    else:
        print('没有节点数据更新')


# 示例链接数组
links = [
    "hysteria2://5353b3c5-1cf7-4e66-a8d2-c3dcbd781c18@jiedianfsc.fsc.interld123456789.com:28002/?insecure=1&sni=cesuuu.1234567890spcloud.com&mport=28002-29000#%E7%BE%8E%E5%9B%BD003%20-%20hysteria2",
    "ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp2UDhzbkRhdGcwOTdjMTlBM2VZUGpV@51.120.10.54:4567#%E5%9B%BD%E5%AE%B6%E9%98%B2%E7%BE%A4",
    "trojan://telegram-id-directvpn@54.220.119.47:22222?security=tls&sni=trojan.burgerip.co.uk&type=tcp&alpn=http/1.1#%E7%BE%8E%E5%9B%BD%E6%8D%B7%E9%98%B2%E7%BE%A4",
    "vless://54ef4ecf-ff37-436a-be13-95c8a8a1114d@188.121.118.55:443?security=tls&sni=vIrGiNiAvPn-nL.pAgEs.dEv&type=ws&host=ViRgInIaVpN-Nl.PaGeS.DeV&path=%2F%3Fed%3D2048#%E6%B3%95%E5%9B%BD%E9%98%B2%E7%BE%A4",
    "vmess://eyJhZGQiOiIxMDQuMTYuNjAuOCIsImFpZCI6IjAiLCJhbHBuIjoiIiwiZnAiOiIiLCJob3N0IjoiaWN5LXRvb3RoLTNkMDUucGx6dGhzbWRuc3MtN2Q4bHkud29ya2Vycy5kZXYiLCJpZCI6IjA1NjQxY2Y1LTU4ZDItNGJhNC1hOWYxLWIzY2RhMGIxZmIxZCIsIm5ldCI6IndzIiwicGF0aCI6Ilwvb2JkaWkuY2ZkXC9saW5rd3MiLCJwb3J0IjoiMjA5NSIsInBzIjoiXHVkODNjXHVkZGU5XHVkODNjXHVkZGVhW29wZW5wcm94eWxpc3QuY29tXSB2bWVzcy1ERSIsInNjeSI6ImF1dG8iLCJzbmkiOiIiLCJ0bHMiOiIiLCJ0eXBlIjoiIiwidiI6IjIiLCJza2lwLWNlcnQtdmVyaWZ5Ijp0cnVlfQ==",
    "https://sub.white.pp.ua/api/v1/client/subscribe?token=1effb2e4c49743f8637fa2c7fa891c61", # base64
    "https://igdux.top/KdAJ" # yaml
]

generate_clash_config(links)
