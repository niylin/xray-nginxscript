#!/bin/bash

# 系统信息检测
distro=$(awk -F= '/^NAME/{print $2}' /etc/os-release)
if [[ "$distro" == *"Debian"* || "$distro" == *"Ubuntu"* ]]; then
    echo "检测到 Debian/Ubuntu 操作系统"
else
    echo "不支持的操作系统: $distro"
    exit 1
fi

# 检查网络连接
if ! ping -q -c 1 -W 1 github.com >/dev/null && ! ping -q -c 1 -W 1 google.com >/dev/null; then
  # 无法联网，写入 DNS 信息
  echo "无法连接网络,正在写入DNS信息..."
  cat <<EOF > /etc/resolv.conf
nameserver 1.0.0.1
nameserver 8.8.8.8
nameserver 2606:4700:4700::1111
nameserver 2001:4860:4860::8888
EOF

  systemctl restart networking.service
  service networking restart
fi

# 网络连接状态
if ping -q -c 1 -W 1 github.com >/dev/null || ping -q -c 1 -W 1 google.com >/dev/null; then
  echo "已联网"
else
  echo "无法连接互联网"
  exit 1
fi


# 获取用户信息
read -p "请输入完整域名 例如 example.example.com： " domain_name
read -p "请为结点命名： " jiedian_name_zd
read -p "请输入您的 Cloudflare API 密钥: " CF_Key
read -p "请输入您的 Cloudflare 邮件地址: " CF_Email
echo "请选择要解析的IP地址类型："
echo "[1] IPv6"
echo "[2] IPv4"
read -p "请输入选项数字: " ip_type_choice

ipv6_address=$(curl -sL "https://ipv6.ping0.cc")
ipv4_address=$(curl -sL "https://ipv4.ping0.cc")
# 生成 UUID
uuid=$(cat /proc/sys/kernel/random/uuid)

# 安装wgcf
read -p "是否安装wgcf,输入y安装： " wgcfchoice
if [ "$wgcfchoice" == "y" ]; then
    wget -N https://gitlab.com/fscarmen/warp/-/raw/main/menu.sh && echo -e "2\n1\n3\n" | bash menu.sh d
else
    echo "跳过wgcf安装"
fi



if pgrep -x "apache2" >/dev/null || pgrep -x "httpd" >/dev/null || pgrep -x "nginx" >/dev/null; then
    # Prompt user to uninstall web server
    read -t 5 -p "检测到已经安装了 Web 服务器，是否需要卸载？(y/n，默认5秒后自动选择卸载 如不卸载请确保443端口未被占用): " -n 1 -r uninstall_webserver || uninstall_webserver="y"
    echo ""

    if [[ $uninstall_webserver =~ ^[Yy]$ ]]
    then
        echo "开始卸载 Web 服务器..."
        pkill -9 apache2
        pkill -9 httpd
        pkill -9 nginx
        if [ -x "$(command -v apt-get)" ]; then
            apt-get purge -y apache2 apache2.2-common nginx
        elif [ -x "$(command -v yum)" ]; then
            yum remove -y httpd* nginx
        fi
    fi
fi

# 安装必要的软件包
if [ -f /etc/debian_version ]; then
    apt-get update
    # apt-get install -y curl unzip lsof git ufw nginx jq nano sudo
    apt-get install -y curl unzip lsof git ufw nginx jq nano sudo || { echo "安装失败: curl unzip ufw nginx jq"; exit 1; }

elif [ -f /etc/redhat-release ]; then
    yum install -y epel-release
    yum clean all
    yum makecache
    yum install -y curl unzip lsof git ufw nginx jq nano sudo || { echo "安装失败: curl unzip ufw nginx jq"; exit 1; }
fi

# 配置防火墙规则
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp
ufw allow 443
ufw allow 22/tcp
ufw allow 50000:65535/tcp
ufw allow 50000:65535/udp
yes | ufw enable
ufw reload

mkdir -p /opt/cert

# 安装 acme
curl https://get.acme.sh | sh -s email=yingjiblack@gmail.com

# 创建 acme.sh 命令别名
echo 'alias acme.sh=~/.acme.sh/acme.sh' >> ~/.bashrc
source ~/.bashrc

# 使用 Cloudflare API 请求 SSL 证书
~/.acme.sh/acme.sh --issue --dns dns_cf -d $domain_name 
~/.acme.sh/acme.sh --install-cert -d $domain_name \
    --key-file /opt/cert/$domain_name.key \
    --fullchain-file /opt/cert/$domain_name.crt


#自动添加解析
original_domain_name=$domain_name

if [ "$ip_type_choice" != "1" ] && [ "$ip_type_choice" != "2" ]; then
    echo "无效的选项，跳过添加 DNS 解析记录。"
else
    if [ $ip_type_choice -eq 1 ]; then
        # 如果选择IPv6，则获取本机IPv6地址
        ipv6_address=$(curl -sL "https://ipv6.ping0.cc")
        ip_address=$ipv6_address
        record_type="AAAA"
    elif [ $ip_type_choice -eq 2 ]; then
        # 如果选择IPv4，则获取本机IPv4地址
        ipv4_address=$(curl -sL "https://ipv4.ping0.cc")
        ip_address=$ipv4_address
        record_type="A"
    fi
    # 获取 domain_name 的 Zone ID
    curl_head=(
        "X-Auth-Email: ${CF_Email}"
        "X-Auth-Key: ${CF_Key}"
        "Content-Type: application/json"
    )
        while [[ "$original_domain_name" =~ \. ]]; do
original_domain_name="${original_domain_name#*.}"
curl_url="https://api.cloudflare.com/client/v4/zones?name=${original_domain_name}"
response_json_str=$(curl -sS --request GET "${curl_url}" --header "${curl_head[0]}" --header "${curl_head[1]}" --header "${curl_head[2]}")
zone_id_temp=$(echo "${response_json_str}" | jq -r '.result[0] | select(. != null) | .id')
    
    if [ ! -z "$zone_id_temp" ]; then
        zone_id="$zone_id_temp"
        echo "子域名 ${original_domain_name} 的区域 ID 为：$zone_id"
    fi
done


    if curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
      -H "X-Auth-Email: $CF_Email" \
      -H "X-Auth-Key: $CF_Key" \
      -H "Content-Type: application/json" \
      --data "{\"type\":\"$record_type\",\"name\":\"$domain_name\",\"content\":\"$ip_address\",\"ttl\":1,\"proxied\":true}" > /dev/null; then
      echo "CDN域名解析成功！"
    else
      echo "主机名解析添加失败，尝试手动添加。"
    fi
fi

# 生成节点名
declare -A emoji_map
emoji_map["AU"]="🇦🇺"
emoji_map["BR"]="🇧🇷"
emoji_map["CA"]="🇨🇦"
emoji_map["CH"]="🇨🇭"
emoji_map["CN"]="🇨🇳"
emoji_map["DE"]="🇩🇪"
emoji_map["DK"]="🇩🇰"
emoji_map["ES"]="🇪🇸"
emoji_map["FI"]="🇫🇮"
emoji_map["FR"]="🇫🇷"
emoji_map["GB"]="🇬🇧"
emoji_map["HK"]="🇭🇰"
emoji_map["IE"]="🇮🇪"
emoji_map["IN"]="🇮🇳"
emoji_map["JP"]="🇯🇵"
emoji_map["KP"]="🇰🇵"
emoji_map["KR"]="🇰🇷"
emoji_map["MY"]="🇲🇾"
emoji_map["NL"]="🇳🇱"
emoji_map["NO"]="🇳🇴"
emoji_map["PL"]="🇵🇱"
emoji_map["RU"]="🇷🇺"
emoji_map["SE"]="🇸🇪"
emoji_map["SG"]="🇸🇬"
emoji_map["TW"]="🇹🇼"
emoji_map["US"]="🇺🇸"
emoji_map["VN"]="🇻🇳"
emoji_map["ZA"]="🇿🇦"
emoji_map["IT"]="🇮🇹"

response=$(curl -s http://ip-api.com/json/)

countryCode=$(echo $response | jq -r '.countryCode')
cityinfo=$(echo $response | jq -r '.city')
if [[ ${emoji_map[$countryCode]+_} ]]; then
    flag="${emoji_map[$countryCode]}"
fi
jiedian_name="${flag}${cityinfo} CF|$jiedian_name_zd"
DR_jiedian_name=${jiedian_name/CF|/DR|}
HY_jiedian_name=${jiedian_name/CF|/HY|}
RE_jiedian_name=${jiedian_name/CF|/RE|}
TU_jiedian_name=${jiedian_name/CF|/TU|}
WG_jiedian_name=${jiedian_name/CF|/WG|}
echo "$DR_jiedian_name"
echo "$HY_jiedian_name"
echo "$RE_jiedian_name"
echo "$TU_jiedian_name"
echo "$jiedian_name"

# 修改nginx主配置文件
mkdir -p /opt/www/proxy-providers

APPEND_CONTENT="
stream {
    map \$ssl_preread_server_name \$backend {
        www.tencentcloud.com       reality; 
        default                     www;
    }
    upstream reality {
        server 127.0.0.1:10005; # reality协议的端口
    }
    upstream www {
        server 127.0.0.1:2083; # 站点的端口
    }
    server {
        listen 443      reuseport;
        listen [::]:443 reuseport;
        proxy_pass      \$backend;
        ssl_preread     on;
        # proxy_protocol  on;
    }
}
"

# 追加内容到nginx.conf
echo "$APPEND_CONTENT" | sudo tee -a /etc/nginx/nginx.conf > /dev/null
# 创建 nginx 配置文件
cat <<EOF > /etc/nginx/conf.d/$domain_name.conf
server {
    listen 2083 ssl http2;
    listen [::]:2083 ssl http2; # Listen on IPv6 address
    ssl_certificate /opt/cert/$domain_name.crt;
    ssl_certificate_key /opt/cert/$domain_name.key;
    ssl_protocols         TLSv1.3;
    ssl_ecdh_curve        X25519:P-256:P-384:P-521;
    server_name           $domain_name;
    index index.html index.htm;
    root  /opt/www/shipin1;
    error_page 400 = /400.html;

    ssl_early_data on;
    ssl_stapling on;
    ssl_stapling_verify on;
    add_header Strict-Transport-Security "max-age=63072000" always;

    location /$uuid-proxy-providers {
        # 检查 token 是否匹配
        if ($arg_token != "$uuid") {
            return 403;
            }
        # 设置目录路径
        alias /opt/www/proxy-providers;

        # 开启目录列表功能（如果需要）
        autoindex on;
        autoindex_exact_size off;
        autoindex_localtime on;
    }
    location /$uuid-vm {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10001;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection upgrade;
        proxy_set_header Host \$http_host;
        #proxy_set_header X-Real-IP \$remote_addr;
        #proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    location /$uuid-tr {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection upgrade;
        proxy_set_header Host \$http_host;
        #proxy_set_header X-Real-IP \$remote_addr;
        #proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    location /$uuid-vl {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10003;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection upgrade;
        proxy_set_header Host \$http_host;
        #proxy_set_header X-Real-IP \$remote_addr;
        #proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
	    aaaaidddddaa125647
}
EOF

echo "请选择需要执行的操作："
echo "1. 克隆视频网站"
echo "2. 克隆音乐网站"
echo "3. 克隆文件网站"
echo "4. 安装 AList"

while true; do
    read -p "请输入选项编号[1/2/3/4]：" option
    case $option in
        1)
            wget https://github.com/niylin/xray-nginxscript/releases/download/nhg/shipin1.zip -O /opt/www/shipin1.zip
            unzip /opt/www/shipin1.zip -d /opt/www
            sed -i "s|root  /opt/www/shipin1;|root  /opt/www/shipin1;|" /etc/nginx/conf.d/$domain_name.conf
            break
            ;;
        2)
            wget https://github.com/niylin/xray-nginxscript/releases/download/nhg/mikutap.zip -O /opt/www/mikutap.zip
            unzip /opt/www/mikutap.zip -d /opt/www

            sed -i "s|root  /opt/www/shipin1;|root  /opt/www/mikutap;|" /etc/nginx/conf.d/$domain_name.conf
            break
            ;;
        3)
            wget https://github.com/niylin/xray-nginxscript/releases/download/nhg/zhuanhuan.zip -O /opt/www/zhuanhuan.zip
            unzip /opt/www/zhuanhuan.zip -d /opt/www
            sed -i "s|root  /opt/www/shipin1;|root  /opt/www/zhuanhuan;|" /etc/nginx/conf.d/$domain_name.conf
            break
            ;;
        4)
            curl -fsSL "https://alist.nn.ci/v3.sh" | bash -s install
            sed -i "s|aaaaidddddaa125647|location / {\n        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto \$scheme;\n        proxy_set_header Host \$http_host;\n        proxy_set_header X-Real-IP \$remote_addr;\n        proxy_set_header Range \$http_range;\n        proxy_set_header If-Range \$http_if_range;\n        proxy_redirect off;\n        proxy_pass http://127.0.0.1:5244;\n        client_max_body_size 20000m;\n\t}|" /etc/nginx/conf.d/$domain_name.conf
            break
            ;;
        *)
            echo "无效的选项，请输入[1/2/3/4]中的一个。"
            ;;
    esac
done

sed -i 's|aaaaidddddaa125647||g' /etc/nginx/conf.d/$domain_name.conf

   echo "安装sing-box..."
ARCH_RAW=$(uname -m)
case "${ARCH_RAW}" in
    'x86_64')    ARCH='amd64';;
    'x86' | 'i686' | 'i386')     ARCH='386';;
    'aarch64' | 'arm64') ARCH='arm64';;
    'armv7l')   ARCH='armv7';;
    's390x')    ARCH='s390x';;
    *)          echo "Unsupported architecture: ${ARCH_RAW}"; exit 1;;
esac
VERSION=$(curl -s https://api.github.com/repos/SagerNet/sing-box/releases/latest \
    | grep tag_name \
    | cut -d ":" -f2 \
    | sed 's/\"//g;s/\,//g;s/\ //g;s/v//')
	mkdir -p /opt/sing-box
	wget "https://github.com/SagerNet/sing-box/releases/download/v${VERSION}/sing-box-${VERSION}-linux-${ARCH}.tar.gz" -O /opt/sing-box/sing-box-linux-64.tar.gz
tar -xzvf /opt/sing-box/sing-box-linux-64.tar.gz -C /opt/sing-box/ --strip-components=1


# 执行命令并将输出保存到变量
shortId=$(/opt/sing-box/sing-box generate rand 8 --hex)
output=$(/opt/sing-box/sing-box generate reality-keypair)

# 提取 Private key 和 Public key
private_key=$(echo "$output" | grep "PrivateKey:" | awk '{print $2}')
public_key=$(echo "$output" | grep "PublicKey:" | awk '{print $2}')

# 创建sing-box配置文件
cat <<EOF > /opt/sing-box/config.json
{
    "inbounds": [
        {
            "type": "vmess",
            "listen": "127.0.0.1",
            "listen_port": 10001,
            "users": [
                {
                    "uuid": "$uuid",
                    "alterId": 0
                }
            ],
            "transport": {
                "type": "ws",
                "path": "$uuid-vm",
                "max_early_data": 2048,
                "early_data_header_name": "Sec-WebSocket-Protocol"
            }
        },
        {
            "type": "trojan",
            "listen": "127.0.0.1",
            "listen_port": 10002,
            "users": [
                {
                    "password": "$uuid"
                }
            ],
            "transport": {
                "type": "ws",
                "path": "$uuid-tr",
                "max_early_data": 2048,
                "early_data_header_name": "Sec-WebSocket-Protocol"
            }
        },
        {
            "type": "vless",
            "listen": "127.0.0.1",
            "listen_port": 10003,
            "users": [
                {
                    "uuid": "$uuid"
                }
            ],
            "transport": {
                "type": "ws",
                "path": "$uuid-vl",
                "max_early_data": 2048,
                "early_data_header_name": "Sec-WebSocket-Protocol"            }
        },
        {
            "type": "vless",
            "listen": "::",
            "listen_port": 10005,
            "users": [
                {
                    "uuid": "$uuid",
                    "flow": "xtls-rprx-vision"
                }
            ],
            "tls": {
                "enabled": true,
                "server_name": "www.tencentcloud.com",
                "reality": {
                    "enabled": true,
                    "handshake": {
                        "server": "www.tencentcloud.com",
                        "server_port": 443
                    },
                    "private_key": "$private_key",
                    "short_id": [ 
                        "$shortId"
                    ]
                }
            }
        },
        {
            "type": "hysteria2",
            "listen": "::",
            "listen_port": 58999,
            "users": [
                {
                    "password": "$uuid"
                }
            ],
            "tls": {
                "enabled": true,
                "alpn": [
                    "h3"
                ],
                "certificate_path": "/opt/cert/$domain_name.crt",
                "key_path": "/opt/cert/$domain_name.key"
            }
        }
    ],
    "outbounds": [
        {
            "type": "direct"
        }
    ]
}
EOF

#写入守护进程
mkdir -p /usr/lib/systemd/system/
cat <<EOF > /usr/lib/systemd/system/sing-box.service
[Unit]
Description=sing-box service
Documentation=https://sing-box.sagernet.org
After=network.target nss-lookup.target network-online.target

[Service]
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SYS_PTRACE CAP_DAC_READ_SEARCH
ExecStart=/opt/sing-box/sing-box -D /opt/sing-box -C /opt/sing-box run
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=10s
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF

# 配置wire guard
sysctld_99_sysctl="
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
"
echo "$sysctld_99_sysctl" | sudo tee -a /etc/sysctl.d/99-sysctl.conf > /dev/null
sudo sysctl --system

cat <<EOF > /etc/wireguard/wg0.conf
[Interface]
PrivateKey = qESAcU0L9dweGnbZjgEKIr9CDhr56e3BrsSDe//kXHo=
Address = 10.0.0.1/24, 2604:6400:30:ee1b::1/64
PostUp = iptables -A FORWARD -i %i -j ACCEPT; iptables -t nat -A POSTROUTING -o warp -j MASQUERADE
PostUp = ip6tables -A FORWARD -i %i -j ACCEPT; ip6tables -t nat -A POSTROUTING -o warp -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -t nat -D POSTROUTING -o warp -j MASQUERADE
PostDown = ip6tables -D FORWARD -i %i -j ACCEPT; ip6tables -t nat -D POSTROUTING -o warp -j MASQUERADE
ListenPort = 59999
DNS = 1.1.1.1
MTU = 1420
[Peer]
PublicKey = Pl9Kzf0MDGh94QSNTahZRirf5kTYrgo9o8CrXZ652Q0=
AllowedIPs = 10.0.0.2/32, 2604:6400:30:ee1b::2/128

[Peer]
PublicKey = 285myCGI/ZXxSYAWClECq19P7MnyyXWNaSB6IictIlE=
AllowedIPs = 10.0.0.3/32, 2604:6400:30:ee1b::3/128

EOF

# 添加转发
DEBIAN_FRONTEND=noninteractive apt install iptables-persistent -y
iptables -t nat -A PREROUTING -p tcp --dport 58000:58998 -j REDIRECT --to-port 58999
iptables -t nat -A PREROUTING -p udp --dport 58000:58998 -j REDIRECT --to-port 58999
ip6tables -t nat -A PREROUTING -p tcp --dport 58000:58998 -j REDIRECT --to-port 58999
ip6tables -t nat -A PREROUTING -p udp --dport 58000:58998 -j REDIRECT --to-port 58999
iptables -t nat -A PREROUTING -p tcp --dport 59000:59998 -j REDIRECT --to-port 59999
iptables -t nat -A PREROUTING -p udp --dport 59000:59998 -j REDIRECT --to-port 59999
ip6tables -t nat -A PREROUTING -p tcp --dport 59000:59998 -j REDIRECT --to-port 59999
ip6tables -t nat -A PREROUTING -p udp --dport 59000:59998 -j REDIRECT --to-port 59999
netfilter-persistent  save

systemctl daemon-reload
systemctl restart sing-box
systemctl enable sing-box
systemctl restart nginx
wg-quick up wg0

# 写入节点配置
cat <<EOF > /opt/www/proxy-providers/wg2.conf
[Interface]
Address = 10.0.0.2/24, 2604:6400:30:ee1b::2/64
DNS = 1.1.1.1
MTU = 1420
PrivateKey = eN3ASLZFBtu73KiWzjwUx8qLINBa3wW7h2vVQQhZ+nA=

[Peer]
AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1
Endpoint = $ip_address:59998
PersistentKeepalive = 25
PublicKey = 7tOvkxQE8UoVy+4v+z47zDFIrcywYx5jzijbzjGzehk=
EOF

cat <<EOF > /opt/www/proxy-providers/wg3.conf
[Interface]
Address = 10.0.0.3/24, 2604:6400:30:ee1b::3/64
DNS = 1.1.1.1
MTU = 1420
PrivateKey = eOFj5csSCb6w1iE+84M60pXwcM0P/wsmG1dBJxXpkXQ=

[Peer]
AllowedIPs = 0.0.0.0/1, 128.0.0.0/1, ::/1, 8000::/1
Endpoint = $ip_address:59998
PersistentKeepalive = 25
PublicKey = 7tOvkxQE8UoVy+4v+z47zDFIrcywYx5jzijbzjGzehk=
EOF


# 写入节点配置
cat <<EOF > /opt/www/proxy-providers/$jiedian_name_zd.yaml
mixed-port: 7890
tproxy-port: 7891 
socks-port: 7892
allow-lan: true
bind-address: "*"
mode: rule
log-level: info
ipv6: true
keep-alive-interval: 30
find-process-mode: strict
external-controller: "0.0.0.0:9090"
secret: "$uuid"
external-ui: ui
external-ui-url: "https://github.com/MetaCubeX/metacubexd/archive/refs/heads/gh-pages.zip"
profile:
  store-selected: true
  store-fake-ip: false
unified-delay: true
tcp-concurrent: true
global-client-fingerprint: chrome
geodata-mode: true
geox-url:
  geoip: "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.dat"
  geosite: "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.dat"
  mmdb: "https://fastly.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.metadb"
geo-auto-update: true
geo-update-interval: 24
global-ua: clash.meta
sniffer:
  enable: true
  force-dns-mapping: true
  parse-pure-ip: true
  override-destination: false
  sniff:
    HTTP:
      ports: [80, 8080-8880]
      override-destination: true
    TLS:
      ports: [443, 8443]
    QUIC:
      ports: [443, 8443]
  skip-domain:
    - "Mijia Cloud"
tun:
  enable: true
  stack: gvisor
  auto-route: true
  strict-route: false
  auto-detect-interface: true
  dns-hijack:
  - any:53
external-controller-cors:
  allow-private-network: true
  allow-origins:
  - '*'
dns:
  enable: true
  listen: :53
  enhanced-mode: redir-host
  # enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  fake-ip-filter-mode: blacklist
  prefer-h3: false
  respect-rules: false
  use-hosts: false
  use-system-hosts: false
  fake-ip-filter:
  - '*.lan'
  - '*.local'
  - '*.arpa'
  - time.*.com
  - ntp.*.com
  - time.*.com
  - +.market.xiaomi.com
  - localhost.ptlogin2.qq.com
  - '*.msftncsi.com'
  - www.msftconnecttest.com
  default-nameserver:
  - system
  - 223.6.6.6
  - 8.8.8.8
  nameserver:
  - 8.8.8.8
  - https://doh.pub/dns-query
  - https://dns.alidns.com/dns-query
  fallback: []
  nameserver-policy: {}
  proxy-server-nameserver:
  - https://doh.pub/dns-query
  - https://dns.alidns.com/dns-query
  - tls://223.5.5.5
  direct-nameserver: []
  direct-nameserver-follow-policy: false
  fallback-filter:
    geoip: true
    geoip-code: CN
    ipcidr:
    - 240.0.0.0/4
    - 0.0.0.0/32
    domain:
    - +.google.com
    - +.facebook.com
    - +.youtube.com
proxy-groups: 
  - name: NetSelect
    type: select
    proxies:
      - DIRECT
      - AutoSelect
      - $HY_jiedian_name
      - $jiedian_name-vm
      - $jiedian_name
      - $RE_jiedian_name
  - name: others
    type: select
    proxies:
      - NetSelect
      - DIRECT
  - name: 🛑全球拦截
    type: select
    proxies:
      - REJECT
      - NetSelect
      - AutoSelect
      - DIRECT
  - name: 🎯全球直连
    type: select
    proxies:
      - DIRECT
      - NetSelect
      - AutoSelect
  - name: AutoSelect
    type: url-test
    url: http://1.0.0.1
    interval: "3000"
      - $HY_jiedian_name
      - $jiedian_name-vm
      - $jiedian_name
      - $RE_jiedian_name
proxies:
  - name: $HY_jiedian_name
    type: hysteria2
    server: $ip_address
    port: 58999
    ports: 58000-58999
    password: $uuid
    sni: $domain_name
    alpn:
      - h3
  - name: $jiedian_name-vm
    type: vmess
    server: www.visa.com
    port: 443
    uuid: $uuid
    alterId: 0
    cipher: auto
    tls: true
    servername: $domain_name
    network: ws
    ws-opts:
      path: /$uuid-vm
      headers:
        Host: $domain_name
  - name: $jiedian_name
    type: trojan
    server: www.visa.com
    port: 443
    udp: true
    tls: true
    network: ws
    ws-opts:
      path: /$uuid-tr
      headers:
        Host: $domain_name
      max-early-data: 2048
      early-data-header-name: Sec-WebSocket-Protocol
      v2ray-http-upgrade: false
    password: $uuid
    sni: $domain_name
  - name: $RE_jiedian_name
    type: vless
    server: $ip_address
    port: 443
    uuid: $uuid
    network: tcp
    tls: true
    udp: true
    flow: xtls-rprx-vision
    servername: www.tencentcloud.com
    reality-opts:
      public-key: $public_key
      short-id: $shortId
    client-fingerprint: chrome
rule-providers:
  GitHub:
    type: http
    behavior: classical
    url: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/GitHub/GitHub.yaml"
    path: ./ruleset/GitHub.yaml
    interval: 86400
  Gemini:
    type: http
    behavior: classical
    url: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Gemini/Gemini.yaml"
    path: ./ruleset/Gemini.yaml
    interval: 86400
  google:
    type: http
    behavior: classical
    url: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Google/Google.yaml"
    path: ./ruleset/google.yaml
    interval: 86400

  apple:
    type: http
    behavior: classical
    url: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Apple/Apple_Classical.yaml"
    path: ./ruleset/apple.yaml
    interval: 86400
    
  Speedtest:
    type: http
    behavior: classical
    url: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Speedtest/Speedtest.yaml"
    path: ./ruleset/Speedtest.yaml
    interval: 86400

  SteamCN:
    type: http
    behavior: classical
    url: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/SteamCN/SteamCN.yaml"
    path: ./ruleset/SteamCN.yaml
    interval: 86400
    
  private:
    type: http
    behavior: classical
    url: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Privacy/Privacy_Classical.yaml"
    path: ./ruleset/private.yaml
    interval: 86400

  Netflix_domain:
    type: http
    behavior: classical
    url: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Netflix/Netflix_Classical.yaml"
    path: ./ruleset/Netflix.yaml
    interval: 86400

  youtube_domain:
    type: http
    behavior: classical
    url: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/YouTube/YouTube.yaml"
    path: ./ruleset/youtube.yaml

  Spotify_domain:
    type: http
    behavior: classical
    url: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Spotify/Spotify.yaml"    
    path: ./ruleset/Spotify.yaml
    interval: 86400

  telegram:
    type: http
    behavior: classical
    url: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Telegram/Telegram.yaml"
    path: ./ruleset/telegram.yaml
    interval: 86400

  Microsoft:
    type: http
    behavior: classical
    url: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/Microsoft/Microsoft.yaml"
    path: ./ruleset/Microsoft.yaml
    interval: 86400

  openai:
    type: http
    behavior: classical
    url: "https://cdn.jsdelivr.net/gh/blackmatrix7/ios_rule_script@master/rule/Clash/OpenAI/OpenAI.yaml"
    path: ./ruleset/OpenAI.yaml
    interval: 86400

  reject:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/reject.txt"
    path: ./ruleset/reject.yaml
    interval: 86400

  proxy:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/proxy.txt"
    path: ./ruleset/proxy.yaml
    interval: 86400

  direct:
    type: http
    behavior: domain
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt"
    path: ./ruleset/direct.yaml
    interval: 86400

  cncidr:
    type: http
    behavior: ipcidr
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt"
    path: ./ruleset/cncidr.yaml
    interval: 86400

  lancidr:
    type: http
    behavior: ipcidr
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/lancidr.txt"
    path: ./ruleset/lancidr.yaml
    interval: 86400

  applications:
    type: http
    behavior: classical
    url: "https://cdn.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/applications.txt"
    path: ./ruleset/applications.yaml
    interval: 86400

rules:
  - RULE-SET,youtube_domain,NetSelect
  - RULE-SET,Spotify_domain,NetSelect
  - RULE-SET,Netflix_domain,NetSelect
  - DOMAIN,clash.razord.top,🎯全球直连
  - DOMAIN,yacd.haishan.me,🎯全球直连
  - RULE-SET,private,NetSelect     # 隐私追踪
  - RULE-SET,reject,🛑全球拦截      # 广告拦截    
  - RULE-SET,apple,NetSelect 
  - RULE-SET,google,NetSelect 
  - RULE-SET,lancidr,DIRECT          
  - RULE-SET,telegram,NetSelect
  - RULE-SET,openai,NetSelect
  - RULE-SET,Microsoft,NetSelect
  - RULE-SET,Speedtest,NetSelect
  - RULE-SET,Gemini,NetSelect
  - RULE-SET,GitHub,NetSelect
  - GEOIP,LAN,DIRECT
  - GEOIP,CN,🎯全球直连
  - RULE-SET,cncidr,🎯全球直连       
  - RULE-SET,direct,🎯全球直连
  - RULE-SET,SteamCN,🎯全球直连
  - RULE-SET,applications,🎯全球直连
  - RULE-SET,proxy,NetSelect
  - MATCH,others

EOF

cat <<EOF > /opt/www/proxy-providers/link.yamml
--------------------------------------------------------
--------------------------------------------------------
VMESS_LINK="vmess://$(echo -n '{"v":"2","ps":"'$jiedian_name'-vmess","add":"'$domain_name'","port":"443","id":"'$uuid'","aid":"0","scy":"none","net":"ws","type":"none","host":"'$domain_name'","path":"/'$uuid'-vm","tls":"tls","sni":"'$domain_name'","alpn":"h2","fp":"chrome"}' | base64 -w 0)"

TROJAN_LINK="trojan://$uuid@$domain_name:443?security=tls&sni=$domain_name&alpn=h2&fp=chrome&type=ws&host=$domain_name&path=%2F$uuid-tr#$jiedian_name-trojan"

--------------------------------------------------------
--------------------------------------------------------
ipv4_address: $ipv4_address
ipv6_address: $ipv6_address
节点信息保存在/opt/www/proxy-providers/
订阅地址: https://$domain_name/$uuid-proxy-providers/$jiedian_name_zd.yaml?token=$uuid
wireguard原生客户端中,"Endpoint"ipv6地址需要加上[]才能连接,正确格式 [IPV6]:port
wireguard端口 59000-59999
hysteria2端口 58000-58999
EOF
cat /opt/www/proxy-providers/link.yamml




