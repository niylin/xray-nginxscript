#!/bin/bash

# 系统信息检测
if ! command -v apt >/dev/null 2>&1; then
    echo "包管理器不是apt，退出"
    exit 1
fi
# 检查网络连接
if ! ping -q -c 1 -W 1 github.com >/dev/null && ! ping -q -c 1 -W 1 google.com >/dev/null; then
  # 无法联网，写入 DNS 信息
  echo "无法连接网络,正在写入DNS信息..."
  cat <<EOF > /etc/resolv.conf
nameserver 1.1.1.1
nameserver 8.8.8.8
nameserver 2001:4860:4860::8888
nameserver 2606:4700:4700::1111
EOF

  systemctl restart networking.service
fi
# 网络连接状态
if ping -q -c 1 -W 1 github.com >/dev/null || ping -q -c 1 -W 1 google.com >/dev/null; then
  echo "已联网"
else
  echo "无法连接互联网"
fi
apt update && apt -y install curl
mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared buster main' | tee /etc/apt/sources.list.d/cloudflared.list
apt-get update && apt-get install cloudflared

uuid=$(cat /proc/sys/kernel/random/uuid)
jiedian_name=$uuid
domain_name="$uuid.nnn.uw.to"
mkdir -p /root/.cloudflared/
cat << EOF > /root/.cloudflared/cert.pem
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQg0zxMXJNQ6quvDXbS
5zNaNI6PHnXiqX5vtRinyRtE3fChRANCAASgZ4RBIeL433GKxw2iUFPlMqGkjlrk
T5ZRiKE3CTy0MFvJDUx7OVmdUykiabYfsyBRMPMAsbsJ3nxP2jLLAdnq
-----END PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIIDHTCCAsSgAwIBAgIUaboTA51UEXvQSK0VNsFSvoEzrmEwCgYIKoZIzj0EAwIw
gY8xCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpDYWxpZm9ybmlhMRYwFAYDVQQHEw1T
YW4gRnJhbmNpc2NvMRkwFwYDVQQKExBDbG91ZEZsYXJlLCBJbmMuMTgwNgYDVQQL
Ey9DbG91ZEZsYXJlIE9yaWdpbiBTU0wgRUNDIENlcnRpZmljYXRlIEF1dGhvcml0
eTAeFw0yMzA1MDExOTE4MDBaFw0zODA0MjcxOTE4MDBaMGIxGTAXBgNVBAoTEENs
b3VkRmxhcmUsIEluYy4xHTAbBgNVBAsTFENsb3VkRmxhcmUgT3JpZ2luIENBMSYw
JAYDVQQDEx1DbG91ZEZsYXJlIE9yaWdpbiBDZXJ0aWZpY2F0ZTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABKBnhEEh4vjfcYrHDaJQU+UyoaSOWuRPllGIoTcJPLQw
W8kNTHs5WZ1TKSJpth+zIFEw8wCxuwnefE/aMssB2eqjggEoMIIBJDAOBgNVHQ8B
Af8EBAMCBaAwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUFBwMBMAwGA1UdEwEB
/wQCMAAwHQYDVR0OBBYEFCkZ9xey7bPS4ZJMpKHfjZZ5GRjsMB8GA1UdIwQYMBaA
FIUwXTsqcNTt1ZJnB/3rObQaDjinMEQGCCsGAQUFBwEBBDgwNjA0BggrBgEFBQcw
AYYoaHR0cDovL29jc3AuY2xvdWRmbGFyZS5jb20vb3JpZ2luX2VjY19jYTAhBgNV
HREEGjAYggsqLm5ubi51dy50b4IJbm5uLnV3LnRvMDwGA1UdHwQ1MDMwMaAvoC2G
K2h0dHA6Ly9jcmwuY2xvdWRmbGFyZS5jb20vb3JpZ2luX2VjY19jYS5jcmwwCgYI
KoZIzj0EAwIDRwAwRAIgW5+ZKHK+P6bR5dRU5qG0WUNsAVRjprK1rC25kjcGoRkC
IGqwVLslfwNG+p3E7Xf+FV36Geo+FoaYKwd8lEN0cKOm
-----END CERTIFICATE-----
-----BEGIN ARGO TUNNEL TOKEN-----
eyJ6b25lSUQiOiJlZDE2NjE3MGZiYmFmOWU3OWQxNmQxNTgyZWMwZDNmMCIsImFj
Y291bnRJRCI6IjUwNGQ4MjA5Mzc2NjEyZDIyMzBkYWVhNjNiYTQ1NTA0Iiwic2Vy
dmljZUtleSI6InYxLjAtYjg1YTZlMTNmZDdmYzY2NTlhODY5OWEwLTc4NjdhY2Yz
ZTVjMjNkZDk4NTlhYTQ0YjBkYjZhNzA2YThjOWRhZmQ0OTE4YmM5ZDg0OGU0NjIy
NmJmNjIyNDEyNTk4NzY3YjdhODhhNGU3NGY1ODVkNzZlODdiYTQ5NmMyY2M3NDYx
MmNkNGEzZDVhYzVjYmEzNWNhYTc0OGQyOWIxZWUwZDM4YTAzNWFlM2IwZmE2N2Uz
MWEwNWFlOGMiLCJhcGlUb2tlbiI6Ik1zRmhTSThwa1E4N1F4YkppU3FCVGg1a3hf
V0FVb1BLd3lUTkF4NGsifQ==
-----END ARGO TUNNEL TOKEN-----
EOF
cloudflared tunnel create $jiedian_name
cloudflared tunnel route dns $jiedian_name "tr$domain_name"
for file in /root/.cloudflared/*.json; do
  if [[ -r "$file" ]]; then
    # 使用 basename 命令获取文件名，不包括扩展名
    name=$(basename "$file" .json)
    # 输出文件名和对应的内容
    echo "File: $file"
    echo "Name: $name"
  fi
done
cat <<EOF > /root/.cloudflared/config.yml
tunnel: $name
credentials-file: $file
protocol: http2
originRequest:
  connectTimeout: 30s
  noTLSVerify: false

ingress:
  - hostname: tr${domain_name}
    service: http://localhost:10003
  - service: http_status:404
EOF
   echo "安装xray..."
	mkdir -p /home/xray
	wget https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip -O /home/xray/Xray-linux-64.zip
	unzip /home/xray/Xray-linux-64.zip -d /home/xray
#写入守护进程
mkdir -p /usr/lib/systemd/system
cat <<EOF > /usr/lib/systemd/system/xray.service
[Unit]
Description="xray"

[Service]
Type=simple
GuessMainPID=true
WorkingDirectory=/home/xray
StandardOutput=journal
StandardError=journal
ExecStart=/home/xray/xray
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# 修改 xray 配置文件
cat <<EOF > /home/xray/config.json
{
    "inbounds":[
        {
            "port":10001,
            "listen":"127.0.0.1",
            "protocol":"vmess",
            "settings":{
                "clients":[
                    {
                        "id":"$uuid",
                        "alterId":0
                    }
                ]
            },
            "streamSettings":{
                "network":"ws",
                "wsSettings":{
                    "path":"/$uuid-vm"
                }
            },
            "sniffing":{
                "enabled":true,
                "destOverride":[
                    "http",
                    "tls",
                    "quic"
                ],
                "metadataOnly":false
            }
        },
        {
            "port":10002,
            "listen":"127.0.0.1",
            "protocol":"vless",
            "settings": {
              "clients": [
                {
                  "id": "$uuid",
                  "flow": ""
                }
                         ],
            "decryption": "none",
            "fallbacks": []
                        },
            "streamSettings": {
            "network": "ws",
            "security": "none",
            "wsSettings": {
            "path": "/$uuid-vl",
            "headers": {}
          }
      },
           "tag": "inbound-11111",
           "sniffing": {
             "enabled": true,
             "destOverride": [
               "http",
               "tls"
                             ]
                       }
        },
        {
            "port":10003,
            "listen":"127.0.0.1",
            "protocol":"trojan",
            "settings":{
                "clients":[
                    {
                        "password":"$uuid"
                    }
                ]
            },
            "streamSettings":{
                "network":"ws",
                "security":"none",
                "wsSettings":{
                    "path":"/$uuid-tr"
                }
            },
            "sniffing":{
                "enabled":true,
                "destOverride":[
                    "http",
                    "tls",
                    "quic"
                ],
                "metadataOnly":false
            }
        }
    ],
    "outbounds":[
        {
            "protocol":"freedom"
        }
    ]
}
EOF
# 重启 xray 
systemctl daemon-reload
systemctl restart xray
systemctl enable xray
cloudflared service install
systemctl start cloudflared
# 生成 Trojan over WebSocket 的链接
TROJAN_LINK="trojan://$uuid@tr$domain_name:443?security=tls&sni=vl$domain_name&alpn=h2&fp=chrome&type=ws&host=vl$domain_name&path=%2F$uuid-tr#$jiedian_name-trojan"

# 生成clash配置
config="\  
  - name: $jiedian_name-trojan
    server: tr$domain_name
    port: 443
    type: trojan
    tls: true
    servername: tr$domain_name
    network: ws
    ws-opts:
      path: /$uuid-tr
    password: $uuid
    sni: tr$domain_name"

# 输出链接
echo  "$TROJAN_LINK"
echo "------------------------------------------------------"
echo "------------------------------------------------------"
echo "$config"
