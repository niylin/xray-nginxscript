#!/bin/bash
apt update && apt -y install curl
mkdir -p --mode=0755 /usr/share/keyrings
curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg | sudo tee /usr/share/keyrings/cloudflare-main.gpg >/dev/null
echo 'deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared buster main' | sudo tee /etc/apt/sources.list.d/cloudflared.list
apt-get update && apt-get install cloudflared
jiedian_name=$(hostname)
uuid=$(cat /proc/sys/kernel/random/uuid)
default_domain="$uuid.nnn.uw.to"

read -p "是否使用内置证书和域名 $default_domain (Y/n)? " use_default_domain

if [[ "$use_default_domain" =~ ^[Nn]$ ]]; then
  read -p "请输入您的域名： " domain_name
else
  domain_name=$default_domain
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
fi

echo "请选择如何设置证书："
echo "1. 手动上传证书"
echo "3. 使用 Cloudflare 账户登录"

mkdir -p /root/.cloudflared/
read -p "请输入选项（1/3）：" cert_option

if [ "$cert_option" = "1" ]; then
    read -p "请上传证书到 /root/.cloudflared/cert.pem 后按 Enter 键继续。"
elif [ "$cert_option" = "3" ]; then
    cloudflared tunnel login
else
    echo "无效选项。"
    exit 1
fi
# chmod 700 ~/.cloudflared
# chmod 600 ~/.cloudflared/cert.pem
# 构建隧道
cloudflared tunnel create $jiedian_name
cloudflared tunnel route dns $jiedian_name "vm$domain_name"
cloudflared tunnel route dns $jiedian_name "tr$domain_name"
cloudflared tunnel route dns $jiedian_name "vl$domain_name"

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
  - hostname: vm${domain_name}
    service: http://localhost:10001
  - hostname: vl${domain_name}
    service: http://localhost:10002
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
systemctl start xray
systemctl enable xray
cloudflared service install
systemctl start cloudflared
# 生成 VMESS over WebSocket 的链接
VMESS_LINK="vmess://$(echo -n '{"v":"2","ps":"'$jiedian_name'-vmess","add":"'vm$domain_name'","port":"443","id":"'$uuid'","aid":"0","scy":"none","net":"ws","type":"none","host":"'vm$domain_name'","path":"/'$uuid'-vm","tls":"tls","sni":"'vm$domain_name'","alpn":"h2","fp":"chrome"}' | base64 -w 0)"

# 生成 VLESS over WebSocket 的链接
VLESS_LINK="vless://$uuid@vl$domain_name:443?encryption=none&security=tls&sni=vl$domain_name&alpn=h2&fp=chrome&type=ws&host=vl$domain_name&path=%2F$uuid-vl#$jiedian_name-vless"

# 生成 Trojan over WebSocket 的链接
TROJAN_LINK="trojan://$uuid@vl$domain_name:443?security=tls&sni=vl$domain_name&alpn=h2&fp=chrome&type=ws&host=vl$domain_name&path=%2F$uuid-tr#$jiedian_name-trojan"

# 生成clash配置
config="\  
  - name: $jiedian_name-vmess
    server: vm$domain_name
    port: 443
    type: vmess
    uuid: $uuid
    alterId: 0
    cipher: auto
    tls: true
    servername: vm$domain_name
    network: ws
    ws-opts:
      path: /$uuid-vm
      headers:
        Host: vm$domain_name
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
    sni: tr$domain_name
  - name: $jiedian_name-vless
    type: vless
    server: vl$domain_name
    port: 443
    uuid: $uuid
    cipher: none
    tls: true
    network: ws
    ws-opts:
      path: /$uuid-vl
      headers:
        Host: vl$domain_name"

# 输出链接
echo  "$VMESS_LINK"
echo  "$VLESS_LINK"
echo  "$TROJAN_LINK"
echo "------------------------------------------------------"
echo "------------------------------------------------------"
echo "clash配置trojan,vmess"
echo "$config"
