#!/bin/bash

distro=$(awk -F= '/^NAME/{print $2}' /etc/os-release)

if [[ "$distro" == *"Debian"* || "$distro" == *"Ubuntu"* ]]; then
    echo "检测到 Debian/Ubuntu 操作系统"
elif [[ "$distro" == *"CentOS Linux"* ]]; then
    echo "检测到 CentOS 操作系统"
else
    echo "不支持的操作系统: $distro"
    exit 1
fi

# Check if web server is installed
if pgrep -x "apache2" >/dev/null || pgrep -x "httpd" >/dev/null || pgrep -x "nginx" >/dev/null; then
    # Prompt user to uninstall web server
    read -t 5 -p "检测到已经安装了 Web 服务器，是否需要卸载？(y/n，默认5秒后自动选择卸载): " -n 1 -r uninstall_webserver || uninstall_webserver="y"
    echo ""

    if [[ $uninstall_webserver =~ ^[Yy]$ ]]
    then
        echo "开始卸载 Web 服务器..."
        pkill -9 apache2 httpd nginx

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
    apt-get install -y curl unzip lsof git ufw nginx
elif [ -f /etc/redhat-release ]; then
    yum install epel-release
    yum clean all
    yum makecache
    yum install -y curl unzip lsof git ufw nginx
fi

# 配置防火墙规则
ufw default deny incoming
ufw default allow outgoing
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 22/tcp
yes | ufw enable
ufw reload

# 获取用户输入的域名
read -p "请输入您的域名： " domain_name

read -p "请输入您的 Cloudflare API 密钥: " api_key
read -p "请输入您的 Cloudflare 邮件地址: " email

# 安装 acme.sh
curl https://get.acme.sh | sh -s email=$email

export CF_Key="$api_key"
export CF_Email="$email"

# 创建 acme.sh 命令别名
echo 'alias acme.sh=~/.acme.sh/acme.sh' >> ~/.bashrc

# 重新加载 .bashrc 文件
source ~/.bashrc

# 使用 Cloudflare API 请求 SSL 证书
mkdir -p /home/cert
~/.acme.sh/acme.sh --issue --dns dns_cf -d $domain_name -d "*.$domain_name"
~/.acme.sh/acme.sh --install-cert -d $domain_name \
    --key-file /home/cert/$domain_name.key \
    --fullchain-file /home/cert/$domain_name.crt

#自动添加解析
echo "请选择要解析的IP地址类型："
echo "[1] IPv6"
echo "[2] IPv4"
read -p "请输入选项数字: " ip_type_choice

if [ "$ip_type_choice" != "1" ] && [ "$ip_type_choice" != "2" ]; then
    echo "无效的选项，跳过添加 DNS 解析记录。"
else
    if [ $ip_type_choice -eq 1 ]; then
        # 如果选择IPv6，则获取本机IPv6地址
        ip_address=$(ip -6 addr show | grep inet6 | grep -v fe80 | awk '{if($2!="::1/128") print $2}' | cut -d"/" -f1 | head -n 1)
        record_type="AAAA"
    elif [ $ip_type_choice -eq 2 ]; then
        # 如果选择IPv4，则获取本机IPv4地址
        ip_address=$(ip -4 addr show | grep inet | grep -v '127.0.0.1' | awk '{print $2}' | cut -d "/" -f1 | head -n 1)
        record_type="A"
    fi

    # 获取 Zone ID
    zone_name=$(echo "${domain_name}" | awk -F '.' '{print $(NF-1)"."$NF}')
    if [ -z "$zone_name" ]; then
        echo "无效的域名提供，跳过添加 DNS 解析记录。"
    else
	zone_id=$(curl -s -X GET "https://api.cloudflare.com/client/v4/zones?name=${zone_name}" \
		-H "X-Auth-Email: ${CF_Email}" \
		-H "X-Auth-Key: ${CF_Key}" \
		-H "Content-Type: application/json" | grep -oP '(?<="id":")[^"]*' | head -n1)

        if [ -z "$zone_id" ]; then
            echo "无法获取域名 $domain_name 的区域 ID，跳过添加 DNS 解析记录。"
        else
            echo "您的区域 ID 为：$zone_id"

            echo "请选择 CDN 加速："
            echo "[1] 开启"
            echo "[2] 不开启"
            read -p "请输入选项数字: " cdn_choice

            if [ "$cdn_choice" == "1" ]; then
               cdn=true
            else
            cdn=false
            fi
            # 添加解析记录
            if curl -s -X POST "https://api.cloudflare.com/client/v4/zones/$zone_id/dns_records" \
              -H "X-Auth-Email: $CF_Email" \
              -H "X-Auth-Key: $CF_Key" \
              -H "Content-Type: application/json" \
              --data "{\"type\":\"$record_type\",\"name\":\"$domain_name\",\"content\":\"$ip_address\",\"ttl\":1,\"proxied\":$cdn}" > /dev/null; then
		      echo "域名解析成功！"
			  else
			  echo "域名解析失败,尝试手动添加。"
			fi
        fi
    fi
fi

# 生成 UUID
uuid=$(cat /proc/sys/kernel/random/uuid)

# 创建 nginx 配置文件
cat <<EOF > /etc/nginx/conf.d/$domain_name.conf
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    ssl_certificate /home/cert/$domain_name.crt;
    ssl_certificate_key /home/cert/$domain_name.key;
    ssl_protocols         TLSv1.3;
    ssl_ecdh_curve        X25519:P-256:P-384:P-521;
    server_name           $domain_name;
    index index.html index.htm;
    root  /home/www/shipin1;
    error_page 400 = /400.html;

    ssl_early_data on;
    ssl_stapling on;
    ssl_stapling_verify on;
    add_header Strict-Transport-Security "max-age=63072000" always;

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

    location /$uuid-vl {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10002;
        proxy_http_version 1.1;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host \$http_host;
        # Config for 0-RTT in TLSv1.3
        proxy_set_header Early-Data \$ssl_early_data;
    }
    
    location /$uuid-tr {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10003;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection upgrade;
        proxy_set_header Host \$http_host;
        #proxy_set_header X-Real-IP \$remote_addr;
        #proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location /$uuid-ss {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:10004;
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
            mkdir -p /home/www
            wget https://github.com/niylin/xray-nginxscript/releases/download/nhg/shipin1.zip -O /home/www/shipin1.zip
            unzip /home/www/shipin1.zip -d /home/www
            sed -i "s|root  /home/www/shipin1;|root  /home/www/shipin1;|" /etc/nginx/conf.d/$domain_name.conf
            break
            ;;
        2)
            mkdir -p /home/www
            wget https://github.com/niylin/xray-nginxscript/releases/download/nhg/mikutap.zip -O /home/www/mikutap.zip
            unzip /home/www/mikutap.zip -d /home/www

            sed -i "s|root  /home/www/shipin1;|root  /home/www/mikutap;|" /etc/nginx/conf.d/$domain_name.conf
            break
            ;;
        3)
            mkdir -p /home/www
            wget https://github.com/niylin/xray-nginxscript/releases/download/nhg/zhuanhuan.zip -O /home/www/zhuanhuan.zip
            unzip /home/www/zhuanhuan.zip -d /home/www
            sed -i "s|root  /home/www/shipin1;|root  /home/www/zhuanhuan;|" /etc/nginx/conf.d/$domain_name.conf
            break
            ;;
        4)
            curl -fsSL "https://alist.nn.ci/v3.sh" | bash -s install
            sed -i "s|aaaaidddddaa125647|location / {\n        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto \$scheme;\n        proxy_set_header Host \$http_host;\n        proxy_set_header X-Real-IP \$remote_addr;\n        proxy_set_header Range \$http_range;\n        proxy_set_header If-Range \$http_if_range;\n        proxy_redirect off;\n        proxy_pass http://127.0.0.1:5244;\n        client_max_body_size 20000m;\n\t}|" /etc/nginx/conf.d/$domain_name.conf
# 为alist添加虚拟驱动
            wget https://github.com/niylin/xray-nginxscript/releases/download/nhg/data.tar.gz -P /opt/alist
            tar -xzf /opt/alist/data.tar.gz -C /opt/alist/data --strip-components=3 --overwrite
            systemctl restart alist
            break
            ;;
        *)
            echo "无效的选项，请输入[1/2/3/4]中的一个。"
            ;;
    esac
done

sed -i 's|aaaaidddddaa125647||g' /etc/nginx/conf.d/$domain_name.conf

# 安装 xray
# bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

   echo "安装xray..."
	mkdir -p /home/xray
	wget https://github.com/XTLS/Xray-core/releases/latest/download/Xray-linux-64.zip -O /home/xray/Xray-linux-64.zip
	unzip /home/xray/Xray-linux-64.zip -d /home/xray

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
        },
        {
            "port":10004,
            "listen":"127.0.0.1",
            "protocol":"shadowsocks",
            "settings":{
                "clients":[
                    {
                        "method":"chacha20-ietf-poly1305",
                        "password":"$uuid"
                    }
                ],
                "decryption":"none"
            },
            "streamSettings":{
                "network":"ws",
                "wsSettings":{
                    "path":"/$uuid-ss"
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
#写入守护进程
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
# 重启 xray 和 nginx
systemctl daemon-reload
systemctl start xray
systemctl enable xray
systemctl restart nginx

# 生成 VMESS over WebSocket 的链接
VMESS_LINK="vmess://$(echo -n '{"v":"2","ps":"-vmess","add":"'$domain_name'","port":"443","id":"'$uuid'","aid":"0","scy":"none","net":"ws","type":"none","host":"'$domain_name'","path":"/'$uuid'-vm","tls":"tls","sni":"'$domain_name'","alpn":"h2","fp":"chrome"}' | base64 -w 0)"

# 生成 VLESS over WebSocket 的链接
VLESS_LINK="vless://$uuid@$domain_name:443?encryption=none&security=tls&sni=$domain_name&alpn=h2&fp=chrome&type=ws&host=$domain_name&path=%2F$uuid-vl#-vless"

# 生成 Trojan over WebSocket 的链接
TROJAN_LINK="trojan://$uuid@$domain_name:443?security=tls&sni=$domain_name&alpn=h2&fp=chrome&type=ws&host=$domain_name&path=%2F$uuid-tr#-trojan"

# 生成 Shadowsocks 的链接
Shadowsocks_LINK=$(echo -n "chacha20-ietf-poly1305:${uuid}@${domain_name}:443" | base64 -w 0)

# 生成clash配置
config="\  
  - name: -vmess
    server: $domain_name
    port: 443
    type: vmess
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
  - name: -trojan
    server: $domain_name
    port: 443
    type: trojan
    tls: true
    servername: $domain_name
    network: ws
    ws-opts:
      path: /$uuid-tr
    password: $uuid
    sni: $domain_name"
# 输出链接
echo "------------------------------------------------------" > /root/link.conf
echo "------------------------------------------------------" >> /root/link.conf
echo  "$VMESS_LINK" >> /root/link.conf
echo  "$VLESS_LINK" >> /root/link.conf
echo  "$TROJAN_LINK" >> /root/link.conf
echo  "ss://${Shadowsocks_LINK}#$jiedianname_encoded-shadowsocks" >> /root/link.conf
echo  "Shadowsocks需要手动添加tls信息" >> /root/link.conf
echo  "sspath=/$uuid-ss" >> /root/link.conf
echo  "开启ws, tls ,四种协议除path外其他参数均相同" >> /root/link.conf
echo "------------------------------------------------------" >> /root/link.conf
echo "------------------------------------------------------" >> /root/link.conf
echo "clash配置Trojan,vmess" >> /root/link.conf
echo "$config" >> /root/link.conf
echo "------------------------------------------------------" >> /root/link.conf
echo "------------------------------------------------------" >> /root/link.conf
echo  "Shadowsocks需要手动添加tls信息" >> /root/link.conf
echo  "sspath=/$uuid-ss" >> /root/link.conf
echo  "开启ws, tls ,四种协议除path外其他参数均相同" >> /root/link.conf

# 输出链接
echo "------------------------------------------------------"
echo "------------------------------------------------------"
echo  "$VMESS_LINK"
echo  "$VLESS_LINK"
echo  "$TROJAN_LINK"
echo  "ss://${Shadowsocks_LINK}#$jiedianname_encoded-shadowsocks"
echo  "Shadowsocks需要手动添加tls信息"
echo  "sspath=/$uuid-ss"
echo  "开启ws, tls ,四种协议除path外其他参数均相同"
echo "------------------------------------------------------"
echo "------------------------------------------------------"
echo "clash配置Trojan,vmess"
echo "$config"
echo "------------------------------------------------------"
echo "------------------------------------------------------"
echo  "此配置保存在/root/link.conf"
echo  "脚本会自动开启80,443,22端口,安装curl,git,lsof,ufw,unzip"
echo "------------------------------------------------------"
echo "------------------------------------------------------"
echo "如果访问伪装页面失败,尝试使用以下命令手动重启ufw及nginx"
echo "重启ufw:    ufw reload"
echo "重启nginx:  systemctl restart nginx"
echo "重启xray:   systemctl restart xray"
