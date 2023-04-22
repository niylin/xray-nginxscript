#!/bin/bash

# 提示用户选择是否卸载 Apache2
read -t 5 -p "是否需要卸载 Apache2？(y/n，默认5秒后自动选择卸载): " -n 1 -r uninstall_apache2
echo ""

if [[ $uninstall_apache2 =~ ^[Yy]$ ]]
then
   echo "开始卸载 apache2..."
   apt update
   systemctl stop apache2
   pkill -9 apache2
   apt purge -y apache2
   apt purge -y apache2.2-common
fi

# 提示用户选择是否重装 Nginx
echo  "建议重装 Nginx"
read -t 5 -p "是否需要重装 Nginx？(y/n，默认5秒后自动选择重装): " -n 1 -r reinstall_nginx
echo ""
if [[ $reinstall_nginx =~ ^[Yy]$ ]]
then
   echo "开始卸载并重装 Nginx..."
   systemctl stop nginx
   pkill -9 nginx
   apt purge -y nginx
   apt install -y nginx
fi

# 安装 ufw
apt install -y curl
apt install -y git
apt install -y lsof
apt install -y ufw

# 设置默认规则
ufw default deny incoming
ufw default allow outgoing

# 开启 80、443 和 22 端口
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 22/tcp

# 启用 ufw 并重载规则
yes | ufw enable
ufw reload

# 获取用户输入的域名
read -p "请输入您的域名： " domain_name

read -p "请输入您的 Cloudflare API 密钥: " api_key
read -p "请输入您的 Cloudflare 邮件地址: " email

# 安装 acme.sh
curl https://get.acme.sh | sh -s email=$email

# 创建 acme.sh 命令别名
echo 'alias acme.sh=~/.acme.sh/acme.sh' >> ~/.bashrc

# 重新加载 .bashrc 文件
source ~/.bashrc

export CF_Key="$api_key"
export CF_Email="$email"
            
# 使用 Cloudflare API 请求 SSL 证书
~/.acme.sh/acme.sh --issue --dns dns_cf -d $domain_name -d "*.$domain_name"

~/.acme.sh/acme.sh --install-cert -d $domain_name \
    --key-file /home/cert.key \
    --fullchain-file /home/cert.crt

# 生成 UUID
uuid=$(cat /proc/sys/kernel/random/uuid)

cat <<EOF > /etc/nginx/sites-enabled/$domain_name.conf
server {
    listen 443 ssl http2;
    listen [::]:443 ssl http2;
    ssl_certificate       /home/cert.crt;
    ssl_certificate_key   /home/cert.key;
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
        proxy_pass http://127.0.0.1:10000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection upgrade;
        proxy_set_header Host \$http_host;
        #proxy_set_header X-Real-IP \$remote_addr;
        #proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location /$uuid-vl {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:20000;
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
        proxy_pass http://127.0.0.1:30000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade \$http_upgrade;
        proxy_set_header Connection upgrade;
        proxy_set_header Host \$http_host;
        #proxy_set_header X-Real-IP \$remote_addr;
        #proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    
    location /$uuid-ss {
        proxy_redirect off;
        proxy_pass http://127.0.0.1:40000;
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
            git clone https://github.com/niylin/shipin1.git /home/www/shipin1
            sed -i "s|root  /home/www/shipin1;|root  /home/www/shipin1;|" /etc/nginx/sites-enabled/$domain_name.conf
            break
            ;;
        2)
            git clone https://github.com/HFIProgramming/mikutap.git /home/www/mikutap
            sed -i "s|root  /home/www/shipin1;|root  /home/www/mikutap;|" /etc/nginx/sites-enabled/$domain_name.conf
            break
            ;;
        3)
            git clone https://github.com/niylin/wenjian.git /home/www/wenjian
            sed -i "s|root  /home/www/shipin1;|root  /home/www/wenjian;|" /etc/nginx/sites-enabled/$domain_name.conf
            break
            ;;
        4)
            curl -fsSL "https://alist.nn.ci/v3.sh" | bash -s install
            sed -i "s|aaaaidddddaa125647|location / {\n        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto \$scheme;\n        proxy_set_header Host \$http_host;\n        proxy_set_header X-Real-IP \$remote_addr;\n        proxy_set_header Range \$http_range;\n        proxy_set_header If-Range \$http_if_range;\n        proxy_redirect off;\n        proxy_pass http://127.0.0.1:5244;\n        client_max_body_size 20000m;\n\t}|" /etc/nginx/sites-enabled/$domain_name.conf
            break
            ;;
        *)
            echo "无效的选项，请输入[1/2/3/4]中的一个。"
            ;;
    esac
done

sed -i 's|aaaaidddddaa125647||g' /etc/nginx/sites-enabled/$domain_name.conf

# 安装 xray
bash -c "$(curl -L https://github.com/XTLS/Xray-install/raw/main/install-release.sh)" @ install

# 修改 xray 配置文件
cat <<EOF > /usr/local/etc/xray/config.json
{
    "inbounds":[
        {
            "port":10000,
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
            "port":20000,
            "listen":"127.0.0.1",
            "protocol":"vless",
            "settings": {
              "clients": [
                {
                  "id": "$uuid",
                  "flow": "xtls-rprx-direct"
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
            "port":30000,
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
            "port":40000,
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

# 重启 xray 和 nginx
systemctl restart xray
systemctl restart nginx

# 生成 VLESS over WebSocket 的链接
VLESS_LINK="vless://$uuid@$domain_name:443?encryption=none&security=tls&sni=$domain_name&alpn=h2&fp=chrome&type=ws&host=$domain_name&path=%2F$uuid-vl"

# 生成 Trojan over WebSocket 的链接
TROJAN_LINK="trojan://$uuid@$domain_name:443?security=tls&sni=$domain_name&alpn=h2&fp=chrome&type=ws&host=$domain_name&path=%2F$uuid-tr"

# 输出链接
echo  "$VLESS_LINK" > /root/link.conf
echo  "" >> /root/link.conf
echo  "$TROJAN_LINK" >> /root/link.conf
echo  "" >> /root/link.conf
echo  "uuid=$uuid" >> /root/link.conf
echo  "server=$domain_name:443" >> /root/link.conf
echo  "vmesspath=/$uuid-vm" >> /root/link.conf
echo  "shadowsockspath=/$uuid-ss" >> /root/link.conf
echo  "开启ws, tls ,四种协议除path外其他参数均相同" >> /root/link.conf
echo  "此配置保存在/root/link.conf" >> /root/link.conf

# 输出链接
echo  "$VLESS_LINK"
echo  ""
echo  "$TROJAN_LINK"
echo  ""
echo  "uuid=$uuid"
echo  "server=$domain_name:443"
echo  "vmesspath=/$uuid-vm"
echo  "shadowsockspath=/$uuid-ss"
echo  "开启ws, tls ,四种协议除path外其他参数均相同"
echo  "此配置保存在/root/link.conf"
echo  "脚本会自动开启80,443,22端口,安装curl,git,lsof,ufw"
echo "           ,     ,\n";
echo "           (\\____/)\n";
echo "            (_oo_)\n";
echo "              (O)\n";
echo "            __||__    \\)\n";
echo "         []/______\\[] /\n";
echo "         / \\______/ \\/\n";
echo "        /    /__\\\n";
echo "       (\\   /____\\\n";

