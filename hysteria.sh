
# 获取用户信息
read -p "请输入您的域名： " domain_name
read -p "请为结点命名,可任意输入： " jiedian_name
read -p "请输入您的 Cloudflare API 密钥: " api_key
read -p "请输入您的 Cloudflare 邮件地址: " email


# 安装必要的软件包
if [ -f /etc/debian_version ]; then
    apt-get update
    apt-get install -y curl unzip ufw wget || { echo "安装失败: curl unzip ufw wget"; exit 1; }

elif [ -f /etc/redhat-release ]; then
    yum install -y epel-release
    yum clean all
    yum makecache
    yum install -y curl unzip ufw wget || { echo "安装失败: curl unzip ufw wget"; exit 1; }
fi
# 生成节点名
declare -A flag_map
flag_map["法国"]="🇫🇷"
flag_map["英国"]="🇬🇧"
flag_map["美国"]="🇺🇸"
flag_map["新加坡"]="🇸🇬"
flag_map["德国"]="🇩🇪"
flag_map["澳大利亚"]="🇦🇺"
flag_map["日本"]="🇯🇵"
flag_map["加拿大"]="🇨🇦"
flag_map["韩国"]="🇰🇷"
flag_map["俄罗斯"]="🇷🇺"
flag_map["荷兰"]="🇳🇱"
flag_map["瑞士"]="🇨🇭"
flag_map["瑞典"]="🇸🇪"
flag_map["挪威"]="🇳🇴"
flag_map["南非"]="🇿🇦"
flag_map["印度"]="🇮🇳"
flag_map["西班牙"]="🇪🇸"
flag_map["丹麦"]="🇩🇰"
flag_map["芬兰"]="🇫🇮"
flag_map["爱尔兰"]="🇮🇪"
flag_map["波兰"]="🇵🇱"
flag_map["中国"]="🇨🇳"

#  获取地理位置信息
geo_info=$(curl -s ip.ping0.cc/geo)

# 提取国家信息
country=$(echo $geo_info | awk -F ' ' '{print $2}')

# 根据国家生成旗帜字符
if [[ ${flag_map[$country]+_} ]]; then
    flag="${flag_map[$country]}"
    jiedian_name="$flag CF | ${jiedian_name} "
fi

DR_jiedian_name=${jiedian_name/ CF | / DR | }

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

# 生成 UUID
uuid=$(cat /proc/sys/kernel/random/uuid)

# 安装hysteria
mkdir -p /home/hysteria
wget https://github.com/apernet/hysteria/releases/latest/download/hysteria-linux-amd64 -O /home/hysteria/hysteria-linux-amd64
chmod +x /home/hysteria/hysteria-linux-amd64

cat <<EOF > /home/hysteria/config.json
{
    "listen": ":19999",
    "cert": "/home/cert/$domain_name.crt",
    "key": "/home/cert/$domain_name.key",
    "up_mbps": 30,
    "down_mbps": 50,
    "obfs": "$uuid"
}
EOF

# 添加转发
iptables -t nat -A PREROUTING -p tcp --dport 20000:30000 -j REDIRECT --to-port 19999
iptables -t nat -A PREROUTING -p udp --dport 20000:30000 -j REDIRECT --to-port 19999
ip6tables -t nat -A PREROUTING -p tcp --dport 20000:30000 -j REDIRECT --to-port 19999
ip6tables -t nat -A PREROUTING -p udp --dport 20000:30000 -j REDIRECT --to-port 19999
#写入守护进程
mkdir -p /usr/lib/systemd/system/
cat <<EOF > /usr/lib/systemd/system/hysteria.service
[Unit]
Description=Hysteria

[Service]
Type=simple
GuessMainPID=true
WorkingDirectory=/home/hysteria
ExecStart=/home/hysteria/hysteria-linux-amd64 -config /home/hysteria/config.json server
Restart=always

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl start hysteria
systemctl enable hysteria
ufw default deny incoming
ufw default allow outgoing
ufw allow 22/tcp
ufw allow 19999
ufw allow 20000:30000/tcp
ufw allow 20000:30000/udp
yes | ufw enable
ufw reload

# 生成clash配置
config="\  
  - name: $HY_jiedian_name
    type: hysteria
    server: direct.$domain_name
    port: 19999
    ports: 20000-30000 #port 不可省略
    obfs: $uuid
    protocol: udp #支持 udp/wechat-video/faketcp
    up: 30
    down: 100
    sni: $domain_name"

# 输出链接
echo "$config"
