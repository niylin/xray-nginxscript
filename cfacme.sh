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

    original_domain_name=$domain_name
    # 构造 curl 请求 URL 和头部信息
    curl_url="https://api.cloudflare.com/client/v4/zones?name=${original_domain_name}"
    curl_head=(
        "X-Auth-Email: ${CF_Email}"
		  	"X-Auth-Key: ${CF_Key}"
		  	"Content-Type: application/json"
		    )

		# 发送 curl 请求并解析响应结果
		response_json_str=$(curl -sS --request GET "${curl_url}" --header "${curl_head[0]}" --header "${curl_head[1]}" --header "${curl_head[2]}")
		zone_id=$(echo "${response_json_str}" | jq -r '.result[0].id')

			if [ ! -z "$zone_id" ]; then
			echo "您的区域 ID 为：$zone_id"
			fi

		# 拆分域名并依次查询每个子域名的区域 ID
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
