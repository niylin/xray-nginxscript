# xray-nginx
仅支持Ubuntu和debian,其他系统请自行修改
<div>
  <button class="btn" data-clipboard-target="#code">Copy</button>
  <pre><code id="code" class="language-python">
  wget https://raw.githubusercontent.com/niylin/xray-nginxscript/main/test.sh && chmod +x test.sh && ./test.sh
  </code></pre>
</div>

xray一键安装脚本,nginx前置ws+tls,  
此脚本会卸载apache2和重装nginx.如不想卸载,请及时选n,5秒确认时间  
vless+ws+tls  
vmess+ws+tls  
Trojan+ws+tls  
shadowsocks+ws+tls  
证书仅添加cfapi申请  
四个伪装页面 视频页面,文件转换页面,小游戏页面,alist页面  
输入域名,cfapi,cf邮箱即可完成安装,自动申请通配符证书  
<div>
  <button class="btn" data-clipboard-target="#code">Copy</button>
  <pre><code id="code" class="language-python">
保存至本地删除
    59 #read -p "请输入您的 Cloudflare API 密钥: " api_key
    60 #read -p "请输入您的 Cloudflare 邮件地址: " email
</code></pre>
</div>
<div>
  <button class="btn" data-clipboard-target="#code">Copy</button>
  <pre><code id="code" class="language-python">
  修改"cfapi"和"email"为自己的即可
    71 #export CF_Key="cfapi"
    72 #export CF_Email="email"
</code></pre>
</div>
即可实现只输域名完成安装
