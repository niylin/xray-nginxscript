# xray-nginx  
------------------------------------------------------------------------------------------------------------------------
支持系统 Ubuntu,debian,centos7
<div>
  <button class="btn" data-clipboard-target="#code"></button>
  <pre><code id="code" class="language-python">
  wget https://raw.githubusercontent.com/niylin/xray-nginxscript/main/test.sh && chmod +x test.sh && ./test.sh
  </code></pre>
</div>

## xray一键安装脚本,nginx前置  
请确保10001-10004端口未被占用  
此脚本会卸载apache和nginx.如不想卸载,请及时选n,5秒确认时间  
vless+ws+tls  
vmess+ws+tls  
Trojan+ws+tls  
shadowsocks+ws+tls  
四个伪装页面 视频页面,文件转换页面,小游戏页面,alist页面  
 
### 自动解析  
通过cloud flare API申请证书,并解析到本地ip,选择ip规则为去除本地回环地址的第一个地址.自动解析不支持eu.org等免费域名  
输入域名,cfapi,cf邮箱即可完成安装,自动申请通配符证书  
  
####  
证书/home/cert  
站点/home/www  
xray配置文件/usr/local/etc/xray  
  
##### 使用其他证书,跳过api环节,修改nginx配置即可  

#### 修改个人信息,以减少输入内容,请更改以下内容  
<div>
  <button class="btn" data-clipboard-target="#code"></button>
  <pre><code id="code" class="language-python">
    删除以下行
    59 #read -p "请输入您的 Cloudflare API 密钥: " api_key
    60 #read -p "请输入您的 Cloudflare 邮件地址: " email
</code></pre>
</div>
<div>
  <button class="btn" data-clipboard-target="#code"></button>
  <pre><code id="code" class="language-python">
    修改"cfapi"和"email"为自己的即可
    65 #export CF_Key="cfapi"
    66 #export CF_Email="email"
</code></pre>
</div>
