# xray-nginx  
------------------------------------------------------------------------------------------------------------------------
仅支持Ubuntu和debian,其他系统请自行修改
<div>
  <button class="btn" data-clipboard-target="#code"></button>
  <pre><code id="code" class="language-python">
  wget https://raw.githubusercontent.com/niylin/xray-nginxscript/main/test.sh && chmod +x test.sh && ./test.sh
  </code></pre>
</div>
未经过测试的版本,添加了centos7支持
<div>
  <button class="btn" data-clipboard-target="#code"></button>
  <pre><code id="code" class="language-python">
  wget https://raw.githubusercontent.com/niylin/xray-nginxscript/main/test1.sh && chmod +x test1.sh && ./test1.sh
  </code></pre>
</div>  

## xray一键安装脚本,nginx前置  
此脚本会卸载apache2和重装nginx.如不想卸载,请及时选n,5秒确认时间  
vless+ws+tls  
vmess+ws+tls  
Trojan+ws+tls  
shadowsocks+ws+tls  
  
### 自动解析  
通过cloud flare API申请证书,并解析到本地ip,选择ip规则为去除本地回环地址的第一个地址.自动解析不支持eu.org等免费域名  
四个伪装页面 视频页面,文件转换页面,小游戏页面,alist页面  
输入域名,cfapi,cf邮箱即可完成安装,自动申请通配符证书  
  
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
