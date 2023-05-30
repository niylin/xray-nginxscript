# xray-nginx  
------------------------------------------------------------------------------------------------------------------------
支持系统 Ubuntu,debian,centos7 
<div>
  <button class="btn" data-clipboard-target="#code"></button>
  <pre><code id="code" class="language-python">
  wget https://raw.githubusercontent.com/niylin/xray-nginxscript/main/test.sh && chmod +x test.sh && ./test.sh
  </code></pre>
</div>

仅申请证书和解析
<div>
  <button class="btn" data-clipboard-target="#code"></button>
  <pre><code id="code" class="language-python">
  wget https://raw.githubusercontent.com/niylin/xray-nginxscript/main/cfacme.sh && chmod +x cfacme.sh && ./cfacme.sh
  </code></pre>
</div>
使用argo搭建,选择内置域名和证书为一键完成,不需要公网ip和通用端口,机器可以访问网络就可以使用
<div>
  <button class="btn" data-clipboard-target="#code"></button>
  <pre><code id="code" class="language-python">
  wget https://raw.githubusercontent.com/niylin/xray-nginxscript/main/argo.sh && chmod +x argo.sh && ./argo.sh
  </code></pre>
</div>
## xray一键安装脚本,nginx前置,包含fscarmen的wgcf安装  

请确保10001-10004端口未被占用  
此脚本会卸载apache和nginx.如不想卸载,请及时选n,5秒确认时间  

vless+ws+tls  

vmess+ws+tls  

Trojan+ws+tls  

shadowsocks+ws+tls  

四个伪装页面 视频页面,文件转换页面,小游戏页面,alist页面  
 
### 自动解析  
通过cloud flare API申请证书,并解析到本地ip,选择ip规则为去除本地回环地址的第一个地址.  
输入域名,cfapi,cf邮箱即可完成安装,自动申请通配符证书 并添加两条解析记录,一个开启cdn,一个直连 
  
####  
xray安装目录/home/xray  
证书保存目录/home/cert  
伪装站点目录/home/www  
  
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
