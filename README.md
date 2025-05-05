
------------------------------------------------------------------------------------------------------------------------
支持系统 Ubuntu,debian,
<div>
  <button class="btn" data-clipboard-target="#code"></button>
  <pre><code id="code" class="language-python">
  wget https://raw.githubusercontent.com/niylin/proxy-nginx/main/sb-nginx.sh && chmod +x test.sh && ./test.sh
  </code></pre>
</div>

vless+reality

vmess+ws+tls  

Trojan+ws+tls  

hysteria2

wireguard

四个伪装页面 视频页面,文件转换页面,小游戏页面,alist页面  

仅申请证书和解析
<div>
  <button class="btn" data-clipboard-target="#code"></button>
  <pre><code id="code" class="language-python">
  wget https://raw.githubusercontent.com/niylin/proxy-nginx/main/cfacme.sh && chmod +x cfacme.sh && ./cfacme.sh
  </code></pre>
</div>
使用argo搭建,选择内置域名和证书为一键完成,不需要公网ip和通用端口,机器可以访问网络就可以使用
<div>
  <button class="btn" data-clipboard-target="#code"></button>
  <pre><code id="code" class="language-python">
  wget https://raw.githubusercontent.com/niylin/proxy-nginx/main/argo.sh && chmod +x argo.sh && ./argo.sh
  </code></pre>
</div>
 

 
### 自动解析  
通过cloud flare API申请证书,并解析到本地ip,
输入域名,cfapi,cf邮箱即可完成安装,自动申请通配符证书 并添加两条解析记录,一个开启cdn,一个直连 
  



