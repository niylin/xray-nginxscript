
------------------------------------------------------------------------------------------------------------------------
支持系统 Ubuntu,debian,
<div>
  <button class="btn" data-clipboard-target="#code"></button>
  <pre><code id="code" class="language-python">
  wget https://raw.githubusercontent.com/niylin/xray-nginxscript/main/sb-nginx.sh && chmod +x test.sh && ./test.sh
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
 

请确保10001-10004和443端口未被占用  
此脚本会卸载apache和nginx.如不想卸载,请及时选n,5秒确认时间  

vless+reality

vmess+ws+tls  

Trojan+ws+tls  

hysteria2

wireguard

四个伪装页面 视频页面,文件转换页面,小游戏页面,alist页面  
 
### 自动解析  
通过cloud flare API申请证书,并解析到本地ip,
输入域名,cfapi,cf邮箱即可完成安装,自动申请通配符证书 并添加两条解析记录,一个开启cdn,一个直连 
  



