# xray-nginxs

xray一键安装脚本,nginx前置ws+tls,
vless+ws+tls
vmess+ws+tls
Trojan+ws+tls
shadowsocks+ws+tls
证书仅添加了通过cfapi申请
四个伪装页面 视频页面,文件转换页面,小游戏页面,alist页面
只需要输入域名,cfapi,cf邮箱即可完成安装,自动申请通配符证书

保存至本地删除
    52#read -p "请输入您的 Cloudflare API 密钥: " api_key
    53#read -p "请输入您的 Cloudflare 邮件地址: " email
修改
    64#export CF_Key="cfapi"
    65#export CF_Email="email"

即可实现只输域名完成安装
