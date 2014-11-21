RulePath = "/usr/local/nginx/conf/lua/rule_conf/"
logdir = "/data/logs/nginx/"
attacklog = "on"
Redirect = "on"
rdsHost = "192.168.1.2"
rdsPort = 6381
ipWhitelist = {"127.0.0.1","192.168.1.0-192.168.1.255"}
ipBlocklist = {"1.0.0.1","2.0.0.0-2.0.0.255"}
html = [[please go awary ~~]]
htmlWarn = [[<a href="http://www.xx.com">点击这里</a>访问网站<a href="http://www.xx.com">首页</a>]]
htmlError = [[some evil l.u.a, please try the page later. ]]
