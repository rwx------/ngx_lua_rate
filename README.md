ngx_lua_rate
============

功能
----

1.	针对不同的url, 采用不同的过滤控制频率
2.	针对不同的url参数, 采用不同的过滤控制频率
3.	采用两级灰度机制, 针对不同的频率做出不同的反应
4.	有白名单/黑名单机制
5.	白名单和黑名单可以写成ip段

注: 需依赖[lua-nginx-module](https://github.com/openresty/lua-nginx-module)和[lua-resty-redis](https://github.com/openresty/lua-resty-redis)

配置
----

```
http {
  lua_package_path "/opt/app/nginx/conf/lua/?.lua";
  init_by_lua_file  /opt/app/nginx/conf/lua/init.lua;

  server {
    ...
    # lua_code_cache off; # 在lua脚本调试模式下使用
    access_by_lua_file /opt/app/nginx/conf/lua/rate_limit.lua;
    ...
  }
}
```

todo
----

1.	防御cc攻击
2.	进入灰1阶段次数统计
3.	按进入灰1节点次数入ip黑名单
4.	黑名单里ip的过期时间

说明
----

本程序原型为 [loveshell/ngx_lua_waf](https://github.com/loveshell/ngx_lua_waf) , 在此基础上进行的修改.
