require 'config'
local match = string.match
local ngxmatch=ngx.re.find
local ngxlower = string.lower
local unescape=ngx.unescape_uri
local get_headers = ngx.req.get_headers
local optionIsOn = function (options) return options == "on" and true or false end
logpath = logdir
rulepath = RulePath
attacklog = optionIsOn(attacklog)
Redirect=optionIsOn(Redirect)
function getClientIp()
        IP = ngx.req.get_headers()["X-Real-IP"]
        if IP == nil then
                IP  = ngx.var.remote_addr
        end
        if IP == nil then
                IP  = "unknown"
        end
        return IP
end
function write(logfile,msg)
    local fd = io.open(logfile,"ab")
    if fd == nil then return end
    fd:write(msg)
    fd:flush()
    fd:close()
end
function log(method,url,data,ruletag)
    if attacklog then
        local realIp = getClientIp()
        local ua = ngx.var.http_user_agent
        local servername=ngx.var.server_name
        local time=ngx.localtime()
        if ua  then
            line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\"  \""..ua.."\" \""..ruletag.."\"\n"
        else
            line = realIp.." ["..time.."] \""..method.." "..servername..url.."\" \""..data.."\" - \""..ruletag.."\"\n"
        end
        local filename = logpath..'/'..servername.."_"..ngx.today().."_sec.log"
        write(filename,line)
    end
end
function ipToDecimal(ckip)
    local n = 4
    local num = 0
    local pos = 0
    for st, sp in function() return string.find(ckip, '.', pos, true) end do
        n = n - 1
        num = num + string.sub(ckip, pos, st-1) * (256 ^ n)
        pos = sp + 1
        if n == 1 then num = num + string.sub(ckip, pos, string.len(ckip)) end
    end
    return num
end
------------------------------------规则读取函数-------------------------------------------------------------------
function read_rule(var)
    file = io.open(rulepath..'/'..var,"r")
    if file==nil then
        return
    end
    t = {}
    for line in file:lines() do
        table.insert(t,line)
    end
    file:close()
    return(t)
end

urlrules=read_rule('url')
argsrules=read_rule('args')

function say_html()
    if Redirect then
        ngx.header.content_type = "text/html"
        ngx.say(html)
        ngx.exit(200)
    end
end

function say_html_warn()
    if Redirect then
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.header.content_type = "text/html"
        ngx.say(htmlWarn)
        ngx.exit(200)
    end
end

function say_html_error()
    if Redirect then
        ngx.status = ngx.HTTP_FORBIDDEN
        ngx.header.content_type = "text/html"
        ngx.say(htmlError)
        ngx.exit(200)
    end
end

function ckArgsConf(argsRule, cnt, sec)
    local counts = cnt or 0
    local seconds = sec or 0
    local arg = ''

    local st1, sp1 = string.find(argsRule, '#', 0, true)
    if st1 ~= nil then
        arg = string.sub(argsRule, 0, st1-1)
        local st2, sp2 = string.find(argsRule, '#', sp1 + 1, true)
        counts = tonumber(string.sub(argsRule, sp1 + 1, st2 - 1))
        seconds = tonumber(string.sub(argsRule, sp2 + 1, string.len(argsRule)))
    else
        arg = argsRule
    end
    return arg, counts, seconds
end

function ckArgs()
    for _,rule in pairs(argsrules) do
        local argrule, counts, seconds = ckArgsConf(rule, 100, 300)
        local args = ngx.req.get_uri_args()
        for key, val in pairs(args) do
            if key ~= nil and type(val) ~= 'table' then
                data = ngxlower(key.."="..val)
                if argrule ~="" and data == ngxlower(argrule) then
                    ckOverRate(argrule, counts, seconds)
                end
            end
        end
    end
    return false
end

-- check if the request was overrated
function ckOverRate(ckUriArg, counts, seconds)
    local uri=ngx.var.request_uri
    local redis = require "resty.redis"
    local red = redis:new()
    red:set_timeout(1000)
    local ok, err = red:connect(rdsHost, rdsPort)
    -- if redis connection failed, the real progress should going on.
    if not ok then
        log('GET',uri,"-",'redis: '..err)
    end
    local ua = ngx.var.http_user_agent
    local token = ngx.md5(getClientIp()..ua..uri..ckUriArg)
    token = "lua_rate_"..token
    local res, err = red:get(token)
    if res == ngx.null then
        ok, err = red:set(token, 1)
        if not ok then
            log('GET',uri,"-",'redis: '..err)
        end
        res = red:expire(token, seconds)
    elseif tonumber(res) < counts then
        red:incr(token)
    elseif tonumber(res) < counts * 2 then
        num = red:incr(token)
        if tonumber(num) == counts * 2 then
            red:expire(token, seconds * 50)
        end
        log('GET',uri,"-",'ckOverRate: warning of the rate')
        say_html_warn()
        return true
    else
        log('GET',uri,"-",'ckOverRate: error for exceed the rate : '..res)
        say_html_error()
        return true
    end
    return false
end

function ckUrl()
    for _,rule in pairs(urlrules) do
        if rule ~= "" then
            local url, counts, seconds = ckArgsConf(rule)
            if ngxmatch(ngx.var.uri,url,"imjo") then
                if counts ~= 0 then
                    ckOverRate(url, counts, seconds)
                    return false
                end
                return true
            end
        end
    end
    return false
end



function ckWhiteIp()
    if next(ipWhitelist) ~= nil then
        local cIP = getClientIp()
        local numIP = 0
        if cIP ~= "unknown" then numIP = tonumber(ipToDecimal(cIP))  end
        for _,ip in pairs(ipWhitelist) do
            local s, e = string.find(ip, '-', 0, true)
            if s == nil and cIP == ip then
                return true
            elseif s ~= nil then
                sIP = tonumber(ipToDecimal(string.sub(ip, 0, s - 1)))
                eIP = tonumber(ipToDecimal(string.sub(ip, e + 1, string.len(ip))))
                if numIP >= sIP and numIP <= eIP then
                   return true
                end
            end
        end
    end
    return false
end

function ckBlockIp()
    if next(ipBlocklist) ~= nil then
        local cIP = getClientIp()
        local numIP = 0
        if cIP ~= "unknown" then numIP = tonumber(ipToDecimal(cIP)) end
        for _,ip in pairs(ipBlocklist) do
            local s, e = string.find(ip, '-', 0, true)
            if s == nil and cIP == ip then
                log('GET',ngx.var.request_uri,"-",'ckBlockIp')
                ngx.exit(403)
                return true
            elseif s ~= nil then
                sIP = tonumber(ipToDecimal(string.sub(ip, 0, s - 1)))
                eIP = tonumber(ipToDecimal(string.sub(ip, e + 1, string.len(ip))))
                if numIP >= sIP and numIP <= eIP then
                    log('GET',ngx.var.request_uri,"-",'ckBlockIp')
                    ngx.exit(403)
                    return true
                end
            end
        end
    end
    return false
end
