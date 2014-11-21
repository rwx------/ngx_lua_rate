-- whether in white ip list
if ckBlockIp() then
    say_html_error()
elseif not ckWhiteIp() then
    -- the url need check
    if ckUrl() then
        -- the args need check
        ckArgs()
    end
end
