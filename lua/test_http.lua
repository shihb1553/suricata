package.path = 'var/lib/suricata/rules/?.lua;'

require("util_data")
require("util_action")

function init(args)
    local needs = {}
    -- needs["elimit"] = {1, 120}
    needs["efreq"] = {80}
    -- needs["http.request_line"] = tostring(true)
    return needs
end

function match(args)
    -- local a = tostring(args["http.request_line"])
    local a = util_data.get('http.request_line')
    local b = util_data.get('ip.dst')
    if util_data.dwordget(a, util_data.byteget(a,2)) ~= b then
        local c = util_data.get('payload')
        -- util_action.record2k("a.cap", 20, 20000, 20)
        -- util_action.event('r=', util_data.lower(c))
        -- util_action.usocket(12345678, "172.17.0.1", 9999)
        -- util_action.event('r=', util_data.base64e("qwertyuiop"))
        -- util_action.event('r=', util_data.hex(util_data.zip("qwertyuiop")))
        -- util_action.event('r=', util_data.hex(util_data.ungzip({0x1f, 0x8b, 0x08, 0x08, 0xfa,
        --     0xed, 0x5c, 0x68, 0x00, 0x03, 0x61, 0x61, 0x61, 0x2e, 0x74, 0x78, 0x74, 0x00, 0x4b,
        --     0x4c, 0x4a, 0x4e, 0x49, 0x4d, 0x4b, 0xe7, 0x02, 0x00, 0x24, 0x2a, 0x53, 0x0d, 0x08, 0x00, 0x00, 0x00})))
        -- util_action.event('r=', util_data.hex(util_data.undeflate({0x4b, 0x4c, 0x4a, 0x4e, 0x49, 0x4d, 0x4b, 0x07, 0x00})))
        util_action.event('r=', util_data.hex(util_data.charset({0xE4, 0xB8, 0xAD, 0xE5, 0x9B, 0xBD}, "UTF-8", "GBK"))) -- D6 D0 B9 FA
        return 1
    end
    return 0
end

return 0
