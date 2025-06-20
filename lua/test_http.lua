package.path = 'var/lib/suricata/rules/?.lua;'

require("util_data")
require("util_action")

function init (args)
    local needs = {}
    -- needs["http.request_line"] = tostring(true)
    return needs
end

function match(args)
    -- local a = tostring(args["http.request_line"])
    local a = util_data.get('http.request_line')
    local b = util_data.get('ip.dst')
    if util_data.dwordget(a, util_data.byteget(a,2)) ~= b then
        local c = util_data.get('payload')
        util_action.record2k("a.cap", 20, 20000, 20)
        -- util_action.event('r=', util_data.lower(c))
        return 1
    end
    return 0
end

return 0
