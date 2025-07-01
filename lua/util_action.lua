
util_action = {}

function util_action.event(...)
    local args = {...}
    if #args == 0 then
        return nil
    elseif #args == 1 then
        SCDetectCustomDataSet('nil', args[1])
    elseif #args % 2 ~= 0 then
        return nil
    end
    local key = "nil"
    for i, v in ipairs(args) do
        if i % 2 == 1 then
            key = v
        else
            SCDetectCustomDataSet(key, args[i])
        end
    end
    return nil
end

function util_action.eventr(...)
    local args = {...}
    table.insert(args, "reverse")
    table.insert(args, "true")
    return util_action.event(unpack(args)) -- for luajit lua5.1
end

function util_action.nothing()
    return nil
end

function util_action.usocket(id, ip, port)
    return SCUSocketSet(id, ip, port)
end

local function record(type, fmt, packets, bytes, seconds)
    if bytes ~=0 and bytes >= 20000000 then
        return nil
    end
    if seconds ~= 0 and seconds >= 172800 then
        return nil
    end
    return SCRecordSet(type, fmt, packets, bytes, seconds)
end

function util_action.mtcpdump(fmt, packets, bytes, seconds)
    return record("one-packet", fmt, packets, bytes, seconds)
end

function util_action.record2k(fmt, packets, bytes, seconds)
    return record("ippairs", fmt, packets, bytes, seconds)
end

function util_action.record5k(fmt, packets, bytes, seconds)
    return record("session", fmt, packets, bytes, seconds)
end

return util_action
