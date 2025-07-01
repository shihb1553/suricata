
util_data = {}

function util_data.dwordget(data, offset)
    if data == nil or offset + 3 > #data then
        return nil
    end
    return string.byte(data, offset) * 16777216 + string.byte(data, offset + 1) * 65536 + string.byte(data, offset + 2) * 256 + string.byte(data, offset + 3)
end

function util_data.dwordget2(data, offset)
    if data == nil or offset + 3 > #data then
        return nil
    end
    return string.byte(data, offset) + string.byte(data, offset + 1) * 256 + string.byte(data, offset + 2) * 65536 + string.byte(data, offset + 3) * 16777216
end

function util_data.wordget(data, offset)
    if data == nil or offset + 1 > #data then
        return nil
    end
    return string.byte(data, offset) * 256 + string.byte(data, offset + 1)
end

function util_data.wordget2(data, offset)
    if data == nil or offset + 1 > #data then
        return nil
    end
    return string.byte(data, offset) + string.byte(data, offset + 1) * 256
end

function util_data.byteget(data, offset)
    if data == nil or offset > #data then
        return nil
    end
    return string.byte(data, offset)
end

function util_data.get(key)
    if key == 'ip.dst' then
        ip_version, src_ip, dst_ip, protocol, src_port, dst_port = SCPacketTuple()
        return dst_ip
    elseif key == 'ip.src' then
        ip_version, src_ip, dst_ip, protocol, src_port, dst_port = SCPacketTuple()
        return src_ip
    elseif key == 'payload' then
        return SCPacketPayload()
    elseif key == 'http.request_line' then
        return HttpGetRequestLine()
    elseif key == 'http.response_line' then
        return HttpGetResponseLine()
    elseif key == 'http.host' then
        return HttpGetRequestHost()
    elseif key == 'http.uri' then
        return HttpGetRequestUriNormalized()
    end
    return nil
end

function util_data.hex(data)
    local result = {}
    for i = 1, #data do
        table.insert(result, string.format("\\x%02X", string.byte(data, i)))
    end
    return table.concat(result)
end

local base64 = require('base64')
function util_data.base64d(str)
    return base64.decode(str)
end

function util_data.base64e(str)
    return base64.encode(str)
end

function util_data.zip(str)
    return SCStrZip(str)
end

function util_data.unzip(data)
    return SCUnzip(data)
end

function util_data.ungzip(data)
    return SCUngzip(data)
end

function util_data.undeflate(data)
    local a, msg = SCUndeflate(data)
    if a == nil then
        print(msg)
    end
    return a
end

function util_data.charset(data, src, dst)
    return SCCharset(data, src, dst)
end

function util_data.sequence(str, op, ...)
    local args = {...}
    if op == '==' then
        local start_index, _ = string.find(str, table.concat(args, ''), 1, true)
        if start_index == 1 then
            return true
        end
    elseif op == '*=' then
        local start_index, _ = string.find(string.lower(str), string.lower(table.concat(args, '')), 1, true)
        if start_index == 1 then
            return true
        end
    elseif op == '^' then
        local init = 1
        for _, value in ipairs(args) do
            local start_index, stop_index = string.find(str, value, init, true)
            if start_index == nil then
                return false
            end
            init = stop_index + 1
        end
        return true
    elseif op == '*^' then
        local init = 1
        for _, value in ipairs(args) do
            local start_index, stop_index = string.find(string.lower(str), string.lower(value), init, true)
            if start_index == nil then
                return false
            end
            init = stop_index + 1
        end
        return true
    end
    return false
end

util_data.ST_CMD = 1
util_data.ST_ALL = 2
util_data.ST_NONE = 4
util_data.ST_SHUF = 8
function util_data.stoken(str, mask, ...)
    local args = {...}
    local result = {}
    -- local str = HttpGetRequestLine()
    if str == nil then
        return false
    end
    if mask[util_data.ST_CMD] == true then
        local start_index, end_index = string.find(str, args[1] .. '?', 1, true)
        if start_index == nil then
            return false
        end
        table.remove(args, 1)
        str = string.sub(str, end_index + 1)
    else
        local start_index, end_index = string.find(str, '?', 1, true)
        if start_index == nil then
            return false
        end
        str = string.sub(str, end_index + 1)
    end
    if str == nil then
        return false
    end

    local init = 1
    while true do
        local start_index, end_index = string.find(str, '=', init, true)
        if start_index == nil then
            break
        end
        local part = string.sub(str, init, start_index - 1)
        table.insert(result, part)
        local delime_index, _ = string.find(str, '&', end_index, true)
        if delime_index == nil then
            break
        end
        init = delime_index + 1
    end

    print('result: ', #result)
    print('args: ', #args)

    if mask[util_data.ST_ALL] == true and #result ~= #args then
        return false
    end

    if mask[util_data.ST_SHUF] == true then
        table.sort(result)
        table.sort(args)
    end

    for i = 1, #args do
        if result[i] ~= args[i] then
            return false
        end
    end
    return true
end

function util_data.sarray(str, op, ...)
    local args = {...}
    for _, value in ipairs(args) do
        if op == '==' and string.find(str, value, 1, true) == 1 then
            return true
        elseif op == '*=' and string.find(string.lower(str), string.lower(value), 1, true) == 1 then
            return true
        elseif op == '^' and string.find(str, value, 1, true) ~= nil then
            return true
        elseif op == '*^' and string.find(string.lower(str), string.lower(value), 1, true) ~= nil then
            return true
        elseif op == '^^' then
            local _, end_index = string.find(str, value, 1, true)
            if end_index == #str then
                return true
            end
        end
    end
    return false
end

function util_data.iparray(ip, op, ...)
    local args = {...}
    for _, value in ipairs(args) do
        if op == '==' and ip == value then
            return true
        end
    end
    return false
end

function util_data.narray(num, op, ...)
    local args = {...}
    for _, value in ipairs(args) do
        if op == '==' and num == value then
            return true
        end
    end
    return false
end

return util_data
