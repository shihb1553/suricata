
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
