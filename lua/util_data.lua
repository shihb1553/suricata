
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
