-- test_string.lua
local lu = require('luaunit')
local util_data = require('util_data')

TestDataUtils = {} -- 测试套件

function TestDataUtils:setUp()
    -- 每个测试前的设置
    self.test_str = "Hello World"
end

function TestDataUtils:tearDown()
    -- 每个测试后的清理
    self.test_str = nil
end

function TestDataUtils:test_sequence()
    lu.assertEquals(util_data.sequence("db=db_server=db_port=", "==", "db=", "db_server=", "db_port="), true)
    lu.assertEquals(util_data.sequence("aaadb=db_server=db_port=", "==", "db=", "db_server=", "db_port="), false)
    lu.assertEquals(util_data.sequence("db=db_server=adb_port=", "==", "db=", "db_server=", "db_port="), false)
    lu.assertEquals(util_data.sequence("db=dB_server=db_port=", "*=", "db=", "db_server=", "db_port="), true)

    lu.assertEquals(util_data.sequence("php?db=aaaa&db_server=bbbbb&db_port=CCCCC", "^", "db=", "db_server=", "db_port="), true)
    lu.assertEquals(util_data.sequence("php?dB=aaaa&db_server=bbbbb&db_port=CCCCC", "^", "db=", "db_server=", "db_port="), false)
    lu.assertEquals(util_data.sequence("php?dB=aaaa&db_server=bbbbb&db_port=CCCCC", "*^", "db=", "db_server=", "db_port="), true)
end

function TestDataUtils:test_stoken()
    local mask = {}
    mask[util_data.ST_CMD] = true
    mask[util_data.ST_ALL] = true
    lu.assertEquals(util_data.stoken("abc.php?a=aaaaa&b=bbbbb&c=cccc&d=dd", mask, "php", "a", "b", "c", "d"), true)

    mask[util_data.ST_ALL] = false
    lu.assertEquals(util_data.stoken("abc.php?a=aaaaa&b=bbbbb&c=cccc&d=dd&x=xxxxx", mask, "php", "a", "b", "c", "d"), true)

    mask[util_data.ST_CMD] = false
    mask[util_data.ST_ALL] = true
    lu.assertEquals(util_data.stoken("abc.php?a=aaaaa&b=bbbbb&c=cccc&d=dd", mask, "a", "b", "c", "d"), true)

    mask[util_data.ST_SHUF] = true
    lu.assertEquals(util_data.stoken("abc.php?a=aaaaa&d=dd&b=bbbbb&c=cccc", mask, "a", "b", "c", "d"), true)
end

function TestDataUtils:test_sarray()
    lu.assertEquals(util_data.sarray("?portscanxxxxxxx", "==", "?exploits", "?portscan", "?crypte"), true)
    lu.assertEquals(util_data.sarray("abc.php?portscanxxxxxxx", "==", "?exploits", "?portscan", "?crypte"), false)
    lu.assertEquals(util_data.sarray("?Portscanxxxxxxx", "==", "?exploits", "?portscan", "?crypte"), false)
    lu.assertEquals(util_data.sarray("?Portscanxxxxxxx", "*=", "?exploits", "?portscan", "?crypte"), true)
    lu.assertEquals(util_data.sarray("abc.php?portscanxxxxxxx", "^", "?exploits", "?portscan", "?crypte"), true)
    lu.assertEquals(util_data.sarray("abc.php?Portscanxxxxxxx", "*^", "?exploits", "?portscan", "?crypte"), true)
    lu.assertEquals(util_data.sarray("abc.php", "^^", ".html", ".txt", ".jpg"), false)
    lu.assertEquals(util_data.sarray("abc.html", "^^", ".html", ".txt", ".jpg"), true)
end

function TestDataUtils:test_iparray()
    lu.assertEquals(util_data.iparray("192.168.1.1", "==", "192.168.1.1", "192.168.1.2", "192.168.1.3"), true)
    lu.assertEquals(util_data.iparray("192.168.1.1", "==", "192.168.1.2", "192.168.1.3"), false)
end

function TestDataUtils:test_narray()
    lu.assertEquals(util_data.narray(8080, "==", 8080, 8081, 8082), true)
    lu.assertEquals(util_data.narray(8080, "==", 8081, 8082), false)
end

-- 运行测试
os.exit(lu.LuaUnit.run())
