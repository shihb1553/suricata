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


-- util_data.ST_CMD = 1
-- util_data.ST_ALL = 2
-- util_data.ST_NONE = 4
-- util_data.ST_SHUF = 8
function TestDataUtils:test_stoken()
    local mask = {}
    mask[util_data.ST_CMD] = true
    mask[util_data.ST_ALL] = true
    lu.assertEquals(util_data.stoken("abc.php?a=aaaaa&b=bbbbb&c=cccc&d=dd", mask, "php", "a", "b", "c", "d"), true)
end

-- function TestDataUtils:test_reverse()
--     lu.assertEquals(util_data.reverse(self.test_str), "dlroW olleH")
--     lu.assertEquals(util_data.reverse(""), "") -- 边界测试
-- end

-- 运行测试
os.exit(lu.LuaUnit.run())
