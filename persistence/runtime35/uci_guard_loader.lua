-- Own module-loader adapter. A separate installer must preserve the exact
-- stock bytecode under the fixed private RAM path before binding the wrapper.
local M={}
function M.load(stock_chunk,loaded,guard,managed)
    assert(type(stock_chunk)=="function" and type(loaded)=="table"
        and type(guard)=="table" and type(guard.install)=="function"
        and type(managed)=="function","guard loader dependencies missing")
    -- Exact stock module uses module('luci.model.uci') and populates
    -- package.loaded, rather than returning its module table.
    stock_chunk("luci.model.uci")
    local original=assert(loaded["luci.model.uci"],"stock UCI module not loaded")
    assert(type(original)=="table" and type(original.cursor)=="function","stock UCI API invalid")
    local meta=assert(getmetatable(original.cursor()),"shared cursor metatable missing")
    assert(type(meta)=="table","shared cursor metatable invalid")
    guard.install(meta,managed)
    return original
end
return M
