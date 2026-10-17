-- Read-only metadata route for the native Deco VLAN status page.
-- Install together with its web assets; this file does not change networking.
module("luci.controller.admin.vlan_status", package.seeall)

local controller = require "luci.model.controller"
local uci = require "luci.model.uci"

local function read_status()
    local cursor = uci.cursor()
    local guest_configured = cursor:get("wifi", "guest") ~= nil
    local iot_configured = cursor:get("iot_wifi", "iot") ~= nil
    local vlan_id = tonumber(cursor:get("wifi", "guest", "vlan_id"))

    -- Zero is the stock unset sentinel. Missing/invalid IDs remain absent,
    -- which the page displays as not configured; no value is written back.
    if not vlan_id or vlan_id ~= vlan_id or vlan_id < 1 or vlan_id > 4094
            or vlan_id % 1 ~= 0 then
        vlan_id = nil
    end

    return {
        guest = {
            configured = guest_configured,
            enabled = cursor:get("wifi", "guest", "enable") == "1",
            vlan_id = vlan_id,
            vlan_enabled = cursor:get("wifi", "guest", "vlan_enable") == "1"
        },
        iot = {
            configured = iot_configured,
            vlan_supported = false
        },
        scope = "guest_global",
        read_only = true
    }
end

local callbacks = {
    status = {
        read = {cb = read_status}
    }
}

function dispatch(request)
    return controller.dispatch(callbacks, request)
end

function _index()
    return controller._index(dispatch)
end

function index()
    local page = entry({"admin", "vlan_status"}, call("_index"))
    page.leaf = true
    page.sysauth = true
end
