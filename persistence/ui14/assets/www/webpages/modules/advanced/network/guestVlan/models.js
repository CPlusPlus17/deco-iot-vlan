(function ($) {
    "use strict";

    $.su.modelManager.define("guestVlanStatus", {
        fields: [
            {name: "responseValid"},
            {name: "guestNetwork"},
            {name: "guestTagging"},
            {name: "guestVlanId"},
            {name: "scope"},
            {name: "iotNetwork"},
            {name: "iotVlan"}
        ],

        convert: function (status) {
            var text = $.su.CHAR.VLAN_STATUS;
            var guest = status && status.guest;
            var iot = status && status.iot;
            var valid = !!(status && status.read_only === true &&
                status.scope === "guest_global" && guest && iot &&
                typeof guest.configured === "boolean" &&
                typeof guest.enabled === "boolean" &&
                typeof guest.vlan_enabled === "boolean" &&
                typeof iot.configured === "boolean" &&
                iot.vlan_supported === false);
            var result = {
                responseValid: valid,
                guestNetwork: text.NOT_CONFIGURED,
                guestTagging: text.NOT_CONFIGURED,
                guestVlanId: text.NOT_CONFIGURED,
                scope: text.GUEST_SCOPE,
                iotNetwork: text.NOT_CONFIGURED,
                iotVlan: text.NOT_SUPPORTED
            };

            if (!valid) {
                return result;
            }

            if (guest.configured) {
                result.guestNetwork = guest.enabled ? text.ENABLED : text.DISABLED;
                result.guestTagging = guest.vlan_enabled ? text.ENABLED : text.DISABLED;
                if (typeof guest.vlan_id === "number" &&
                        isFinite(guest.vlan_id) &&
                        Math.floor(guest.vlan_id) === guest.vlan_id &&
                        guest.vlan_id >= 1 && guest.vlan_id <= 4094) {
                    result.guestVlanId = String(guest.vlan_id);
                }
            }
            result.iotNetwork = iot.configured ? text.CONFIGURED : text.NOT_CONFIGURED;
            return result;
        },

        proxy: {
            url: $.su.url("/admin/vlan_status?form=status")
        }
    });
}(jQuery));
