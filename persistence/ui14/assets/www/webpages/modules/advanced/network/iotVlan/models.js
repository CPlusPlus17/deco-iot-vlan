(function ($) {
    "use strict";
    var names = ["Main", "Satellite 1", "Satellite 2"];
    $.su.modelManager.define("iotVlanStatus", {
        fields: ["responseValid", "fleet1", "fleet2", "fleet3", "saved", "persistence", "verification", "generation", "canEnable", "canDisable", "maintenance"].map(function (name) { return {name: name}; }),
        convert: function (s) {
            var text = $.su.CHAR.IOT_VLAN, result = {responseValid: false}, phases = ["held", "preparing", "prepared", "committed", "activating", "active", "disabled", "aborted", "error", "degraded"];
            var states = {active: text.ACTIVE, held: text.HELD, degraded: text.DEGRADED, pending: text.PENDING};
            if (!s || s.schema !== 2 || s.kind !== "deco_iot_ui_status" || s.backend_verified !== true || s.read_only !== true ||
                    !s.target || s.target.vlan_id !== 30 || s.target.main_untagged !== true || s.target.expected_nodes !== 3 ||
                    !s.fleet || s.fleet.observed !== true || typeof s.fleet.aligned !== "boolean" || !Array.isArray(s.fleet.nodes) || s.fleet.nodes.length !== 3 ||
                    !s.configuration || typeof s.configuration.attested !== "boolean" || !s.persistence || s.persistence.reboot_verified !== false ||
                    !s.verification || s.verification.packet_tagging !== "not_measured" || s.verification.internet !== "not_measured" || s.verification.isolation !== "not_measured" ||
                    (s.maintenance !== undefined && typeof s.maintenance !== "boolean") || !s.capabilities || typeof s.capabilities.enable !== "boolean" || typeof s.capabilities.disable !== "boolean") { return result; }
            if (!s.fleet.nodes[0]) { return result; }
            var aligned = true, stable = true, attested = true, generation = s.fleet.nodes[0].generation, enabled = s.fleet.nodes[0].desired_enabled;
            for (var i = 0; i < 3; i += 1) {
                var r = s.fleet.nodes[i];
                if (!r || r.name !== names[i] || !Number.isInteger(r.generation) || r.generation < 1 || r.generation > 2147483647 ||
                        typeof r.desired_enabled !== "boolean" || typeof r.active !== "boolean" || typeof r.ready !== "boolean" || typeof r.held !== "boolean" || typeof r.attested !== "boolean" ||
                        !Object.prototype.hasOwnProperty.call(states, r.status) || phases.indexOf(r.phase) < 0 ||
                        (r.active && (!r.ready || r.held || !r.desired_enabled))) { return result; }
                var pending = ["preparing", "prepared", "committed", "activating", "error"].indexOf(r.phase) >= 0;
                var expected = pending ? "pending" : (r.active && r.ready ? "active" : (r.held ? "held" : "degraded"));
                if (r.status !== expected) { return result; }
                stable = stable && !pending; attested = attested && r.attested;
                aligned = aligned && r.generation === generation && r.desired_enabled === enabled;
                result["fleet" + (i + 1)] = states[r.status] + " — " + text.GENERATION + " " + r.generation;
            }
            var safe = aligned && stable && generation < 2147483647 && s.maintenance !== true;
            if (s.fleet.aligned !== aligned || s.configuration.attested !== attested ||
                    (aligned && (s.generation !== generation || s.desired_enabled !== enabled)) ||
                    (!aligned && (s.generation != null || s.desired_enabled != null)) ||
                    s.capabilities.enable !== safe || s.capabilities.disable !== safe) { return {responseValid: false}; }
            result.responseValid = true; result.generation = aligned ? generation : null;
            result.canEnable = safe; result.canDisable = safe; result.maintenance = s.maintenance === true;
            result.saved = !aligned ? text.GENERATION_MISMATCH : ((enabled ? text.DESIRED_ENABLED : text.DESIRED_DISABLED) + "; " + (attested ? text.COMMIT_ATTESTED : text.COMMIT_UNATTESTED));
            result.persistence = text.REBOOT_UNVERIFIED; result.verification = text.NOT_MEASURED;
            return result;
        },
        proxy: {url: $.su.url("/admin/vlan_status?form=iot_status"), ajax: {timeout: 70000}}
    });
}(jQuery));
