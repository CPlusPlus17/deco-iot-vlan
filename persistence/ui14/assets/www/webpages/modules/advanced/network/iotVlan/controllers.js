(function ($) {
    "use strict";
    $.su.moduleManager.define("iotVlan", {
        services: ["ajax"], models: ["iotVlanStatus"], views: ["iotVlanView"], preventSave: true,
        listeners: {
            ev_on_launch: function (event, c) { c.destroyed = false; c.loadStatus(); },
            ev_before_destroy: function (event, c) { c.destroyed = true; }
        },
        init: function (c, views) {
            views.iotVlanView.enableButton.disable(); views.iotVlanView.disableButton.disable();
            this.control({
                "#iot-vlan-refresh": {ev_button_click: function () { c.loadStatus(); }},
                "#iot-vlan-enable": {ev_button_click: function () { c.applyPolicy(true); }},
                "#iot-vlan-disable": {ev_button_click: function () { c.applyPolicy(false); }}
            });
        }
    }, function (c, views, models, stores, deps, services) {
        var text = $.su.CHAR.IOT_VLAN, view = views.iotVlanView;
        function disable() { view.enableButton.disable(); view.disableButton.disable(); }
        function fail(message) {
            if (c.destroyed) { return; }
            c.busy = false; c.generation = null; disable(); view.details.hide();
            view.refreshButton.enable(); view.statusMessage.setValue(message);
        }
        function ready() {
            if (c.destroyed) { return; }
            var data = models.iotVlanStatus.getData();
            if (!data.responseValid) { fail(text.INVALID_RESPONSE); return; }
            c.busy = false; c.generation = data.generation; view.refreshButton.enable();
            if (data.canEnable) { view.enableButton.enable(); } else { view.enableButton.disable(); }
            if (data.canDisable) { view.disableButton.enable(); } else { view.disableButton.disable(); }
            view.details.show(); view.statusMessage.setValue(data.maintenance ? (text.MAINTENANCE || "The page is being updated.") : text.FLEET_OBSERVED);
        }

        function pollJob(nonce, deadline) {
            if (c.destroyed) { return; }
            if (Date.now() >= deadline) { fail(text.OUTCOME_UNKNOWN); return; }
            services.ajax.request({url: $.su.url("/admin/vlan_status?form=iot_job"), ajax: {timeout: 15000},
                data: {operation: "read", params: {nonce: nonce}},
                preventSuccessEvent: true, preventFailEvent: true, preventErrorEvent: true, preventDefaultError: true,
                success: function (report) {
                    if (c.destroyed) { return; }
                    if (!report || report.schema !== 3 || report.kind !== "deco_iot_ui_job" || report.nonce !== nonce) { fail(text.OUTCOME_UNKNOWN); return; }
                    if (report.state === "pending" && report.completed === false) {
                        setTimeout(function () { pollJob(nonce, deadline); }, 2000); return;
                    }
                    if (report.state !== "done" || report.completed !== true || report.outcome !== "observed" || report.refresh_required !== false) { fail(text.OUTCOME_UNKNOWN); return; }
                    c.busy = false; c.loadStatus();
                },
                fail: function () { fail(text.OUTCOME_UNKNOWN); }, error: function () { fail(text.OUTCOME_UNKNOWN); }
            });
        }

        return {
            destroyed: false, busy: false, generation: null,
            loadStatus: function () {
                if (c.destroyed || c.busy) { return; }
                c.busy = true; c.generation = null; disable(); view.details.hide(); view.refreshButton.disable(); view.statusMessage.setValue(text.LOADING);
                models.iotVlanStatus.load({preventSuccessEvent: true, preventFailEvent: true, preventErrorEvent: true,
                    success: ready, fail: function () { fail(text.UNAVAILABLE); }, error: function () { fail(text.UNAVAILABLE); }});
            },
            applyPolicy: function (enabled) {
                var data = models.iotVlanStatus.getData();
                if (c.destroyed || c.busy || !data.responseValid || !Number.isInteger(c.generation) ||
                        (enabled ? !data.canEnable : !data.canDisable)) { return; }
                var generation = c.generation;
                c.busy = true; c.generation = null; disable(); view.details.hide(); view.refreshButton.disable(); view.statusMessage.setValue(text.APPLYING);
                services.ajax.request({url: $.su.url("/admin/vlan_status?form=iot_apply"), ajax: {timeout: 55000},
                    data: {operation: "write", params: {enabled: enabled, expected_generation: generation}},
                    preventSuccessEvent: true, preventFailEvent: true, preventErrorEvent: true, preventDefaultError: true,
                    success: function (report) {
                        if (c.destroyed) { return; }
                        if (!report || report.schema !== 3 || report.kind !== "deco_iot_ui_job" ||
                                report.state !== "pending" || report.completed !== false ||
                                typeof report.nonce !== "string" || !/^[0-9a-f]{32}$/.test(report.nonce)) { fail(text.OUTCOME_UNKNOWN); return; }
                        pollJob(report.nonce, Date.now() + 300000);
                    },
                    fail: function () { fail(text.OUTCOME_UNKNOWN); }, error: function () { fail(text.OUTCOME_UNKNOWN); }
                });
            }
        };
    });
}(jQuery));
