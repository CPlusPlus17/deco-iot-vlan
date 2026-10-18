(function ($) {
    "use strict";

    $.su.moduleManager.define("guestVlan", {
        models: ["guestVlanStatus"],
        views: ["guestVlanView"],
        preventSave: true,
        listeners: {
            ev_on_launch: function (event, controller) {
                controller.destroyed = false;
                controller.loadStatus();
            },
            ev_before_destroy: function (event, controller) {
                controller.destroyed = true;
            }
        }
    }, function (controller, views, models) {
        var text = $.su.CHAR.VLAN_STATUS;

        function unavailable(message) {
            if (controller.destroyed) {
                return;
            }
            views.guestVlanView.details.hide();
            views.guestVlanView.statusMessage.setValue(message);
        }

        return {
            destroyed: false,

            loadStatus: function () {
                views.guestVlanView.details.hide();
                views.guestVlanView.statusMessage.setValue(text.LOADING);

                models.guestVlanStatus.load({
                    preventSuccessEvent: true,
                    preventFailEvent: true,
                    preventErrorEvent: true,
                    success: function () {
                        if (controller.destroyed) {
                            return;
                        }
                        if (!models.guestVlanStatus.getData().responseValid) {
                            unavailable(text.INVALID_RESPONSE);
                            return;
                        }
                        views.guestVlanView.statusMessage.setValue(text.READY);
                        views.guestVlanView.details.show();
                    },
                    fail: function () {
                        unavailable(text.UNAVAILABLE);
                    },
                    error: function () {
                        unavailable(text.UNAVAILABLE);
                    }
                });
            }
        };
    });
}(jQuery));
