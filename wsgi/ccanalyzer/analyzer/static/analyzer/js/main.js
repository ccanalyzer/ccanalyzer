/**
 * Class Main
 *
 * This is the main initialization script
 */
var Main = function() {
    "use strict";

    var $body = $("body");
    var isMobile = false,
        $topBar = $(".topbar"),
        supportTransition = true,
        windowWidth, windowHeight,
        $closedbar = $(".closedbar"),
        $mainContent = $(".main-content"),
        $footer = $(".main-wrapper > footer"),
        $mainNavigation = $('.main-navigation');

    var viewport = function() {
        var e = window, a = 'inner';

        if (!('innerWidth' in window )) {
            a = 'client';
            e = document.documentElement || document.body;
        }

        return {
            width: e[a + 'Width'], height: e[a + 'Height']
        };
    };

    var resizeHeight = function() {
        if(windowWidth > 992) {
            $mainNavigation.css({
                height: windowHeight - $topBar.outerHeight(true) - $(".slide-tools").outerHeight(true)
            });
            $(".navbar-content").css({
                height: windowHeight - $topBar.outerHeight(true)
            });
        } else {
            $mainNavigation.css({
                height: windowHeight - $(".slide-tools").outerHeight(true)
            });
            $(".navbar-content").css({
                height: windowHeight
            });
        }

        $mainContent.css({
            "min-height": windowHeight - $topBar.outerHeight(true) - $footer.outerHeight(true)
        });
    };

    var initEnvironment = function() {
        if (/Android|webOS|iPhone|iPad|iPod|BlackBerry|IEMobile|Opera Mini/i.test(navigator.userAgent)) {
            $body.addClass('isMobile');
            isMobile = true;
        }

        var thisBody = document.body || document.documentElement, thisStyle = thisBody.style;
        supportTransition = thisStyle.transition !== undefined
            || thisStyle.WebkitTransition !== undefined
            || thisStyle.MozTransition !== undefined
            || thisStyle.OTransition !== undefined;

        $(window).resize(function() {
            var vp = viewport();
            windowWidth = vp.width;
            windowHeight = vp.height;
            resizeHeight();
        }).trigger("resize");
    };

    return {
        init: function() {
            initEnvironment();
        }
    };
}();

$(document).ready(function() {
    Main.init();
});
