/* ============================================================
   VulnScan — app.js  (bulletproof edition)
   ============================================================ */
(function () {
    "use strict";

    function ready(fn) {
        if (document.readyState === "loading") {
            document.addEventListener("DOMContentLoaded", fn);
        } else {
            fn();
        }
    }

    ready(function () {
        console.log("[VulnScan] app.js ready");

        /* ============ SIDEBAR ============ */
        const body      = document.body;
        const hamburger = document.getElementById("hamburger");
        const overlay   = document.getElementById("overlay");
        const sidebar   = document.getElementById("sidebar");

        function setSidebar(open) {
            if (open) {
                body.classList.add("sidebar-open");
                document.documentElement.classList.add("sidebar-open");
            } else {
                body.classList.remove("sidebar-open");
                document.documentElement.classList.remove("sidebar-open");
            }
            if (hamburger) hamburger.setAttribute("aria-expanded", open ? "true" : "false");
            if (sidebar)   sidebar.setAttribute("aria-hidden", open ? "fasle" : "true");
            console.log("[VulnScan] sidebar-open:", open);
        }

        function toggleSidebar(e) {
            if (e) { e.preventDefault(); e.stopPropagation(); }
            setSidebar(!body.classList.contains("sidebar-open"));
        }

        if (hamburger) {
            hamburger.addEventListener("click", toggleSidebar);
            hamburger.addEventListener("touchend", toggleSidebar, { passive: false });
            hamburger.onclick = toggleSidebar; // fallback
        } else {
            console.error("[VulnScan] #hamburger NOT FOUND");
        }

        if (overlay) {
            overlay.addEventListener("click", function () { setSidebar(false); });
        }

        // Close on ESC
        document.addEventListener("keydown", function (e) {
            if (e.key === "Escape") setSidebar(false);
        });

        // Auto-close when a nav link is clicked on mobile
        document.querySelectorAll(".sidebar-nav .nav-link").forEach(function (a) {
            a.addEventListener("click", function () {
                if (window.innerWidth < 900) setSidebar(false);
            });
        });

        /* ============ ENTITY CARD EXPAND ============ */
        document.addEventListener("click", function (e) {
            const card = e.target.closest(".entity-card");
            if (!card) return;
            if (e.target.closest("a, button")) return;
            const sel = card.getAttribute("data-bs-target");
            if (!sel) return;
            const el = document.querySelector(sel);
            if (!el) return;
            el.classList.toggle("show");
        });

        /* ============ NMAP OPTION ENGINE ============ */
        const CONFLICTS = {
            udp_scan: [
                "ack_scan", "window_scan", "maimon_scan", "null_scan",
                "fin_scan", "xmas_scan", "idle_scan", "ftp_bounce",
                "sctp_init_scan", "sctp_cookie_scan", "ip_protocol_scan",
            ],
            ping_only: [
                "syn_scan", "connect_scan", "ack_scan", "window_scan",
                "maimon_scan", "null_scan", "fin_scan", "xmas_scan",
                "idle_scan", "sctp_init_scan", "sctp_cookie_scan",
                "ip_protocol_scan", "ftp_bounce", "udp_scan",
                "version_detect", "version_light", "version_all",
                "version_trace", "os_detect", "osscan_limit",
                "osscan_guess", "aggressive", "fast_scan", "top_ports",
                "script", "script_default", "script_vuln",
                "traceroute", "seq_ports",
            ],
            list_scan: [
                "ping_only", "syn_scan", "connect_scan", "ack_scan",
                "window_scan", "maimon_scan", "null_scan", "fin_scan",
                "xmas_scan", "idle_scan", "udp_scan",
                "sctp_init_scan", "sctp_cookie_scan", "ip_protocol_scan",
                "ftp_bounce", "version_detect", "version_light",
                "version_all", "os_detect", "aggressive",
                "fast_scan", "top_ports", "script", "script_default",
                "script_vuln", "traceroute",
            ],
            aggressive: ["ping_only", "list_scan"],
            version_light: ["version_all"],
            version_all:   ["version_light"],
            fragment: ["mtu"],
            mtu:      ["fragment"],
        };

        function conflictsOf(name) {
            const out = new Set(CONFLICTS[name] || []);
            for (const [k, list] of Object.entries(CONFLICTS)) {
                if (list.includes(name)) out.add(k);
            }
            return out;
        }

        function setDisabled(input, disabled, owner) {
            if (!input) return;
            if (disabled) {
                input.disabled = true;
                input.dataset.wasDisabledBy = owner;
            } else if (input.dataset.wasDisabledBy === owner) {
                input.disabled = false;
                delete input.dataset.wasDisabledBy;
            }
        }

        document.querySelectorAll('.opt input[type="checkbox"]').forEach(function (cb) {
            cb.addEventListener("change", function () {
                if (cb.checked) {
                    const group = cb.dataset.group;
                    if (group) {
                        document.querySelectorAll('.opt input[data-group="' + group + '"]')
                            .forEach(function (o) { if (o !== cb) o.checked = false; });
                    }
                    conflictsOf(cb.name).forEach(function (n) {
                        const o = document.querySelector('.opt input[name="' + n + '"]');
                        if (o) o.checked = false;
                    });
                    if (cb.dataset.disables) {
                        cb.dataset.disables.split(/\s+/).filter(Boolean).forEach(function (n) {
                            setDisabled(document.querySelector('[name="' + n + '"]'), true, cb.name);
                        });
                    }
                } else {
                    if (cb.dataset.disables) {
                        cb.dataset.disables.split(/\s+/).filter(Boolean).forEach(function (n) {
                            setDisabled(document.querySelector('[name="' + n + '"]'), false, cb.name);
                        });
                    }
                }
            });
        });

        // Reverse: typing into a controlled field unticks its box
        document.querySelectorAll('#options-panel input[type="text"], #options-panel input[type="number"]')
            .forEach(function (input) {
                input.addEventListener("input", function () {
                    if (!input.value) return;
                    document.querySelectorAll('.opt input[type="checkbox"][data-disables]')
                        .forEach(function (cb) {
                            const list = cb.dataset.disables.split(/\s+/).filter(Boolean);
                            if (list.includes(input.name) && cb.checked) {
                                cb.checked = false;
                                list.forEach(function (n) {
                                    if (n !== input.name) {
                                        setDisabled(document.querySelector('[name="' + n + '"]'), false, cb.name);
                                    }
                                });
                            }
                        });
                });
            });

        console.log("[VulnScan] option engine ready");
    });
})();
