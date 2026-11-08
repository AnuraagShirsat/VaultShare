/**
 * VaultShare application script.
 * Unobtrusive event handlers to support strict Content Security Policy.
 */

document.addEventListener("DOMContentLoaded", function () {
    // 1. Confirmation dialogs on forms (e.g. access revocation)
    document.querySelectorAll("form[data-confirm]").forEach(function (form) {
        form.addEventListener("submit", function (e) {
            const message = form.getAttribute("data-confirm");
            if (message && !window.confirm(message)) {
                e.preventDefault();
            }
        });
    });

    // 2. Quick select user dropdown in document management view
    const quickSelect = document.getElementById("userQuickSelect");
    if (quickSelect) {
        quickSelect.addEventListener("change", function () {
            const val = this.value;
            if (!val) return;
            const input = document.getElementById("recipientsInput");
            if (!input) return;
            const current = input.value.trim();
            if (!current) {
                input.value = val;
            } else {
                const parts = current
                    .split(",")
                    .map(function (s) {
                        return s.trim();
                    })
                    .filter(Boolean);
                if (!parts.includes(val)) {
                    parts.push(val);
                    input.value = parts.join(", ");
                }
            }
            this.selectedIndex = 0;
        });
    }
});
