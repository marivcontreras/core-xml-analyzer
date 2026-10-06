function copyWarningSummary() {

    const textarea = document.getElementById("warning-summary");

    textarea.select();
    textarea.setSelectionRange(0, 999999);

    navigator.clipboard.writeText(textarea.value);
}

function filterWarningTable() {

    const type = document.getElementById("wt-type").value;
    const category = document.getElementById("wt-category").value;
    const location = document.getElementById("wt-location").value;
    const text = document.getElementById("wt-text").value.toLowerCase();

    const rows = document.querySelectorAll("#warning-table tbody tr");
    let visible = 0;

    rows.forEach(row => {
        const show =
            (!type || row.dataset.type === type) &&
            (!category || row.dataset.category === category) &&
            (!location || row.dataset.location === location) &&
            (!text || row.lastElementChild.textContent.toLowerCase().includes(text));

        row.style.display = show ? "" : "none";
        if (show) visible++;
    });

    document.getElementById("wt-count").textContent =
        `${visible} de ${rows.length} advertencias`;
}
