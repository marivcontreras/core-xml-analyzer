function copyWarningSummary() {

    const textarea = document.getElementById("warning-summary");

    textarea.select();
    textarea.setSelectionRange(0, 999999);

    navigator.clipboard.writeText(textarea.value);
}
