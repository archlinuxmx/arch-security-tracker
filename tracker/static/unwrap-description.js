"use strict";

function unwrapProse(text) {
    let fenced = false;
    return text.replace(/\r\n?/g, "\n").split(/(\n[ \t]*\n)/).map(function (paragraph) {
        const hasFence = /^[ \t]*(```|~~~)/m.test(paragraph);
        const preserve = fenced || hasFence || /^(?:[ \t]|>|[-*+] |\d+[.)] )/m.test(paragraph);
        if (hasFence) {
            const fences = paragraph.match(/^[ \t]*(?:```|~~~)/gm);
            if (fences.length % 2) fenced = !fenced;
        }
        return preserve || /^\n/.test(paragraph) ? paragraph : paragraph.replace(/\n/g, " ");
    }).join("");
}

const description = document.getElementById("description");
const unwrapButton = document.getElementById("unwrap-description");
const undoButton = document.getElementById("undo-unwrap");
let previousDescription;
unwrapButton.addEventListener("click", function () {
    previousDescription = description.value;
    description.value = unwrapProse(description.value);
    undoButton.disabled = false;
});
undoButton.addEventListener("click", function () {
    description.value = previousDescription;
    undoButton.disabled = true;
});
