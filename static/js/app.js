/* Ghostlayer — the small amount of behaviour the pages need.
   Everything works without it; this only removes friction. */

(function () {
  "use strict";

  // ---- Upload: drag and drop, filename echo, busy state ----------------
  var zone = document.getElementById("dropzone");
  var input = document.getElementById("document");
  var chosen = document.getElementById("chosen");
  var form = document.getElementById("scanform");
  var busy = document.getElementById("busy");
  var go = document.getElementById("go");

  function describe(file) {
    if (!file) { return ""; }
    var kb = file.size / 1024;
    var size = kb < 1024 ? kb.toFixed(0) + " KB" : (kb / 1024).toFixed(1) + " MB";
    return file.name + "  \u00b7  " + size;
  }

  if (zone && input) {
    ["dragenter", "dragover"].forEach(function (name) {
      zone.addEventListener(name, function (e) {
        e.preventDefault();
        zone.classList.add("is-hot");
      });
    });

    ["dragleave", "drop"].forEach(function (name) {
      zone.addEventListener(name, function (e) {
        e.preventDefault();
        zone.classList.remove("is-hot");
      });
    });

    zone.addEventListener("drop", function (e) {
      if (input.disabled) { return; }
      var files = e.dataTransfer && e.dataTransfer.files;
      if (files && files.length) {
        input.files = files;
        chosen.textContent = describe(files[0]);
      }
    });

    input.addEventListener("change", function () {
      chosen.textContent = describe(input.files && input.files[0]);
    });
  }

  if (form) {
    form.addEventListener("submit", function () {
      if (input && input.files && !input.files.length) { return; }
      if (busy) { busy.classList.add("on"); }
      if (go) {
        go.disabled = true;
        go.textContent = "Scanning\u2026";
      }
    });
  }

  // ---- Copy buttons ------------------------------------------------------
  document.querySelectorAll("[data-copy]").forEach(function (button) {
    button.addEventListener("click", function () {
      var target = document.querySelector(button.getAttribute("data-copy"));
      if (!target) { return; }
      var text = target.textContent.trim();
      var done = function () {
        var original = button.textContent;
        button.textContent = "Copied";
        setTimeout(function () { button.textContent = original; }, 1600);
      };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done, function () {});
      } else {
        var field = document.createElement("textarea");
        field.value = text;
        document.body.appendChild(field);
        field.select();
        try { document.execCommand("copy"); done(); } catch (err) { /* nothing to do */ }
        document.body.removeChild(field);
      }
    });
  });
}());
