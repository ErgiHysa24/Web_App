// WatchDog Web: aggiornamento automatico di coda e scansioni in corso. Nessuna dipendenza.
(function () {
  "use strict";

  function getJson(url) {
    return fetch(url, { credentials: "same-origin", headers: { Accept: "application/json" } })
      .then(function (r) {
        if (r.redirected || r.status === 401) { window.location.reload(); throw new Error("sessione scaduta"); }
        return r.json();
      });
  }

  // Pagina di una scansione in coda o in corso.
  var live = document.querySelector("[data-scan-live]");
  if (live) {
    var bar = live.querySelector("[data-bar]");
    var step = live.querySelector("[data-step]");
    var pct = live.querySelector("[data-pct]");
    var log = live.querySelector("[data-log]");
    var time = live.querySelector("[data-duration]");
    var first = live.getAttribute("data-status");
    var tick = function () {
      getJson(live.getAttribute("data-scan-live")).then(function (d) {
        if (d.status !== "queued" && d.status !== "running") { window.location.reload(); return; }
        if (d.status !== first) { window.location.reload(); return; }
        if (bar) { bar.value = d.progress; }
        if (pct) { pct.textContent = d.progress + "%"; }
        if (step) { step.textContent = d.status === "queued" ? "In coda, posizione " + d.position : d.step; }
        if (time) { time.textContent = d.duration; }
        if (log) {
          var atEnd = log.scrollTop + log.clientHeight >= log.scrollHeight - 30;
          log.textContent = d.log;
          if (atEnd) { log.scrollTop = log.scrollHeight; }
        }
        window.setTimeout(tick, 2000);
      }).catch(function () { window.setTimeout(tick, 5000); });
    };
    if (log) { log.scrollTop = log.scrollHeight; }
    window.setTimeout(tick, 1500);
  }

  // Quadro generale ed elenco: ricarica quando una scansione parte o finisce.
  var queue = document.querySelector("[data-queue]");
  if (queue) {
    var signature = queue.getAttribute("data-queue");
    var watch = function () {
      getJson("/status.json").then(function (d) {
        var now = d.last_finished + "|" + d.active.map(function (x) { return x.id + x.status; }).join(",");
        if (now !== signature) { window.location.reload(); return; }
        d.active.forEach(function (x) {
          var row = queue.querySelector('[data-scan="' + x.id + '"]');
          if (!row) { return; }
          var b = row.querySelector("[data-bar]"); if (b) { b.value = x.progress; }
          var s = row.querySelector("[data-step]"); if (s) { s.textContent = x.step; }
        });
        window.setTimeout(watch, 4000);
      }).catch(function () { window.setTimeout(watch, 10000); });
    };
    window.setTimeout(watch, 4000);
  }

  // Tooltip dei grafici e della heatmap: data-tip = "valore|riga|riga". Testo inserito con
  // textContent (mai come HTML): nomi e servizi possono arrivare dai sistemi analizzati.
  var tip = document.querySelector(".tip");
  if (tip) {
    var current = null;
    var show = function (el, x, y) {
      var lines = (el.getAttribute("data-tip") || "").split("|").filter(function (s) { return s; });
      if (!lines.length) { return; }
      tip.textContent = "";
      lines.forEach(function (line, i) {
        var node = document.createElement(i === 0 ? "b" : "span");
        node.textContent = line;
        tip.appendChild(node);
        if (i > 0 && i < lines.length - 1) { tip.appendChild(document.createElement("br")); }
      });
      tip.hidden = false;
      var w = tip.offsetWidth, h = tip.offsetHeight;
      var left = Math.min(window.innerWidth - w - 8, Math.max(8, x + 14));
      var top = y - h - 12 < 8 ? y + 18 : y - h - 12;
      tip.style.left = left + "px";
      tip.style.top = top + "px";
    };
    var hide = function () { tip.hidden = true; current = null; };
    document.addEventListener("pointermove", function (e) {
      var el = e.target.closest ? e.target.closest("[data-tip]") : null;
      if (!el) { if (current) { hide(); } return; }
      current = el;
      show(el, e.clientX, e.clientY);
    });
    document.addEventListener("focusin", function (e) {
      var el = e.target.closest ? e.target.closest("[data-tip]") : null;
      if (!el) { return; }
      var r = el.getBoundingClientRect();
      show(el, r.left + r.width / 2, r.top);
    });
    document.addEventListener("focusout", hide);
    document.addEventListener("scroll", hide, true);
  }

  // "Seleziona tutti" nei gruppi di caselle.
  document.querySelectorAll("[data-check-all]").forEach(function (button) {
    button.addEventListener("click", function () {
      var boxes = document.querySelectorAll(button.getAttribute("data-check-all"));
      var all = Array.prototype.every.call(boxes, function (b) { return b.checked; });
      boxes.forEach(function (b) { b.checked = !all; });
    });
  });
}());
