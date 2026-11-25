// Arpent — petites interactions sans dépendance.
(function () {
  "use strict";

  // Confirmation avant certains envois (ex. « Quitter »).
  document.querySelectorAll("form[data-confirm]").forEach(function (f) {
    f.addEventListener("submit", function (e) {
      if (!window.confirm(f.dataset.confirm)) e.preventDefault();
    });
  });

  // Boutons « sous-réseau proposé » : remplit le champ des plages.
  document.querySelectorAll("[data-fill-ranges]").forEach(function (b) {
    b.addEventListener("click", function () {
      var input = document.querySelector("input[name=ranges]");
      if (input) input.value = b.dataset.fillRanges;
    });
  });

  // Profil complet : case de confirmation obligatoire.
  var profile = document.getElementById("profile");
  var confirmFull = document.getElementById("confirm-full");
  if (profile && confirmFull) {
    var sync = function () {
      var full = profile.value === "full";
      confirmFull.hidden = !full;
      confirmFull.querySelector("input").required = full;
    };
    profile.addEventListener("change", sync);
    sync();
  }

  // Filtre texte sur un tableau.
  document.querySelectorAll("input[data-filter]").forEach(function (input) {
    var table = document.querySelector(input.dataset.filter);
    if (!table) return;
    input.addEventListener("input", function () {
      var q = input.value.trim().toLowerCase();
      table.querySelectorAll("tbody tr").forEach(function (tr) {
        tr.hidden = q !== "" && tr.textContent.toLowerCase().indexOf(q) < 0;
      });
    });
  });

  // Tri des colonnes marquées data-sort.
  function ipKey(s) {
    var m = s.trim().match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)/);
    if (!m) return s;
    return m.slice(1).map(function (x) { return ("00" + x).slice(-3); }).join(".");
  }
  document.querySelectorAll("table.sortable").forEach(function (table) {
    table.querySelectorAll("th").forEach(function (th, col) {
      var kind = th.dataset.sort;
      if (!kind) return;
      var asc = true;
      th.addEventListener("click", function () {
        var body = table.tBodies[0];
        var rows = Array.prototype.slice.call(body.rows);
        rows.sort(function (a, b) {
          var x = a.cells[col], y = b.cells[col], r;
          if (kind === "num") r = (+x.dataset.value || 0) - (+y.dataset.value || 0);
          else if (kind === "ip") r = ipKey(x.textContent) < ipKey(y.textContent) ? -1 : 1;
          else r = x.textContent.localeCompare(y.textContent);
          return asc ? r : -r;
        });
        asc = !asc;
        rows.forEach(function (r) { body.appendChild(r); });
      });
    });
  });

  // Page de progression d'un audit : interrogation régulière.
  var box = document.getElementById("progress");
  if (box) {
    var order = ["discovery", "passive", "ports", "probes", "enrich", "save"];
    var fill = box.querySelector(".fill"), counter = box.querySelector(".counter");
    var failures = 0;
    var tick = function () {
      fetch(box.dataset.url, { cache: "no-store", credentials: "same-origin" })
        .then(function (r) { return r.json(); })
        .then(function (j) {
          failures = 0;
          if (j.status === "unknown") { document.getElementById("progress-lost").hidden = false; return; }
          var idx = order.indexOf(j.phase);
          box.querySelectorAll("ol.phases li").forEach(function (li, i) {
            li.className = i < idx ? "done" : (i === idx ? "active" : "");
          });
          var pct = j.total > 0 ? Math.round(100 * j.done / j.total) : 0;
          fill.style.width = pct + "%";
          counter.textContent = j.done + " / " + j.total + " · " + pct + " % · " + j.elapsed + " s";
          if (j.status === "running") { setTimeout(tick, 700); return; }
          if (j.error && j.status === "failed") {
            var e = document.getElementById("progress-error"); e.textContent = j.error; e.hidden = false;
          }
          setTimeout(function () { window.location.reload(); }, 400);
        })
        .catch(function () { if (++failures < 20) setTimeout(tick, 1500); });
    };
    tick();
  }
})();
