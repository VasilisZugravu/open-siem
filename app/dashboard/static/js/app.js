(function () {
  "use strict";

  const REDUCED_MOTION = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  window.SIEM = window.SIEM || {};
  window.SIEM.reducedMotion = REDUCED_MOTION;

  /* ---------------- Entrance animations ---------------- */

  function initEntrance() {
    const els = document.querySelectorAll("[data-animate]");
    if (!els.length) return;
    if (REDUCED_MOTION || !("IntersectionObserver" in window)) {
      els.forEach((el) => el.classList.add("in-view"));
      return;
    }
    const observer = new IntersectionObserver(
      (entries) => {
        entries.forEach((entry) => {
          if (entry.isIntersecting) {
            const el = entry.target;
            const delay = Number(el.dataset.delay || 0);
            el.style.animationDelay = delay + "ms";
            el.classList.add("in-view");
            observer.unobserve(el);
          }
        });
      },
      { threshold: 0.1 }
    );
    els.forEach((el, i) => {
      if (!el.dataset.delay) el.dataset.delay = String(Math.min(i * 40, 400));
      observer.observe(el);
    });
  }

  /* ---------------- Count-up numbers ---------------- */

  function countUp(el, target, duration) {
    target = Number(target) || 0;
    if (REDUCED_MOTION) {
      el.textContent = target.toLocaleString();
      return;
    }
    duration = duration || 700;
    const start = Number(el.dataset.countFrom || 0);
    if (start === target) {
      el.textContent = target.toLocaleString();
      return;
    }
    const startTime = performance.now();
    function frame(now) {
      const p = Math.min(1, (now - startTime) / duration);
      const eased = 1 - Math.pow(1 - p, 3);
      const value = Math.round(start + (target - start) * eased);
      el.textContent = value.toLocaleString();
      if (p < 1) {
        requestAnimationFrame(frame);
      } else {
        el.dataset.countFrom = String(target);
      }
    }
    requestAnimationFrame(frame);
  }

  function initCounters() {
    document.querySelectorAll("[data-count]").forEach((el) => {
      countUp(el, el.dataset.count);
    });
  }

  window.SIEM.countUp = countUp;

  /* ---------------- Toasts ---------------- */

  function dismissToast(toast) {
    toast.classList.add("is-leaving");
    setTimeout(() => toast.remove(), REDUCED_MOTION ? 0 : 220);
  }

  function initToasts() {
    document.querySelectorAll(".toast-item").forEach((toast) => {
      const closeBtn = toast.querySelector(".toast-close");
      if (closeBtn) closeBtn.addEventListener("click", () => dismissToast(toast));
      const timeout = Number(toast.dataset.timeout || 5000);
      setTimeout(() => {
        if (toast.isConnected) dismissToast(toast);
      }, timeout);
    });
  }

  /* ---------------- Button loading state on submit ---------------- */

  function initFormLoading() {
    document.querySelectorAll("form[data-loading-btn]").forEach((form) => {
      form.addEventListener("submit", () => {
        const btn = form.querySelector("button[type=submit]");
        if (btn) {
          btn.classList.add("is-loading");
          btn.disabled = true;
        }
      });
    });
  }

  /* ---------------- Chart.js dark theme defaults ---------------- */

  function applyChartDefaults() {
    if (typeof Chart === "undefined") return;
    Chart.defaults.color = "#94a3b8";
    Chart.defaults.font.family = "Inter, sans-serif";
    Chart.defaults.borderColor = "rgba(255,255,255,0.06)";
    Chart.defaults.plugins.legend.labels.color = "#94a3b8";
    if (REDUCED_MOTION) {
      Chart.defaults.animation = false;
    } else {
      Chart.defaults.animation = { duration: 600, easing: "easeOutCubic" };
    }
  }

  window.SIEM.chartPalette = {
    accent: "#22d3ee",
    accent2: "#fbbf24",
    crit: "#f43f5e",
    high: "#fb923c",
    med: "#fbbf24",
    low: "#38bdf8",
    info: "#64748b",
    ok: "#34d399",
    grid: "rgba(255,255,255,0.06)",
  };

  /* ---------------- Live polling module ---------------- */

  function initLive(opts) {
    const root = opts.root;
    if (!root) return;
    const endpoint = opts.endpoint;
    const render = opts.render;
    const intervalMs = opts.intervalMs || 5000;
    let timer = null;
    let inFlight = false;

    function isLive() {
      const params = new URLSearchParams(window.location.search);
      return params.get("live") !== "0";
    }

    function tick() {
      if (!isLive() || document.hidden || inFlight) {
        schedule();
        return;
      }
      inFlight = true;
      const url = endpoint + (opts.queryString ? opts.queryString() : "");
      fetch(url, { headers: { "X-Requested-With": "fetch" } })
        .then((res) => {
          if (!res.ok) throw new Error("bad status " + res.status);
          return res.json();
        })
        .then((data) => render(data))
        .catch(() => {
          /* transient network error: keep polling, don't blow up the UI */
        })
        .finally(() => {
          inFlight = false;
          schedule();
        });
    }

    function schedule() {
      clearTimeout(timer);
      timer = setTimeout(tick, intervalMs);
    }

    document.addEventListener("visibilitychange", () => {
      if (!document.hidden) tick();
    });

    schedule();
  }

  window.SIEM.initLive = initLive;
  window.SIEM.dismissToast = dismissToast;

  document.addEventListener("DOMContentLoaded", () => {
    applyChartDefaults();
    initEntrance();
    initCounters();
    initToasts();
    initFormLoading();
  });
})();
