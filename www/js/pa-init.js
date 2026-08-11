// Plausible, served from this origin.
//
// Two things are proxied by Caddy so that nothing on this site loads from, or
// sends to, another host: the vendor script at /js/pa-*.js, and events at
// /pa/event. `endpoint` has to be overridden here because the vendor script
// hard-codes an absolute `/api/event` on the vendor's own domain and does not
// derive it from its own `src` — proxying the script alone would have left
// every event going straight there, which is what the proxy exists to prevent,
// while looking exactly like it was working.
//
// The vendor hostname deliberately appears nowhere in this file, and a test
// asserts that: the only correct value for `endpoint` here is a path on this
// origin.
//
// This lives in a file rather than inline so the policy header can stay
// `script-src 'self'`. An inline block would need `'unsafe-inline'`, which
// re-opens the whole class of injection this header is here to close, on the
// pages that carry it.
//
// `formSubmissions`, `outboundLinks` and `fileDownloads` default to true. They
// are left on, and named on the privacy page: none captures what was typed
// into a field, only that a submission happened.
window.plausible = window.plausible || function () {
  (plausible.q = plausible.q || []).push(arguments);
};
plausible.init = plausible.init || function (i) { plausible.o = i || {}; };
plausible.init({ endpoint: "/pa/event" });
