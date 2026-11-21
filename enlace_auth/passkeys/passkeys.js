/* enlacePasskeys: the browser side of enlace_auth's passkeys.
 *
 * Served at /auth/passkeys/passkeys.js. Any page on the platform can include it.
 * Confirming an action (step-up):
 *
 *   <script src="/auth/passkeys/passkeys.js"></script>
 *   // when the page shows the action, BEFORE the user taps:
 *   const prepared = await enlacePasskeys.prepareStepUp("equerry: start job 42");
 *   button.onclick = async () => {
 *     const {proof} = await enlacePasskeys.stepUp(prepared);   // Face ID / Touch ID
 *     // send `proof` to your backend, which redeems it at
 *     // POST /auth/passkeys/step-up/redeem {proof, action, email} before acting.
 *   };
 *
 * A step-up a backend requested (the strong form: the text and the audience are
 * the backend's, and the proof redeems only for that audience) is confirmed on the
 * platform's own page, /auth/passkeys/confirm?r=<request>, which uses
 * prepareStepUp({request: id}). stepUp resolves to {proof, action, expires_in,
 * credential}: credential is the signed assertion that was verified.
 *
 * Prepare first: Safari on iPhone and Mac only lets a page call the passkey
 * prompt straight from a tap, so the network round trips (CSRF token, options)
 * must happen before it. A prepared request is good for four minutes; an older
 * one is prepared again (which Safari may then refuse: prepare again on focus).
 *
 * Every call rejects with an Error whose message is safe to show. A user who
 * cancels the system prompt gives err.name === "NotAllowedError"; a request the
 * server refuses because the sign-in is too old (or not a passkey sign-in) gives
 * err.reauth === true; an account without a passkey gives err.status === 409.
 */
(function () {
  "use strict";
  var FRESH_MS = 240000;
  function b2u(buf) {
    var bytes = new Uint8Array(buf), bin = "";
    for (var i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
    return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
  function u2b(text) {
    var s = text.replace(/-/g, "+").replace(/_/g, "/");
    while (s.length % 4) s += "=";
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  }
  async function csrf() {
    var r = await fetch("/auth/csrf", { credentials: "include" });
    return (await r.json()).csrf;
  }
  async function send(method, url, body, token) {
    var headers = { "Content-Type": "application/json" };
    if (method !== "GET") headers["X-CSRF-Token"] = token || (await csrf());
    var r = await fetch(url, {
      method: method,
      credentials: "include",
      headers: headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    var data = {};
    try { data = await r.json(); } catch (e) { /* not JSON */ }
    if (!r.ok) {
      var err = new Error(
        typeof data.detail === "string" ? data.detail : "Request failed (" + r.status + ")."
      );
      err.status = r.status;
      err.reauth = r.headers.get("X-Enlace-Reauth") === "1";
      throw err;
    }
    return data;
  }
  function descriptors(list) {
    return (list || []).map(function (c) {
      return Object.assign({}, c, { id: u2b(c.id) });
    });
  }
  function creationOptions(o) {
    var out = Object.assign({}, o, {
      challenge: u2b(o.challenge),
      user: Object.assign({}, o.user, { id: u2b(o.user.id) }),
      excludeCredentials: descriptors(o.excludeCredentials),
    });
    delete out.purpose;
    return out;
  }
  function requestOptions(o) {
    var out = Object.assign({}, o, {
      challenge: u2b(o.challenge),
      allowCredentials: descriptors(o.allowCredentials),
    });
    delete out.action;
    delete out.audience;
    delete out.purpose;
    return out;
  }
  function credentialJSON(c) {
    var r = c.response;
    var out = {
      id: c.id,
      rawId: b2u(c.rawId),
      type: c.type,
      authenticatorAttachment: c.authenticatorAttachment || null,
      clientExtensionResults: c.getClientExtensionResults ? c.getClientExtensionResults() : {},
      response: { clientDataJSON: b2u(r.clientDataJSON) },
    };
    if (r.attestationObject) {
      out.response.attestationObject = b2u(r.attestationObject);
      out.response.transports = r.getTransports ? r.getTransports() : [];
    }
    if (r.authenticatorData) {
      out.response.authenticatorData = b2u(r.authenticatorData);
      out.response.signature = b2u(r.signature);
      out.response.userHandle = r.userHandle ? b2u(r.userHandle) : null;
    }
    return out;
  }
  async function prepare(url, body) {
    var token = await csrf();
    var options = await send("POST", url, body, token);
    return { url: url, body: body, token: token, options: options, at: Date.now() };
  }
  async function ready(prepared, url, body) {
    return prepared && Date.now() - prepared.at < FRESH_MS ? prepared : prepare(url, body);
  }
  function supported() {
    return !!(window.PublicKeyCredential && navigator.credentials);
  }
  async function conditionalAvailable() {
    return supported() && !!PublicKeyCredential.isConditionalMediationAvailable &&
      (await PublicKeyCredential.isConditionalMediationAvailable());
  }
  async function list() {
    return send("GET", "/auth/passkeys");
  }
  // opts: {purpose, label} enrols a purpose-bound passkey (it never signs in;
  // the system sheet shows `label`, e.g. "Start a job on my Mac").
  function prepareRegister(opts) {
    opts = opts || {};
    var body = opts.purpose ? { purpose: opts.purpose, label: opts.label || "" } : {};
    return prepare("/auth/passkeys/register/options", body);
  }
  async function register(name, prepared) {
    var body = (prepared && prepared.body) || {};
    var p = await ready(prepared, "/auth/passkeys/register/options", body);
    var c = await navigator.credentials.create({ publicKey: creationOptions(p.options) });
    return send("POST", "/auth/passkeys/register/verify", {
      credential: credentialJSON(c),
      name: name || body.label || "",
      purpose: body.purpose || null,
    }, p.token);
  }
  async function remove(id) {
    return send("DELETE", "/auth/passkeys/" + encodeURIComponent(id));
  }
  function prepareSignIn() {
    return prepare("/auth/passkeys/login/options", {});
  }
  async function signIn(opts) {
    opts = opts || {};
    var p = await ready(opts.prepared, "/auth/passkeys/login/options", {});
    var req = { publicKey: requestOptions(p.options) };
    if (opts.conditional) req.mediation = "conditional";
    if (opts.signal) req.signal = opts.signal;
    var c = await navigator.credentials.get(req);
    return send("POST", "/auth/passkeys/login/verify", {
      credential: credentialJSON(c),
      next: opts.next || null,
    }, p.token);
  }
  // A string (the action), {action, purpose}, or {request} (a backend's).
  function prepareStepUp(actionOrRequest) {
    var a = actionOrRequest;
    var body = typeof a === "string"
      ? { action: a }
      : a.request ? { request: a.request } : { action: a.action, purpose: a.purpose || null };
    return prepare("/auth/passkeys/step-up/options", body);
  }
  async function stepUp(actionOrPrepared) {
    var p = typeof actionOrPrepared === "string"
      ? await prepareStepUp(actionOrPrepared)
      : await ready(actionOrPrepared, "/auth/passkeys/step-up/options", actionOrPrepared.body);
    var c = await navigator.credentials.get({ publicKey: requestOptions(p.options) });
    var credential = credentialJSON(c);
    var body = p.body && p.body.request
      ? { request: p.body.request, credential: credential }
      : { action: p.options.action, purpose: p.options.purpose || null, credential: credential };
    var out = await send("POST", "/auth/passkeys/step-up/verify", body, p.token);
    // The signed assertion too, for a verifier that checks it against keys it pinned.
    out.credential = credential;
    return out;
  }
  async function signOut() {
    return send("POST", "/auth/logout", {});
  }
  window.enlacePasskeys = {
    supported: supported,
    conditionalAvailable: conditionalAvailable,
    list: list,
    prepareRegister: prepareRegister,
    register: register,
    remove: remove,
    prepareSignIn: prepareSignIn,
    signIn: signIn,
    prepareStepUp: prepareStepUp,
    stepUp: stepUp,
    signOut: signOut,
  };
})();
