/* enlacePasskeys: the browser side of enlace_auth's passkeys.
 *
 * Served at /auth/passkeys/passkeys.js. Any page on the platform can include it:
 *
 *   <script src="/auth/passkeys/passkeys.js"></script>
 *   const {proof} = await enlacePasskeys.stepUp("start job: repo, title");
 *   // send `proof` to your backend, which redeems it at
 *   // POST /auth/passkeys/step-up/redeem {proof, action} before acting.
 *
 * Every call rejects with an Error whose message is safe to show. A user who
 * cancels the system prompt gives err.name === "NotAllowedError"; a request the
 * server refuses because the sign-in is too old gives err.reauth === true.
 */
(function () {
  "use strict";
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
  async function call(method, url, body) {
    var headers = { "Content-Type": "application/json" };
    if (method !== "GET") headers["X-CSRF-Token"] = await csrf();
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
    return Object.assign({}, o, {
      challenge: u2b(o.challenge),
      user: Object.assign({}, o.user, { id: u2b(o.user.id) }),
      excludeCredentials: descriptors(o.excludeCredentials),
    });
  }
  function requestOptions(o) {
    var out = Object.assign({}, o, {
      challenge: u2b(o.challenge),
      allowCredentials: descriptors(o.allowCredentials),
    });
    delete out.action;
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
  function supported() {
    return !!(window.PublicKeyCredential && navigator.credentials);
  }
  async function conditionalAvailable() {
    return supported() && !!PublicKeyCredential.isConditionalMediationAvailable &&
      (await PublicKeyCredential.isConditionalMediationAvailable());
  }
  async function list() {
    return call("GET", "/auth/passkeys");
  }
  async function register(name) {
    var o = await call("POST", "/auth/passkeys/register/options", {});
    var c = await navigator.credentials.create({ publicKey: creationOptions(o) });
    return call("POST", "/auth/passkeys/register/verify", {
      credential: credentialJSON(c),
      name: name || "",
    });
  }
  async function remove(id) {
    return call("DELETE", "/auth/passkeys/" + encodeURIComponent(id));
  }
  async function signIn(opts) {
    opts = opts || {};
    var o = await call("POST", "/auth/passkeys/login/options", {});
    var req = { publicKey: requestOptions(o) };
    if (opts.conditional) req.mediation = "conditional";
    if (opts.signal) req.signal = opts.signal;
    var c = await navigator.credentials.get(req);
    return call("POST", "/auth/passkeys/login/verify", {
      credential: credentialJSON(c),
      next: opts.next || null,
    });
  }
  async function stepUp(action) {
    var o = await call("POST", "/auth/passkeys/step-up/options", { action: action });
    var c = await navigator.credentials.get({ publicKey: requestOptions(o) });
    return call("POST", "/auth/passkeys/step-up/verify", {
      action: o.action,
      credential: credentialJSON(c),
    });
  }
  async function signOut() {
    return call("POST", "/auth/logout", {});
  }
  window.enlacePasskeys = {
    signOut: signOut,
    supported: supported,
    conditionalAvailable: conditionalAvailable,
    list: list,
    register: register,
    remove: remove,
    signIn: signIn,
    stepUp: stepUp,
  };
})();
