export default {
  async fetch(request, env) {
    const password = env.GAME_PASSWORD;
    if (!password) return new Response("Game access is not configured.", { status: 503, headers: { "Cache-Control": "no-store" } });

    const authorization = request.headers.get("Authorization") || "";
    let supplied = "";
    if (authorization.startsWith("Basic ")) {
      try {
        const decoded = atob(authorization.slice(6));
        const separator = decoded.indexOf(":");
        if (separator >= 0 && decoded.slice(0, separator) === "player") {
          supplied = decoded.slice(separator + 1);
        }
      } catch {}
    }

    const encoder = new TextEncoder();
    const expected = await crypto.subtle.digest("SHA-256", encoder.encode(password));
    const actual = await crypto.subtle.digest("SHA-256", encoder.encode(supplied));
    const a = new Uint8Array(expected), b = new Uint8Array(actual);
    let mismatch = 0;
    for (let i = 0; i < a.length; i++) mismatch |= a[i] ^ b[i];

    if (!supplied || mismatch !== 0) {
      return new Response("Authentication required.", {
        status: 401,
        headers: {
          "WWW-Authenticate": 'Basic realm="OpusCraft"',
          "Cache-Control": "no-store",
          "X-Content-Type-Options": "nosniff"
        }
      });
    }
    return env.ASSETS.fetch(request);
  }
};
