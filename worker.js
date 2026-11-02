
const OAUTH = "https://apis.roblox.com/oauth/v1";

function randomString(bytes = 32) {
  const data = crypto.getRandomValues(new Uint8Array(bytes));
  return btoa(String.fromCharCode(...data))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

async function challenge(verifier) {
  const hash = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(verifier)
  );

  return btoa(String.fromCharCode(...new Uint8Array(hash)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=/g, "");
}

function response(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store"
    }
  });
}

function html(message) {
  return new Response(`<!doctype html>
  <html><head><meta name="viewport" content="width=device-width">
  <title>NOVEX STUDIO</title></head>
  <body style="background:#100b19;color:white;font-family:Arial;padding:30px">
  <h1 style="color:#bd83ff">NØV3X STUDIO</h1>
  <p>${message}</p>
  <p>You can return to NOVEX STUDIO.</p>
  </body></html>`, {
    headers: {
      "Content-Type": "text/html;charset=UTF-8",
      "Cache-Control": "no-store"
    }
  });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (!env.CLIENT_ID || !env.REDIRECT_URI || !env.TOKENS) {
      return response({ error: "Backend configuration missing" }, 500);
    }

    // Health check
    if (url.pathname === "/health") {
      return response({ status: "NOVEX backend online" });
    }

    // Begin Roblox OAuth
    if (url.pathname === "/login") {
      const state = randomString();
      const verifier = randomString(48);
      const codeChallenge = await challenge(verifier);

      await env.TOKENS.put(
        "state:" + state,
        verifier,
        { expirationTtl: 600 }
      );

      const auth = new URL(OAUTH + "/authorize");

      auth.searchParams.set("client_id", env.CLIENT_ID);
      auth.searchParams.set("redirect_uri", env.REDIRECT_URI);
      auth.searchParams.set("response_type", "code");
      auth.searchParams.set("scope", "openid profile");
      auth.searchParams.set("state", state);
      auth.searchParams.set("code_challenge", codeChallenge);
      auth.searchParams.set("code_challenge_method", "S256");

      return Response.redirect(auth.toString(), 302);
    }

    // Roblox OAuth callback
    if (url.pathname === "/callback") {
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");

      if (!code || !state) {
        return html("Authorization was not completed.");
      }

      const verifier = await env.TOKENS.get("state:" + state);

      if (!verifier) {
        return html("Invalid or expired authorization session.");
      }

      await env.TOKENS.delete("state:" + state);

      const body = new URLSearchParams({
        grant_type: "authorization_code",
        client_id: env.CLIENT_ID,
        code,
        redirect_uri: env.REDIRECT_URI,
        code_verifier: verifier
      });

      const tokenResponse = await fetch(OAUTH + "/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded"
        },
        body
      });

      if (!tokenResponse.ok) {
        return html("Roblox token exchange failed. Please try again.");
      }

      const tokens = await tokenResponse.json();

      if (!tokens.access_token) {
        return html("Roblox did not return an access token.");
      }

      const profileResponse = await fetch(OAUTH + "/userinfo", {
        headers: {
          Authorization: "Bearer " + tokens.access_token
        }
      });

      if (!profileResponse.ok) {
        return html("Could not retrieve your Roblox profile.");
      }

      const profile = await profileResponse.json();
      const session = randomString(32);

      // Store tokens privately in Cloudflare KV.
      await env.TOKENS.put(
        "session:" + session,
        JSON.stringify({
          access_token: tokens.access_token,
          refresh_token: tokens.refresh_token,
          expires_at: Date.now() + (tokens.expires_in || 900) * 1000,
          profile
        }),
        { expirationTtl: 60 * 60 * 24 * 90 }
      );

      const username = String(
        profile.preferred_username || profile.nickname || "Creator"
      );

      const safeName = username.replace(/[<>&"']/g, "");

      return new Response(
        `<!doctype html>
        <html>
        <head>
          <meta name="viewport" content="width=device-width">
          <title>NOVEX STUDIO Connected</title>
        </head>
        <body style="background:#100b19;color:white;font-family:Arial;padding:30px">
          <h1 style="color:#bd83ff">NØV3X STUDIO</h1>
          <h2>Roblox connected!</h2>
          <p>Welcome, ${safeName}.</p>
          <p>Your Roblox authorization was successful.</p>
        </body>
        </html>`,
        {
          headers: {
            "Content-Type": "text/html;charset=UTF-8",
            "Cache-Control": "no-store",
            "Set-Cookie":
              `novex_session=${session}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=7776000`
          }
        }
      );
    }

    // Check connected Roblox account
    if (url.pathname === "/me") {
      const cookie = request.headers.get("Cookie") || "";
      const match = cookie.match(/(?:^|;\s*)novex_session=([A-Za-z0-9_-]+)/);

      if (!match) {
        return response({ connected: false }, 401);
      }

      const key = "session:" + match[1];
      const raw = await env.TOKENS.get(key);

      if (!raw) {
        return response({ connected: false }, 401);
      }

      const session = JSON.parse(raw);

      // Refresh expired access token
      if (Date.now() >= session.expires_at) {
        if (!session.refresh_token) {
          return response({ connected: false }, 401);
        }

        const refreshBody = new URLSearchParams({
          grant_type: "refresh_token",
          client_id: env.CLIENT_ID,
          refresh_token: session.refresh_token
        });

        const refreshed = await fetch(OAUTH + "/token", {
          method: "POST",
          headers: {
            "Content-Type": "application/x-www-form-urlencoded"
          },
          body: refreshBody
        });

        if (!refreshed.ok) {
          await env.TOKENS.delete(key);
          return response({ connected: false }, 401);
        }

        const newTokens = await refreshed.json();

        session.access_token = newTokens.access_token;
        session.refresh_token =
          newTokens.refresh_token || session.refresh_token;
        session.expires_at =
          Date.now() + (newTokens.expires_in || 900) * 1000;

        await env.TOKENS.put(
          key,
          JSON.stringify(session),
          { expirationTtl: 60 * 60 * 24 * 90 }
        );
      }

      return response({
        connected: true,
        username: session.profile.preferred_username,
        displayName: session.profile.name,
        userId: session.profile.sub
      });
    }

    // Disconnect
    if (url.pathname === "/logout") {
      const cookie = request.headers.get("Cookie") || "";
      const match = cookie.match(/(?:^|;\s*)novex_session=([A-Za-z0-9_-]+)/);

      if (match) {
        await env.TOKENS.delete("session:" + match[1]);
      }

      return new Response("Roblox session disconnected.", {
        headers: {
          "Set-Cookie":
            "novex_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
          "Cache-Control": "no-store"
        }
      });
    }

    return response({ error: "Not found" }, 404);
  }
};
