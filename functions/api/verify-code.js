 
const encoder = new TextEncoder();

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

async function createToken(email, secret) {
  const expires = Math.floor(Date.now() / 1000) + 3600;

  const payload = toBase64Url(
    encoder.encode(JSON.stringify({
      email,
      exp: expires
    }))
  );

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    encoder.encode(payload)
  );

  return `${payload}.${toBase64Url(new Uint8Array(signature))}`;
}

export async function onRequestPost({ request, env }) {
  try {
    if (!env.VIDEO_CODES || !env.VIDEO_SESSION_SECRET) {
      return Response.json(
        { error: "Verification is not configured." },
        { status: 503 }
      );
    }

    const body = await request.json();
    const email = String(body.email || "").trim().toLowerCase();
    const code = String(body.code || "").trim();

    if (
      email.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) ||
      !/^\d{6}$/.test(code)
    ) {
      return Response.json(
        { error: "Invalid email or verification code." },
        { status: 400 }
      );
    }

    const key = `code:${email}`;
    const stored = await env.VIDEO_CODES.get(key, "json");

    if (!stored || stored.attempts >= 5) {
      return Response.json(
        { error: "Code expired or unavailable. Request a new code." },
        { status: 401 }
      );
    }

    const digest = await crypto.subtle.digest(
      "SHA-256",
      encoder.encode(`${email}:${code}`)
    );

    const hash = Array.from(new Uint8Array(digest))
      .map(byte => byte.toString(16).padStart(2, "0"))
      .join("");

    if (hash !== stored.hash) {
      await env.VIDEO_CODES.put(
        key,
        JSON.stringify({
          ...stored,
          attempts: stored.attempts + 1
        }),
        { expirationTtl: 600 }
      );

      return Response.json(
        { error: "Incorrect verification code." },
        { status: 401 }
      );
    }

    await env.VIDEO_CODES.delete(key);

    const token = await createToken(
      email,
      env.VIDEO_SESSION_SECRET
    );

    return Response.json({
      success: true,
      token,
      expiresIn: 3600
    });
  } catch {
    return Response.json(
      { error: "Unable to verify code." },
      { status: 400 }
    );
  }
}
