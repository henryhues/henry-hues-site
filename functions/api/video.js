 
const FILMS = {
  celine: "celine-2000-2006-final-audio.mov",
  lifting: "lifting-me-2-final-audio.mov",
};

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function verifyToken(token, secret) {
  if (!token || !secret) return false;

  const parts = token.split(".");
  if (parts.length !== 2) return false;

  const [payload, signature] = parts;
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const expected = toBase64Url(
    new Uint8Array(
      await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(payload))
    )
  );

  if (expected.length !== signature.length) return false;

  let mismatch = 0;
  for (let i = 0; i < expected.length; i++) {
    mismatch |= expected.charCodeAt(i) ^ signature.charCodeAt(i);
  }
  if (mismatch !== 0) return false;

  try {
    const normalized = payload.replace(/-/g, "+").replace(/_/g, "/");
    const decoded = JSON.parse(atob(normalized));
    return typeof decoded.exp === "number" &&
      decoded.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

export async function onRequestGet({ request, env }) {
  const url = new URL(request.url);
  const film = url.searchParams.get("film");
  const token = request.headers.get("Authorization")?.replace(/^Bearer\s+/i, "");

  if (!Object.hasOwn(FILMS, film)) {
    return new Response("Film not found", { status: 404 });
  }

  if (!(await verifyToken(token, env.VIDEO_SESSION_SECRET))) {
    return new Response("Verification required", { status: 401 });
  }

  if (!env.VIDEO_BUCKET) {
    return new Response("Storage not configured", { status: 503 });
  }

  const key = FILMS[film];
  const range = request.headers.get("Range");
  const object = await env.VIDEO_BUCKET.get(
    key,
    range ? { range: request.headers } : {}
  );

  if (!object) {
    return new Response("Video not found", { status: 404 });
  }

  const headers = new Headers();
  headers.set("Content-Type", "video/quicktime");
  headers.set("Cache-Control", "private, no-store");
  headers.set("Accept-Ranges", "bytes");
  headers.set("X-Content-Type-Options", "nosniff");

  if (object.range) {
    const { offset, length } = object.range;
    headers.set(
      "Content-Range",
      `bytes ${offset}-${offset + length - 1}/${object.size}`
    );
    headers.set("Content-Length", String(length));
    return new Response(object.body, { status: 206, headers });
  }

  headers.set("Content-Length", String(object.size));
  return new Response(object.body, { status: 200, headers });
}
