
export async function onRequestPost({ request, env }) {
  try {
    const { email } = await request.json();

    if (
      typeof email !== "string" ||
      email.length > 254 ||
      !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
    ) {
      return Response.json(
        { error: "Please enter a valid email address." },
        { status: 400 }
      );
    }

    if (!env.RESEND_API_KEY || !env.VIDEO_CODES) {
      return Response.json(
        { error: "Email verification is not configured." },
        { status: 503 }
      );
    }

    const normalizedEmail = email.trim().toLowerCase();

    const bytes = new Uint32Array(1);
    crypto.getRandomValues(bytes);
    const code = String(bytes[0] % 1000000).padStart(6, "0");

    const data = new TextEncoder().encode(
      `${normalizedEmail}:${code}`
    );
    const digest = await crypto.subtle.digest("SHA-256", data);
    const hash = Array.from(new Uint8Array(digest))
      .map(b => b.toString(16).padStart(2, "0"))
      .join("");

    await env.VIDEO_CODES.put(
      `code:${normalizedEmail}`,
      JSON.stringify({ hash, attempts: 0 }),
      { expirationTtl: 600 }
    );

    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.RESEND_API_KEY}`,
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        from: "Henry Hues <archive@henryhues.net>",
        to: [normalizedEmail],
        subject: "Your Henry Hues archive access code",
        text: `Your verification code is ${code}.\n\nThis code expires in 10 minutes.\n\nHenry Hues`
      })
    });

    if (!response.ok) {
      await env.VIDEO_CODES.delete(`code:${normalizedEmail}`);
      return Response.json(
        { error: "Unable to send the code. Please try again." },
        { status: 502 }
      );
    }

    return Response.json({
      success: true,
      message: "Check your email for your access code."
    });
  } catch {
    return Response.json(
      { error: "Unable to process your request." },
      { status: 400 }
    );
  }
}
