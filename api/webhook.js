const crypto = require("crypto");
const https  = require("https");

// Toutes les valeurs sensibles viennent des variables d'environnement Vercel
const STRIPE_WEBHOOK_SEC = process.env.STRIPE_WEBHOOK_SECRET;
const RESEND_API_KEY     = process.env.RESEND_API_KEY;
const XAIM_HMAC_SECRET   = process.env.XAIM_HMAC_SECRET;
const FROM_EMAIL         = process.env.FROM_EMAIL || "X-AIM <noreply@xaim.gg>";

function randSeg() {
  const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
  let s = "";
  for (let i = 0; i < 4; i++) s += chars[Math.floor(Math.random() * chars.length)];
  return s;
}

function generateKey() {
  const s1 = randSeg(), s2 = randSeg(), s3 = randSeg();
  const body = `${s1}-${s2}-${s3}`;
  const check = crypto.createHmac("sha256", XAIM_HMAC_SECRET)
    .update(body).digest("hex").slice(0, 4).toUpperCase();
  return `XAIM-${body}-${check}`;
}

function sendKey(toEmail, licenseKey) {
  const htmlBody = `
<!DOCTYPE html>
<html>
<body style="background:#0a0a0a;color:#fff;font-family:Consolas,monospace;padding:40px;">
  <div style="max-width:520px;margin:0 auto;border:1px solid #cc0000;padding:30px;border-radius:4px;">
    <h1 style="color:#cc0000;letter-spacing:4px;margin:0 0 8px">X-AIM V2</h1>
    <p style="color:#888;margin:0 0 24px;font-size:12px">IA AIMBOT — LICENCE PERSONNELLE</p>
    <p style="color:#ccc;margin:0 0 16px">Merci pour ton achat. Voici ta clé de licence :</p>
    <div style="background:#111;border:1px solid #cc0000;padding:16px;text-align:center;margin:0 0 24px;border-radius:2px;">
      <span style="color:#ff4444;font-size:20px;letter-spacing:3px;font-weight:bold">${licenseKey}</span>
    </div>
    <p style="color:#888;font-size:13px;margin:0 0 8px"><b style="color:#ccc">Installation :</b></p>
    <ol style="color:#888;font-size:13px;margin:0 0 24px;padding-left:20px">
      <li>Télécharge X-AIM depuis GitHub Releases</li>
      <li>Lance INSTALLER.bat en admin</li>
      <li>Lance le raccourci X-AIM sur le bureau</li>
      <li>Entre ta clé dans le launcher</li>
      <li>F1 pour toggle l'aim assist</li>
    </ol>
    <p style="color:#555;font-size:11px;margin:0">Cette clé est personnelle et non transférable.</p>
  </div>
</body>
</html>`;

  const payload = JSON.stringify({
    from:    FROM_EMAIL,
    to:      [toEmail],
    subject: "X-AIM V2 — Ta clé de licence",
    html:    htmlBody,
  });

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: "api.resend.com",
      path:     "/emails",
      method:   "POST",
      headers:  {
        "Authorization":  `Bearer ${RESEND_API_KEY}`,
        "Content-Type":   "application/json",
        "Content-Length": Buffer.byteLength(payload),
      },
    }, (res) => {
      let data = "";
      res.on("data", d => data += d);
      res.on("end", () => resolve({ status: res.statusCode, body: data }));
    });
    req.on("error", reject);
    req.write(payload);
    req.end();
  });
}

function verifyStripeSignature(rawBody, sigHeader, secret) {
  const parts = sigHeader.split(",").reduce((acc, p) => {
    const [k, v] = p.split("=");
    acc[k] = v;
    return acc;
  }, {});
  const signed = crypto.createHmac("sha256", secret)
    .update(`${parts.t}.${rawBody}`).digest("hex");
  if (signed !== parts.v1) throw new Error("Signature invalide");
  if (Math.abs(Date.now() / 1000 - parseInt(parts.t)) > 300) throw new Error("Webhook expiré");
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  let rawBody = "";
  await new Promise((resolve) => {
    req.on("data", chunk => rawBody += chunk);
    req.on("end", resolve);
  });

  try {
    verifyStripeSignature(rawBody, req.headers["stripe-signature"], STRIPE_WEBHOOK_SEC);
  } catch (e) {
    return res.status(400).json({ error: e.message });
  }

  const event = JSON.parse(rawBody);
  if (event.type !== "checkout.session.completed") {
    return res.status(200).json({ received: true });
  }

  const session = event.data.object;
  const email   = session.customer_details?.email || session.customer_email;
  if (!email) return res.status(400).json({ error: "Pas d'email client" });

  const key    = generateKey();
  const sendTo = process.env.TEST_EMAIL_OVERRIDE || email;
  const result = await sendKey(sendTo, key);
  console.log(`[X-AIM] ${email} → ${sendTo} → ${key} (Resend: ${result.status})`);

  return res.status(200).json({ received: true });
}
