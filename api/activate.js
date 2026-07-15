const crypto = require("crypto");
const https  = require("https");

const XAIM_HMAC_SECRET   = process.env.XAIM_HMAC_SECRET;
const SUPABASE_URL        = process.env.SUPABASE_URL;
const SUPABASE_SERVICE_KEY = process.env.SUPABASE_SERVICE_KEY;

function validFormat(key) {
  const parts = key.trim().toUpperCase().split("-");
  if (parts.length !== 5 || parts[0] !== "XAIM") return false;
  const body  = parts.slice(1, 4).join("-");
  const check = crypto.createHmac("sha256", XAIM_HMAC_SECRET)
    .update(body).digest("hex").slice(0, 4).toUpperCase();
  return check === parts[4];
}

function sbReq(method, path, body) {
  const base = new URL(SUPABASE_URL);
  const payload = body ? JSON.stringify(body) : null;
  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: base.hostname,
      path:     `/rest/v1${path}`,
      method,
      headers: {
        "apikey":        SUPABASE_SERVICE_KEY,
        "Authorization": `Bearer ${SUPABASE_SERVICE_KEY}`,
        "Content-Type":  "application/json",
        "Prefer":        "return=representation",
        ...(payload ? { "Content-Length": Buffer.byteLength(payload) } : {}),
      },
    }, (res) => {
      let data = "";
      res.on("data", d => data += d);
      res.on("end", () => {
        try { resolve({ status: res.statusCode, body: data ? JSON.parse(data) : null }); }
        catch(e) { resolve({ status: res.statusCode, body: null }); }
      });
    });
    req.on("error", reject);
    if (payload) req.write(payload);
    req.end();
  });
}

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });

  const { key, hwid } = req.body || {};
  if (!key || !hwid) return res.status(400).json({ ok: false, error: "MISSING_PARAMS" });

  const cleanKey = key.trim().toUpperCase();

  if (!validFormat(cleanKey))
    return res.status(200).json({ ok: false, error: "INVALID_KEY" });

  const { status, body } = await sbReq(
    "GET",
    `/licenses?key=eq.${encodeURIComponent(cleanKey)}&select=key,hwid`
  );

  if (status !== 200 || !body || body.length === 0)
    return res.status(200).json({ ok: false, error: "KEY_NOT_FOUND" });

  const record = body[0];

  if (!record.hwid) {
    await sbReq("PATCH", `/licenses?key=eq.${encodeURIComponent(cleanKey)}`, {
      hwid,
      activated_at: new Date().toISOString(),
    });
    return res.status(200).json({ ok: true, first: true });
  }

  if (record.hwid === hwid)
    return res.status(200).json({ ok: true });

  return res.status(200).json({ ok: false, error: "HWID_MISMATCH" });
}
