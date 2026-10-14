const { Issuer, generators } = require('openid-client');

let client = null;

async function setupOIDC() {
  if (!process.env.OIDC_ISSUER) throw new Error('OIDC_ISSUER تنظیم نشده است');
  if (!process.env.OIDC_CLIENT_ID || !process.env.OIDC_CLIENT_SECRET)
    throw new Error('OIDC_CLIENT_ID / OIDC_CLIENT_SECRET تنظیم نشده‌اند');
  if (!process.env.OIDC_REDIRECT_URI) throw new Error('OIDC_REDIRECT_URI تنظیم نشده است');

  const issuer = await Issuer.discover(process.env.OIDC_ISSUER);
  client = new issuer.Client({
    client_id: process.env.OIDC_CLIENT_ID,
    client_secret: process.env.OIDC_CLIENT_SECRET,
    redirect_uris: [process.env.OIDC_REDIRECT_URI],
    response_types: ['code'],
  });
  console.log('✅ OIDC client آماده شد:', issuer.metadata.issuer);
}

function getAuthorizationUrl(req) {
  if (!client) throw new Error('OIDC هنوز آماده نیست');
  const code_verifier = generators.codeVerifier();
  const state = generators.state();
  const nonce = generators.nonce();

  req.session.code_verifier = code_verifier;
  req.session.state = state;
  req.session.nonce = nonce;

  return client.authorizationUrl({
    scope: 'openid profile email',
    code_challenge: generators.codeChallenge(code_verifier),
    code_challenge_method: 'S256',
    state,
    nonce,
  });
}

async function handleCallback(req) {
  if (!client) throw new Error('OIDC هنوز آماده نیست');
  const params = client.callbackParams(req);
  const tokenSet = await client.callback(
    process.env.OIDC_REDIRECT_URI,
    params,
    {
      code_verifier: req.session.code_verifier,
      state: req.session.state,
      nonce: req.session.nonce,
    }
  );
  // پاک‌سازی مقادیر یک‌بارمصرف
  delete req.session.code_verifier;
  delete req.session.state;
  delete req.session.nonce;
  return tokenSet;
}

// اختیاری: خروج از SSO هم (فقط اگر IdP پایان-جلسه پشتیبانی کند و فعالش کنید)
function getEndSessionUrl(idTokenHint) {
  try {
    if (process.env.OIDC_RP_LOGOUT !== 'true' || !client) return null;
    const ep = client.issuer && client.issuer.end_session_endpoint;
    if (!ep) return null;
    const u = new URL(ep);
    if (idTokenHint) u.searchParams.set('id_token_hint', idTokenHint);
    const origin = process.env.PUBLIC_ORIGIN ||
      (process.env.OIDC_REDIRECT_URI ? new URL(process.env.OIDC_REDIRECT_URI).origin : null);
    if (origin) u.searchParams.set('post_logout_redirect_uri', origin);
    return u.toString();
  } catch { return null; }
}

module.exports = { setupOIDC, getAuthorizationUrl, handleCallback, getEndSessionUrl };