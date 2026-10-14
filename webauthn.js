const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const RP_NAME = 'حضور و غیاب دانشگاه';
let RP_ID = null, EXPECTED_ORIGIN = null;

function setupWebAuthn() {
  const origin = process.env.PUBLIC_ORIGIN ||
    (process.env.OIDC_REDIRECT_URI ? new URL(process.env.OIDC_REDIRECT_URI).origin : null);
  if (!origin) throw new Error('برای WebAuthn مقدار PUBLIC_ORIGIN یا OIDC_REDIRECT_URI لازم است');
  EXPECTED_ORIGIN = origin;
  RP_ID = new URL(origin).hostname;
  console.log(`✅ WebAuthn: rpID=${RP_ID} origin=${origin}`);
}

function b64ToU8(s) {
  return Uint8Array.from(Buffer.from(String(s).replace(/-/g, '+').replace(/_/g, '/'), 'base64'));
}
function u8ToB64(u8) {
  return Buffer.from(u8).toString('base64')
    .replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

async function registrationOptions({ excludeCredentials = [], studentId, userName }) {
  return generateRegistrationOptions({
    rpName: RP_NAME,
    rpID: RP_ID,
    userID: new TextEncoder().encode(studentId),
    userName: userName || studentId,
    attestationType: 'none',
    excludeCredentials: excludeCredentials.map(c => ({ id: c.credential_id })),
    authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
  });
}

async function verifyRegistration({ response, expectedChallenge }) {
  return verifyRegistrationResponse({
    response,
    expectedChallenge,
    expectedOrigin: EXPECTED_ORIGIN,
    expectedRPID: RP_ID,
    requireUserVerification: true,
  });
}

async function authenticationOptions({ allowCredentials = [] }) {
  return generateAuthenticationOptions({
    rpID: RP_ID,
    userVerification: 'required',
    allowCredentials: allowCredentials.map(c => ({ id: c.credential_id })),
  });
}

async function verifyAuthentication({ response, expectedChallenge, credential }) {
  return verifyAuthenticationResponse({
    response,
    expectedChallenge,
    expectedOrigin: EXPECTED_ORIGIN,
    expectedRPID: RP_ID,
    authenticator: {
      credentialID: b64ToU8(credential.credential_id),
      credentialPublicKey: new Uint8Array(credential.public_key),
      counter: credential.counter || 0,
    },
    requireUserVerification: true,
  });
}

module.exports = { setupWebAuthn, registrationOptions, verifyRegistration, authenticationOptions, verifyAuthentication, u8ToB64 };