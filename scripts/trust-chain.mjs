// Fetches the provider's listener CA trust chain and writes the file the configuration's tlsCa names.
// iya-sts publishes that bundle at GET /tls/server-certificate: the listener certificate, the
// intermediates, and the root. When the file already holds a chain, the fetch is verified against
// it. Only when it cannot be (no file yet, or a development iya-sts that made a new CA) is the chain
// taken on first use: unverified, but it must name the host, start with the certificate the handshake
// presented, and be signed link by link; compare the printed SHA-256 with iya-sts's PKI page. If that
// document is missing, the handshake's own chain is used.
//
//   node scripts/trust-chain.mjs --config demo/oidc.json
//
// The container runs this before the demo. A failure leaves the file as it is and exits 0, so the
// demo still starts. scripts/configure-iya-sts.ts calls saveTrustChain and does report a failure.

import { X509Certificate } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import https from 'node:https';
import { isIP } from 'node:net';
import { dirname, isAbsolute, resolve } from 'node:path';
import { checkServerIdentity, connect } from 'node:tls';
import { pathToFileURL } from 'node:url';

const TIMEOUT_MS = 10_000;

/** SNI is a hostname. An IP address literal is not one, and Node refuses it. */
function servernameOf(hostname) {
  return isIP(hostname) ? undefined : hostname;
}

/** A path or `file:` path. PEM and `env:` are the configuration's own value, and are not a file to write. */
export function trustPath(raw, baseDir) {
  if (typeof raw !== 'string') return undefined;
  const value = raw.trim();
  if (!value || value.includes('-----BEGIN') || value.startsWith('env:')) return undefined;
  const path = value.startsWith('file:') ? value.slice(5) : value;
  if (!path) return undefined;
  return isAbsolute(path) ? path : resolve(baseDir, path);
}

function certificatesOf(pem) {
  const blocks = String(pem).match(/-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g) ?? [];
  return blocks.map((block) => new X509Certificate(block));
}

function bundleOf(certs) {
  if (!certs.length) throw new Error('the trust chain has no certificates');
  const anchor = [...certs].reverse().find((cert) => cert.subject === cert.issuer) ?? certs[certs.length - 1];
  return {
    pem: `${certs.map((cert) => cert.toString().trim()).join('\n')}\n`,
    anchor,
    count: certs.length,
  };
}

// How each fetch decides whom to trust. With `ca` (the chain the tlsCa file already holds), the
// handshake is checked against it: Node still verifies the chain against `ca` when it does not refuse
// the connection itself, and heldChainRefusal() turns an unverified chain or a host name the leaf does
// not carry into an error before anything is read. Without `ca`, the fetch is trust on first use:
// there is no anchor yet, and acceptFirstUse() below checks what it can.
export function heldChainRefusal(socket, hostname, ca) {
  if (!ca) return undefined;
  if (!socket.authorized) {
    const code = String(socket.authorizationError?.code ?? socket.authorizationError ?? 'CERT_UNTRUSTED');
    const named = code === 'ERR_TLS_CERT_ALTNAME_INVALID'
      ? checkServerIdentity(hostname, socket.getPeerCertificate())
      : undefined;
    if (named) return named;
    return Object.assign(new Error(`the chain in the trust file does not verify the server: ${code}`), { code });
  }
  return checkServerIdentity(hostname, socket.getPeerCertificate()) ?? undefined;
}

/** `GET /tls/server-certificate`, and the leaf the handshake presented. */
function fetchPublished(origin, ca) {
  const target = new URL('/tls/server-certificate', origin);
  return new Promise((resolvePromise, reject) => {
    const servername = servernameOf(target.hostname);
    const req = https.request({
      host: target.hostname,
      port: target.port || 443,
      path: `${target.pathname}${target.search}`,
      method: 'GET',
      agent: false,
      ...(ca ? { ca } : {}),
      rejectUnauthorized: false,
      minVersion: 'TLSv1.2',
      timeout: TIMEOUT_MS,
      ...(servername ? { servername } : {}),
      headers: { accept: 'text/plain' },
    }, (res) => {
      const refusal = heldChainRefusal(res.socket, target.hostname, ca);
      if (refusal) {
        res.destroy();
        reject(refusal);
        return;
      }
      const presented = res.socket.getPeerCertificate();
      const chunks = [];
      res.on('data', (chunk) => chunks.push(chunk));
      res.on('end', () => {
        if ((res.statusCode ?? 0) !== 200) {
          reject(new Error(`${target.href} answered ${res.statusCode}`));
          return;
        }
        try {
          const certs = certificatesOf(Buffer.concat(chunks).toString('utf8'));
          const leaf = presented?.raw ? new X509Certificate(presented.raw) : undefined;
          resolvePromise({ certs, leaf });
        } catch (err) {
          reject(err);
        }
      });
    });
    req.on('timeout', () => req.destroy(new Error(`${target.href} did not answer within ${TIMEOUT_MS / 1000} s`)));
    req.on('error', reject);
    req.end();
  });
}

/** Every certificate the handshake presented, leaf first, including the root when the server sends it. */
function fetchHandshake(origin, ca) {
  const target = new URL(origin);
  return new Promise((resolvePromise, reject) => {
    const servername = servernameOf(target.hostname);
    const socket = connect({
      host: target.hostname,
      port: Number(target.port || 443),
      ...(servername ? { servername } : {}),
      ...(ca ? { ca } : {}),
      rejectUnauthorized: false,
      minVersion: 'TLSv1.2',
    }, () => {
      const certs = [];
      const seen = new Set();
      let current = socket.getPeerCertificate(true);
      const refusal = heldChainRefusal(socket, target.hostname, ca);
      while (!refusal && current?.raw && current.fingerprint256 && !seen.has(current.fingerprint256)) {
        seen.add(current.fingerprint256);
        certs.push(new X509Certificate(current.raw));
        const next = current.issuerCertificate;
        if (!next || next === current || !next.raw) break;
        current = next;
      }
      socket.end();
      if (refusal) {
        reject(refusal);
        return;
      }
      resolvePromise({ certs, leaf: certs[0] });
    });
    socket.setTimeout(TIMEOUT_MS, () => {
      socket.destroy();
      reject(new Error(`${origin} did not complete a TLS handshake`));
    });
    socket.on('error', reject);
  });
}

/**
 * What a first use can still check without an anchor: the leaf names the host, the handshake presented
 * that leaf, and every certificate is signed by the next one up, the top one by itself if it is self-issued.
 */
export function acceptFirstUse(hostname, fetched) {
  const { certs, leaf } = fetched;
  if (!certs.length) throw new Error('the trust chain has no certificates');
  if (!leaf || leaf.fingerprint256 !== certs[0].fingerprint256) {
    throw new Error('the published trust chain does not start with the certificate the handshake presented');
  }
  const mismatch = checkServerIdentity(hostname, certs[0].toLegacyObject());
  if (mismatch) throw mismatch;
  for (let i = 0; i + 1 < certs.length; i += 1) {
    if (!certs[i].checkIssued(certs[i + 1]) || !certs[i].verify(certs[i + 1].publicKey)) {
      throw new Error(`certificate ${i + 1} of the trust chain is not signed by certificate ${i + 2}`);
    }
  }
  const top = certs[certs.length - 1];
  if (top.subject === top.issuer && !top.verify(top.publicKey)) {
    throw new Error('the trust chain\'s self-issued top certificate does not verify its own signature');
  }
}

/** The published trust chain, or the handshake's chain when that document is not served. */
async function fetchChain(origin, ca) {
  try {
    return await fetchPublished(origin, ca);
  } catch (err) {
    if (ca && isVerificationFailure(err)) throw err;
    return fetchHandshake(origin, ca);
  }
}

// The errors that mean the anchor in hand does not lead to the server's chain: a development iya-sts
// makes a new CA when it restarts. A host name the certificate does not carry is not one of them.
const UNVERIFIED = new Set([
  'UNABLE_TO_GET_ISSUER_CERT',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'SELF_SIGNED_CERT_IN_CHAIN',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'CERT_SIGNATURE_FAILURE',
  'CERT_UNTRUSTED',
]);

function isVerificationFailure(err) {
  return UNVERIFIED.has(err?.code);
}

function anchorFile(dest) {
  if (!dest || !existsSync(dest)) return undefined;
  const pem = readFileSync(dest, 'utf8');
  return certificatesOf(pem).length ? pem : undefined;
}

/**
 * The server's trust chain. With `ca` (the tlsCa file's chain), verified against it; when that does
 * not verify the server, or there is no `ca`, taken on first use, after acceptFirstUse()'s checks.
 * `verified` says which.
 */
export async function fetchTrustChain(origin, ca) {
  if (ca) {
    try {
      return { ...bundleOf((await fetchChain(origin, ca)).certs), verified: true };
    } catch (err) {
      if (!isVerificationFailure(err)) throw err;
    }
  }
  const fetched = await fetchChain(origin, undefined);
  acceptFirstUse(new URL(origin).hostname, fetched);
  return { ...bundleOf(fetched.certs), verified: false };
}

/** Writes the chain to `dest`, replacing whatever was there, verified against what was there if it can be. */
export async function saveTrustChain(origin, dest) {
  const chain = await fetchTrustChain(origin, anchorFile(dest));
  mkdirSync(dirname(dest), { recursive: true });
  writeFileSync(dest, chain.pem);
  return { ...chain, path: dest, origin };
}

/** One line for the operator: how this chain came to be trusted. */
export function trustNote(saved) {
  return saved.verified
    ? 'verified against the chain the file already held'
    : 'trusted on first use: compare the sha256 with the Root CA on iya-sts\'s PKI page';
}

function configFromArgv(argv) {
  let config = process.env.OIDC_CONFIG || '';
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === '--config') {
      config = argv[++i] ?? '';
      if (!config) throw new Error('--config needs a value');
    }
  }
  if (!config) throw new Error('trust-chain needs --config <file> or OIDC_CONFIG');
  return resolve(config);
}

async function main() {
  const configPath = configFromArgv(process.argv.slice(2));
  const raw = JSON.parse(readFileSync(configPath, 'utf8'));
  const metadataUrl = String(raw.metadataUrl ?? '').trim();
  if (!metadataUrl) throw new Error(`${configPath} has no metadataUrl`);
  const dest = trustPath(raw.tlsCa, dirname(configPath));
  if (!dest) throw new Error(`${configPath} tlsCa is not a file this process can update`);
  const saved = await saveTrustChain(new URL(metadataUrl).origin, dest);
  console.log(`Saved ${saved.origin}'s listener CA trust chain (${saved.count} certificate(s)) to ${saved.path}`);
  console.log(`  ${trustNote(saved)}`);
  console.log(`  trust anchor ${saved.anchor.subject.replaceAll('\n', ', ')}`);
  console.log(`  sha256 ${saved.anchor.fingerprint256}`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  main().catch((err) => {
    console.error(`tls ca: not updated: ${err.message}`);
    process.exit(0);
  });
}
