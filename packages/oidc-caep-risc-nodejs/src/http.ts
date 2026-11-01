// The back channel: discovery, the token endpoint, UserInfo, and the Shared Signals transmitter.
// node:http(s) only. TLS is always verified; `ca` is the listener's CA trust chain (one PEM bundle,
// leaf through root) added to node's own store. Answers are capped.

import http from 'node:http';
import https from 'node:https';
import { rootCertificates } from 'node:tls';
import { OidcError, type OidcErrorCode } from './errors.ts';

const MAX_BYTES = 2 * 1024 * 1024;
const TIMEOUT_MS = 15_000;

export interface TlsOptions {
  /** PEM CA trust chain for the TLS listener, in addition to node's own store. */
  ca?: string;
  /** A client certificate and key to present (mutual TLS), PEM. */
  cert?: string;
  key?: string;
}

export interface HttpAnswer {
  status: number;
  contentType: string;
  body: string;
}

export function send(url: string, init: { method?: string; headers?: Record<string, string>; body?: string },
  tls: TlsOptions, code: OidcErrorCode): Promise<HttpAnswer> {
  const target = new URL(url);
  if (target.protocol !== 'https:' && target.protocol !== 'http:') {
    return Promise.reject(new OidcError(code, `${url} is not an http(s) URL`));
  }
  const payload = init.body === undefined ? undefined : Buffer.from(init.body, 'utf8');
  const options: https.RequestOptions = {
    method: init.method ?? 'GET',
    headers: { ...(init.headers ?? {}), ...(payload ? { 'content-length': String(payload.length) } : {}) },
    timeout: TIMEOUT_MS,
  };
  if (target.protocol === 'https:') {
    if (tls.ca) options.ca = [tls.ca, ...rootCertificates];
    if (tls.cert && tls.key) {
      options.cert = tls.cert;
      options.key = tls.key;
    }
  }
  const lib = target.protocol === 'https:' ? https : http;
  return new Promise((resolve, reject) => {
    const req = lib.request(target, options, (res) => {
      const chunks: Buffer[] = [];
      let size = 0;
      res.on('data', (chunk: Buffer) => {
        size += chunk.length;
        if (size > MAX_BYTES) {
          req.destroy(new OidcError(code, `${url} answered more than ${MAX_BYTES} bytes`));
          return;
        }
        chunks.push(chunk);
      });
      res.on('end', () => resolve({
        status: res.statusCode ?? 0,
        contentType: String(res.headers['content-type'] ?? ''),
        body: Buffer.concat(chunks).toString('utf8'),
      }));
      res.on('error', reject);
    });
    req.on('timeout', () => req.destroy(new OidcError(code, `${url} did not answer within ${TIMEOUT_MS / 1000} s`)));
    req.on('error', (err) => reject(err instanceof OidcError ? err : new OidcError(code, `${url}: ${err.message}`, { cause: err })));
    if (payload) req.write(payload);
    req.end();
  });
}
