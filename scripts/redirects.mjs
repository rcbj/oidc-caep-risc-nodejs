// The redirect URI the demo registers, and the one it sends, are the same address.
// A loopback URI follows the port the demo listens on. Any other host is left as written.

const LOOPBACK = new Set(['localhost', '127.0.0.1', '::1']);

/** Replace the port of a loopback URL. Anything else is returned unchanged. */
export function onPort(url, port) {
  const next = new URL(url);
  if (!LOOPBACK.has(next.hostname)) return url;
  next.port = String(port);
  return next.href;
}

/**
 * The redirect URIs to register.
 * An explicit public URL replaces the origin and keeps the path.
 * Otherwise `port` moves a loopback URI onto the port the demo listens on.
 */
export function redirectsFor(redirectUri, postLogoutRedirectUri, options) {
  if (options.publicUrlGiven && options.publicUrl) {
    const base = new URL(options.publicUrl.endsWith('/') ? options.publicUrl : `${options.publicUrl}/`);
    const move = (value) => {
      const next = new URL(value);
      next.protocol = base.protocol;
      next.hostname = base.hostname;
      next.port = base.port;
      return next.href;
    };
    return { redirectUri: move(redirectUri), postLogoutRedirectUri: move(postLogoutRedirectUri) };
  }
  if (options.port) {
    return {
      redirectUri: onPort(redirectUri, options.port),
      postLogoutRedirectUri: onPort(postLogoutRedirectUri, options.port),
    };
  }
  return { redirectUri, postLogoutRedirectUri };
}

/** The container's PORT wins. Otherwise the environment. An empty or unusable value is absent. */
export function demoPort(envPort, containerPort) {
  const raw = String(containerPort ?? '').trim() || String(envPort ?? '').trim();
  if (!raw) return undefined;
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) return undefined;
  return port;
}
