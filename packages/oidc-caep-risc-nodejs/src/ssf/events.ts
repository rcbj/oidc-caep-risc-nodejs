// The event types this receiver asks for, and what an event's subject names. CAEP (OpenID CAEP 1.0)
// is about sessions; RISC (OpenID RISC 1.0) is about accounts. Subject identifiers are RFC 9493's,
// and a complex subject (`user`, `session`, ...) is SSF 1.0 section 3. The URIs are the same ones
// oidc-caep-client exposes as CAEP, RISC and SSF.

const CAEP = 'https://schemas.openid.net/secevent/caep/event-type/';
const RISC = 'https://schemas.openid.net/secevent/risc/event-type/';
const SSF = 'https://schemas.openid.net/secevent/ssf/event-type/';

/**
 * Every event type of OpenID CAEP 1.0 (eight, about sessions) and OpenID RISC 1.0 (fourteen, about
 * accounts), and SSF 1.0's own two (about the stream). Register a handler with `receiver.on(EVENT.x, …)`.
 */
export const EVENT = {
  sessionRevoked: `${CAEP}session-revoked`,
  tokenClaimsChange: `${CAEP}token-claims-change`,
  credentialChange: `${CAEP}credential-change`,
  assuranceLevelChange: `${CAEP}assurance-level-change`,
  deviceComplianceChange: `${CAEP}device-compliance-change`,
  sessionEstablished: `${CAEP}session-established`,
  sessionPresented: `${CAEP}session-presented`,
  riskLevelChange: `${CAEP}risk-level-change`,
  accountCredentialChangeRequired: `${RISC}account-credential-change-required`,
  accountPurged: `${RISC}account-purged`,
  accountDisabled: `${RISC}account-disabled`,
  accountEnabled: `${RISC}account-enabled`,
  identifierChanged: `${RISC}identifier-changed`,
  identifierRecycled: `${RISC}identifier-recycled`,
  credentialCompromise: `${RISC}credential-compromise`,
  optIn: `${RISC}opt-in`,
  optOutInitiated: `${RISC}opt-out-initiated`,
  optOutCancelled: `${RISC}opt-out-cancelled`,
  optOutEffective: `${RISC}opt-out-effective`,
  recoveryActivated: `${RISC}recovery-activated`,
  recoveryInformationChanged: `${RISC}recovery-information-changed`,
  /** Deprecated by RISC 1.0 in favour of CAEP's session-revoked; still sent by some transmitters. */
  sessionsRevoked: `${RISC}sessions-revoked`,
  verification: `${SSF}verification`,
  streamUpdated: `${SSF}stream-updated`,
} as const;

/** The eight CAEP event types. */
export const CAEP_EVENTS: readonly string[] = Object.values(EVENT).filter((uri) => uri.startsWith(CAEP));
/** The RISC event types, including the deprecated sessions-revoked. */
export const RISC_EVENTS: readonly string[] = Object.values(EVENT).filter((uri) => uri.startsWith(RISC));

/** What the receiver asks the transmitter for by default. */
export const DEFAULT_EVENTS_REQUESTED: readonly string[] = [
  EVENT.sessionRevoked, EVENT.credentialChange, EVENT.assuranceLevelChange, EVENT.tokenClaimsChange,
  EVENT.accountDisabled, EVENT.accountEnabled, EVENT.accountPurged, EVENT.credentialCompromise,
  EVENT.sessionsRevoked, EVENT.accountCredentialChangeRequired,
];

/**
 * The events that end the matching local sessions by default: the session itself was revoked, or the
 * account behind it was disabled, deleted, compromised, or had every session revoked.
 */
export const DEFAULT_ENDING_EVENTS: readonly string[] = [
  EVENT.sessionRevoked, EVENT.accountDisabled, EVENT.accountPurged, EVENT.credentialCompromise, EVENT.sessionsRevoked,
];

/** Who and what an event's subject names, in the terms the session index is searched by. */
export interface SubjectRef {
  /** The person: an `iss_sub`'s `sub`, when its `iss` is the transmitter's issuer. */
  person?: string;
  /** An `email` subject's address. */
  email?: string;
  /** The provider session: a complex subject's `session` (`opaque` id, or an `iss_sub`'s `sub`). */
  idpSession?: string;
}

function simple(id: Record<string, unknown> | undefined, issuer: string): { sub?: string; email?: string; opaque?: string } {
  if (!id || typeof id !== 'object') return {};
  const format = String(id.format ?? id.subject_type ?? '');
  if (format === 'iss_sub' && typeof id.sub === 'string' && (id.iss === undefined || id.iss === issuer)) return { sub: id.sub };
  if (format === 'email' && typeof id.email === 'string') return { email: id.email };
  if (format === 'opaque' && typeof id.id === 'string') return { opaque: id.id };
  if (format === 'aliases' && Array.isArray(id.identifiers)) {
    return Object.assign({}, ...id.identifiers.map((one: unknown) => simple(one as Record<string, unknown>, issuer)));
  }
  return {};
}

/**
 * Reads an event's subject: SSF 1.0's `sub_id` claim, or (deprecated) a `subject` member of the event
 * itself. A complex subject's `user` names the person and its `session` the provider session.
 */
export function subjectOf(subId: unknown, issuer: string): SubjectRef {
  if (!subId || typeof subId !== 'object') return {};
  const id = subId as Record<string, unknown>;
  const format = String(id.format ?? id.subject_type ?? '');
  const out: SubjectRef = {};
  if (format === 'complex' || (!format && (id.user || id.session))) {
    const user = simple(id.user as Record<string, unknown>, issuer);
    const session = simple(id.session as Record<string, unknown>, issuer);
    if (user.sub) out.person = user.sub;
    if (user.email) out.email = user.email;
    const sessionId = session.opaque ?? session.sub;
    if (sessionId) out.idpSession = sessionId;
    return out;
  }
  const one = simple(id, issuer);
  if (one.sub) out.person = one.sub;
  if (one.email) out.email = one.email;
  return out;
}
