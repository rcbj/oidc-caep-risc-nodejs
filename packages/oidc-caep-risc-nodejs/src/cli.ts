#!/usr/bin/env node
// Reads a configuration file and says whether it names a confidential client. It does not print secrets.

import { readConfigFile } from './config.ts';
import { OidcError } from './errors.ts';

function usage(): string {
  return `oidc-caep-risc-nodejs — a confidential OpenID Connect client

Usage
  oidc-caep-risc-nodejs check --config <file>   read the file and print the client, without its secret
  oidc-caep-risc-nodejs help

The library is RelyingParty, imported from 'oidc-caep-risc-nodejs'.`;
}

function main(argv: string[]): void {
  const command = argv[0] ?? 'help';
  if (command === 'help' || command === '--help' || command === '-h') {
    console.log(usage());
    return;
  }
  if (command !== 'check') throw new OidcError('config', `unknown command ${command}\n${usage()}`);
  const at = argv.indexOf('--config');
  const file = at >= 0 ? argv[at + 1] : undefined;
  if (!file) throw new OidcError('config', `check needs --config <file>\n${usage()}`);
  const config = readConfigFile(file);
  console.log(`client_id:  ${config.clientId}`);
  console.log(`auth:       ${config.tokenEndpointAuthMethod}`);
  console.log(`redirect:   ${config.redirectUri}`);
  console.log(`scopes:     ${config.scopes}`);
  console.log(`metadata:   ${config.metadataUrl ?? config.metadata?.issuer ?? '(file)'}`);
  console.log(`secret:     ${config.clientSecret ? 'present' : 'absent'}`);
  console.log(`tls ca:     ${config.tlsCa ? 'present' : 'absent'}`);
  console.log(`ssf:        ${config.ssf?.transmitter ?? 'not configured'}`);
}

try {
  main(process.argv.slice(2));
} catch (err) {
  console.error(err instanceof OidcError ? err.message : (err as Error).message);
  process.exit(1);
}
