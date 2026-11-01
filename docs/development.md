---
title: Development and releases
---

# Development and releases

## Tests

```sh
npm install
npm test
npm run build
```

`npm test` runs `node:test` on the TypeScript sources: the confidential client against a stub provider (discovery, PKCE, the three client authentication methods, pushed authorization, ID token checks, refresh, client credentials), the Shared Signals receiver against a stub transmitter, the setup script's plan, and the version numbering. Nothing is fetched from a network except `npm view` when a version command asks what is already published, and the tests set `NPM_PUBLISHED_VERSIONS` so they do not.

`npm run build` compiles `packages/oidc-caep-risc-nodejs/src` to `dist/` with TypeScript 7, strict. The tests are not part of that compilation. Node runs them by stripping the types.

Node.js 22.18 or later is required to run the TypeScript sources. The published package is JavaScript and runs on Node 22.12 or later (`require()` of an ES module).

## Continuous integration

| Workflow | Runs on | Does |
|---|---|---|
| `tests.yml` | every push and pull request | `npm test`, the build, the manifests check, then the demo image: the sign-in page and a `/login` redirect that carries `response_type=code` and `code_challenge` |
| `npm-publish.yml` | pushes to `main` and `develop` that change the package | tests, stamps the version, packs, and publishes to npm with provenance |
| `pages.yml` | pushes to `main` that change the docs or the source | builds this site and the TypeDoc reference |

The demo job uses a metadata file (`OIDC_METADATA_FILE`) so `/login` does not contact a provider.

## Branches

- **`develop`** is where work comes together: branch from it and merge back into it.
- **`main`** is what is released.

## Versions and releases

`M.N` is in the `VERSION` file; the patch number is worked out at build time from what is on npm (`scripts/version.mjs`). `main` publishes `M.N.P` under `latest`; `develop` publishes `M.N.P-next.R` under `next`. After bumping `VERSION`, run `npm run version:sync`.

The first publish needs the repository secret `NPM_TOKEN`. After the package exists, trusted publishing (this repository, workflow `npm-publish.yml`, environment `npm`) replaces it.

## One-time setup on GitHub

**GitHub Pages** (`pages.yml`). Pages must exist and build from GitHub Actions. Someone with admin rights on the repository does it once:

```sh
gh api -X POST repos/rcbj/oidc-caep-risc-nodejs/pages -f build_type=workflow
```

or **Settings → Pages → Source: GitHub Actions**. The site is then published at <https://rcbj.github.io/oidc-caep-risc-nodejs/>.

## License

Business Source License 1.1. Licensed Work: oidc-caep-risc-nodejs 0.1 and later. Licensor: Iya CyberSecurity Solutions, LLC. Additional Use Grant: None. Change License: MIT, four years after publication.
