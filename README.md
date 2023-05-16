# with-digest-fetch

Forked from `digest-fetch`, build for cjs/esm support.

See [https://github.com/devfans/digest-fetch#readme](https://github.com/devfans/digest-fetch#readme) for usage.

## Changes in this fork

- Ships both ESM and CJS bundles with correct module exports.
- Better TypeScript support.

## Install

```sh
npm install with-digest-fetch
```

## Usage

```ts
import DigestClient from "with-digest-fetch";

const client = new DigestClient("user", "password");
await client.fetch(url, options);
```
