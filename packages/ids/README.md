# @flametrench/ids

Prefixed wire-format identifiers for [Flametrench](https://github.com/flametrench/spec).

```ts
import { generate, encode, decode, isValid } from "@flametrench/ids";

generate("usr");
// → "usr_0190f2a81b3c7abc8123456789abcdef"

encode("org", "0190f2a8-1b3c-7abc-8123-456789abcdef");
// → "org_0190f2a81b3c7abc8123456789abcdef"

decode("usr_0190f2a81b3c7abc8123456789abcdef");
// → { type: "usr", uuid: "0190f2a8-1b3c-7abc-8123-456789abcdef" }

isValid("usr_0190f2a81b3c7abc8123456789abcdef");          // true
isValid("usr_0190f2a81b3c7abc8123456789abcdef", "org");   // false
```

## Why prefixed IDs

Flametrench uses UUIDv7 in storage and prefixed strings on the wire. The wire format is self-describing: `usr_...` is a user, `org_...` is an organization, `ses_...` is a session. This is the Stripe playbook, and it pays off in every log line, support ticket, and debugger session.

The specification details live at [flametrench/spec/docs/ids.md](https://github.com/flametrench/spec/blob/main/docs/ids.md). The Laravel SDK exposes the same API shape in PHP: [flametrench/ids](https://packagist.org/packages/flametrench/ids).

## Install

```bash
pnpm add @flametrench/ids
# or
npm install @flametrench/ids
```

Requires Node 20 or newer. ESM-only (no CommonJS build).

## Registered type prefixes

The specification reserves the following prefixes:

| Prefix | Resource            | Spec version |
| ------ | ------------------- | ------------ |
| `usr`  | User                | v0.1         |
| `org`  | Organization        | v0.1         |
| `mem`  | Membership          | v0.1         |
| `inv`  | Invitation          | v0.1         |
| `ses`  | Session             | v0.1         |
| `cred` | Credential          | v0.1         |
| `tup`  | Authorization tuple | v0.1         |
| `mfa`  | MFA factor          | v0.2         |
| `shr`  | Share token         | v0.2         |

Implementations must not invent prefixes outside the specification. New prefixes are added through the specification's RFC process.

## Type narrowing at API boundaries

The `isId` type guard narrows `unknown` to `string` when a value is a valid Flametrench identifier. Useful in route handlers, webhook processors, and any boundary where incoming values need validation before use.

```ts
import { isId } from "@flametrench/ids";

export async function loadUser(raw: unknown) {
  if (!isId(raw, "usr")) {
    throw new Response("Invalid user id", { status: 400 });
  }

  // `raw` is narrowed to `string` here, and is guaranteed to be a user id.
  return fetchUserById(raw);
}
```

## Testing

```bash
pnpm install
pnpm test
```

The test suite uses Vitest and covers encoding, decoding, validation, generation, round-trip properties, sortability, and cross-language parity with the PHP SDK.

## License

Apache License 2.0. Copyright 2026 NDC Digital, LLC.
