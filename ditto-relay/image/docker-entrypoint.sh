#!/bin/sh
set -eu

# The relay requires a bech32 nsec signing key. Generate it on first start and
# keep it in app data so the relay identity survives restarts, updates, and
# backups. Set NOSTR_SECRET_KEY to use an existing key instead.
KEY_DIR="${DITTO_RELAY_KEY_DIR:-/keys}"

if [ -z "${NOSTR_SECRET_KEY:-}" ]; then
  if [ -s "$KEY_DIR/nsec" ]; then
    NOSTR_SECRET_KEY="$(cat "$KEY_DIR/nsec")"
    if [ -s "$KEY_DIR/npub" ]; then
      echo "ditto-relay: using relay npub $(cat "$KEY_DIR/npub")" >&2
    fi
  else
    mkdir -p "$KEY_DIR"
    NOSTR_SECRET_KEY="$(DITTO_RELAY_KEY_DIR="$KEY_DIR" bun -e '
      import { generateSecretKey, getPublicKey } from "nostr-tools/pure";
      import { nip19 } from "nostr-tools";
      import { renameSync, writeFileSync } from "node:fs";
      import { join } from "node:path";

      const dir = process.env.DITTO_RELAY_KEY_DIR;
      const secretKey = generateSecretKey();
      const nsec = nip19.nsecEncode(secretKey);
      const npub = nip19.npubEncode(getPublicKey(secretKey));

      const write = (name, content, mode) => {
        const temporaryPath = join(dir, `.${name}.tmp`);
        writeFileSync(temporaryPath, `${content}\n`, { mode });
        renameSync(temporaryPath, join(dir, name));
      };

      write("nsec", nsec, 0o600);
      write("npub", npub, 0o644);
      process.stdout.write(nsec);
    ')"
    echo "ditto-relay: generated relay npub $(cat "$KEY_DIR/npub")" >&2
  fi
  export NOSTR_SECRET_KEY
fi

exec "$@"