# test/fixtures/

Pinned snapshot of production anchors from
[`causallayer-anchor-log`](https://github.com/smq9sn5jck-coder/causallayer-anchor-log),
used to assert that `causallayer-verifier` actually verifies every anchor
the engine has ever published.

```
fixtures/
  anchors/        # Every signed anchor file from causallayer-anchor-log/anchors/
  public-key.pem  # Production Ed25519 SPKI public key
```

To refresh the snapshot:

```bash
git clone https://github.com/smq9sn5jck-coder/causallayer-anchor-log /tmp/anchor-log
rm -rf test/fixtures/anchors && cp -r /tmp/anchor-log/anchors test/fixtures/anchors
rm -f test/fixtures/anchors/*.ots
cp /tmp/anchor-log/public-key.pem test/fixtures/public-key.pem
npm test
```

If `npm test` fails after a refresh, the verifier has regressed against
production anchors — do not publish a new release until it passes again.

The OpenTimestamps `.ots` files are intentionally excluded because the
`causallayer-verifier` library does not (yet) verify OTS proofs in-process;
use `ots verify <anchor>.ots` for that.
