# Symbolon formal models

The models and proofs that SPEC Section 27 requires. No security property
of the specification is claimed until its lemma here is verified;
`STATUS.md` lists every lemma and its state.

## Running

```sh
cd models
nix develop          # pinned Tamarin, Maude, ProVerif, CryptoVerif, EasyCrypt, z3, cvc5
./run.sh             # every model; non-zero exit if any lemma is not verified
./run.sh log.spthy   # one model

MODEL_TIMEOUT=180 MODEL_HEAP=8g ./run.sh log.spthy   # one model, bounded
```

`MODEL_TIMEOUT` bounds each model in seconds, `MODEL_HEAP` sets the Tamarin
heap. The models here need 8g and a minute each; a model that wants more is
a signal to split it, not to raise the numbers.

Prover output is written to `out/`. A model can pass extra prover flags
in a sibling `<model>.args` file. CI (`.github/workflows/models.yml`)
runs `./run.sh` on every change to `SPEC.md` or `models/`.

## Layout

| File | Active compromise (SPEC 27.2) | Lemmas |
|---|---|---|
| `log.spthy` | none | L-01 uniqueness, extension, `H_accept_cosigned` |
| `log_device.spthy` | `RevealDK` | L-01 authorization for a single quorum |
| `log_witness.spthy` | `CorruptWitnessMajority` | `H_cosign_origin` |
| `reshare.spthy` | `RevealDK` | quorum change and the event after it |

One file per compromise rule, as SPEC 27.2 asks: each lemma then states
exactly which compromises it tolerates. See `STATUS.md` for what is
verified.

Each model starts with a header comment listing its abstractions: what the
model leaves out or simplifies, and so what a verified lemma does not
establish. Every model also carries `sanity_*` exists-trace lemmas showing
that the honest protocol completes, so its safety lemmas are not vacuous.

## Tool notes

- Tamarin 1.12.0 with Maude 3.5.1 crashes when the `natural-numbers`
  builtin is combined with `verify`; models use a free `succ` constructor
  for sequence numbers instead.
- alt-ergo is not in the toolchain (unfree licence); EasyCrypt uses z3 and
  cvc5.
