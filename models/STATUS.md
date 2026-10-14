# Model status

Every lemma of SPEC Section 27 and the model that carries it. A property is
claimed only where its lemma reads **verified** here.

Run with `MODEL_TIMEOUT=180 ./run.sh <model>` to reproduce a single model.
`./run.sh` exits non-zero while any lemma below is unverified.

| Lemma | Model | State |
|---|---|---|
| L-01 uniqueness (`L01_one_head_per_seq`) | `log.spthy` | verified |
| L-01 uniqueness under device-key compromise | `log_device.spthy` | verified |
| L-01 uniqueness under witness compromise | `log_witness.spthy` | verified |
| L-01 extension (`L01_extends_previous`) | `log.spthy`, `log_device.spthy`, `log_witness.spthy` | verified |
| L-01 authorization, no quorum change (`L01_authorized`) | `log_device.spthy` | verified |
| every acceptance was co-signed (`H_accept_cosigned`) | `log.spthy`, `log_device.spthy`, `log_witness.spthy` | verified |
| every co-signature came from this log's witnesses (`H_cosign_origin`) | `log_witness.spthy` | verified |
| honest protocol completes (`sanity_event_accepted`) | `log.spthy`, `log_device.spthy` | verified |
| witness setup sanity (`sanity_witness_setup`) | `log_witness.spthy` | verified |
| quorum change sanity (`sanity_reshare_setup`) | `reshare.spthy` | verified |
| quorum change safety (L-01 reshare, L-03, L-04) | `reshare.spthy` | not yet attempted |
| L-02 fork prevention and fork detection | `fork.spthy` | verified |
| L-03 to L-20, C-01 to C-04 | -- | not written |

## What the verified lemmas do and do not establish

They hold for bounded traces: two parties, three intended bodies, two
acceptances, one quorum of two device keys. Unbounded extension of a log is
not established, and each model header says which compromise rules are
active. `log_device.spthy` states authorization for a single quorum;
`reshare.spthy` is where a quorum the adversary installed itself is handled,
and that lemma is not yet verified.

## Why the models look the way they do

Four traps cost most of the time, and each is commented where it occurs:

- A restriction's timepoints may all denote the same event. `All ... #i #j
  #k. F @ #i & F @ #j & F @ #k ==> F` forbids *one* event, not three,
  unless the ordering `#i < #j < #k` is written out.
- `functions: succ/1` is a free function, so the adversary has no deduction
  rule for sequence numbers. It can only relay a sequence number a rule put
  on the wire, which is why every signature is published with its message.
- `!DevKey` holds a raw key and a head may hold a pk; mixing the two makes
  premises unsatisfiable and silently kills every honest acceptance.
- A verification token that does not name the keys that signed can be spent
  by an acceptance under a different quorum. That was a real
  counterexample to `L01_authorized` before the token carried them.