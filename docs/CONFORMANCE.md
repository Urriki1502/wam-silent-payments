# External implementation contract v1

Launch an implementation adapter with `wsp-conformance test --contract-only
--adapter /absolute/executable arg...`. The adapter reads one JSON object per line
on stdin, emits one response line on stdout and sends no other stdout content.
The runner uses a 30-second response timeout and 4 MiB response limit. Fixtures
contain public deterministic test secrets, never real funds. The adapter owns its
own temporary state and must remove it on exit.

Requests contain `op` and `given`. Responses are `{"ok":true,"result":{...}}` or
`{"ok":false,"error":"REJECTED"}`. Failures are recorded by fixed fixture ID,
not raw responses. See devtools/conformance_adapter.py for the executable Python
adapter; an external implementation need not import any project class.

| op | Input / required result |
| --- | --- |
| address | address/hrp → compressed scan_public and spend_public hex |
| sending | official BIP-352 given object → extracted input_pub_keys and outputs |
| receiving | official BIP-352 given object → addresses, detected outputs/tweaks/deterministic signatures and n_outputs |
| create | synthetic seed/labels → API/profile identity, initialize empty wallet |
| chain | complete fixture blocks → replace fixture chain, report height |
| scan | empty object → counters including blocks and rollback |
| balance | empty object → confirmed_atoms, available_atoms and other accounting counters |
| history | empty object → transaction history |
| restart | empty object → close/reopen state, reopened=true |
| recover | empty object → backup, DELETE database, restore/rescan, return balance |
| spend | destination/atoms/fee → create/sign/finalize PSBT, version/input/output counts and fee |
| psbt_reject | hex PSBT → reject malformed fixture |
| privacy | sensitive field names → denied names and empty log |

Expected protocol results come from the unmodified official BIP-352 corpus.
Stateful request/expected-result sequences are tests/conformance/cases.json.
The runner checks every listed group has passing cases and zero failures. The
negative-adapter unit test proves a process rejecting everything is NON-CONFORMANT.
Contract success does not substitute for fuzz, independent differential, native
node, migration, security or release evidence. Full WSP qualification uses the
default command and fails closed if any mandatory evidence is absent or stale.
