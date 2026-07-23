# End-to-end example

The support-operations example is the reference integration for the SDK. It
uses a local synthetic ticket store and demonstrates the complete mediation
boundary without a model, network, real customer data, or real credentials.

Run it from the repository root:

```bash
python examples/support_agent.py
```

The application registers three tools:

- `read_ticket` is an allow-listed read operation.
- `update_ticket` is an idempotent write operation.
- `send_customer_email` is high impact, requires single-use approval, is
  idempotent, and receives a short-lived broker-issued credential only after
  authorization.

The proposal objects in the example stand in for untrusted model output. The
host application supplies the authenticated principal and task context. The
model cannot choose the principal, tenant, approval state, policy decision, or
credential scope.

## Demonstrated outcomes

The output includes:

- a successful ticket read;
- a cross-tenant denial before the handler runs;
- an approval-required email attempt;
- an approved credential-backed email;
- an idempotent replay that does not send a second message;
- an approval replay with a different proposal that is denied;
- an emergency-stop denial;
- a verified hash-chain audit result.

All application data is synthetic and all side effects are in-memory. The
example is intentionally not a production email integration. A production
application should replace the store, approval provider, policy engine, and
credential broker with authenticated adapters while preserving the same
runtime boundary and tests.

The example’s security-path tests are in
`tests/test_support_agent.py` and are executed by `make check`.
