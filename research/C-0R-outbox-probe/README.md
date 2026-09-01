# C-0R durable-outbox probe

Research-only contract. It is not imported by BreakGlass and is not a product
change. The probe imports `host:outbox/outbox@1.0.0`, attempts one non-destructive
GET to `example.com`, and records registration/invocation results separately.

The WIT dependency is copied from the public Terminal-3 reference at commit
`bf08f0ba0fb1ce585696e78b7162a0785afab97f`:

`Terminal-3/adk-circle-call-centre-agent-demo/contract/wit/deps/host-outbox-1.0.0/package.wit`
