# Security Policy

## Reporting a vulnerability

Columbia is privacy infrastructure. A flaw here can deanonymize users, so please
report security issues privately rather than in a public issue. Open a private
security advisory on this repository (Security, then Advisories, then Report a
vulnerability), or contact the maintainer directly.

Include what you found, how to reproduce it, and the impact. You can expect an
acknowledgement within a few days.

## The guarantee in scope

The core property is operator-blindness. The relay sees the client address but
not the request content. The gateway sees the content but not the client
address. Neither hop holds both. The highest-priority reports are the ones that
break this split: anything that lets one hop learn what the other sees, that
leaks a client identifier into a log or a response, or that links a client to
the content they fetched.

## Known limitations that are not vulnerabilities

The non-collusion assumption is documented, not a bug. If a single operator runs
both the relay and the gateway, that operator can line up the address it saw at
the relay against the content it decrypted at the gateway. The protection holds
only when the two hops are run by separate parties who do not collude, or when
you run the whole thing yourself. See README.md and ARCHITECTURE.md. A
single-operator deployment correlating its own hops is out of scope.
