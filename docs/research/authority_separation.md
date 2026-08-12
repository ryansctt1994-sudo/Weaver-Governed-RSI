# Authority separation

Authority is modeled as a finite set of explicit actions attached to an identity. It is not
derived from performance, intelligence, model size, test coverage, or confidence.

The highest-risk transitions require three distinct roles:

- proposer: defines the candidate change;
- validator: evaluates the exact candidate;
- ratifier: authorizes a bounded transition.

The initial implementation rejects identity equality across these roles. Future work must
address organizational capture, shared credentials, common control, and beneficial ownership;
string inequality alone is not sufficient proof of independence.
