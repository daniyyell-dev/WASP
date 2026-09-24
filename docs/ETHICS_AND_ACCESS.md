# Ethical release and access boundary

This GitHub documentation package, together with the separate Mendeley Data CSV deposit, supports defensive cybersecurity research on detecting abuse of trusted Windows processes. The public material was intentionally reduced to aggregate numeric telemetry.

## Excluded material

- Windows PE files and other third-party executables
- Malware, C2 agents, payloads and implant binaries
- Injection, persistence or delivery scripts
- Credentials, tokens, private keys and configuration secrets
- IP addresses, domains, ports tied to infrastructure and network destinations
- Process IDs, hostnames, usernames, original timestamps and absolute paths
- Raw memory, command lines, thread identifiers and unminimised JSONL
- Model checkpoints and artefacts that are not required to understand the dataset

These exclusions reduce privacy, licensing and dual-use risk while preserving the measurements needed to audit the dataset paper.

## Raw data

Raw JSONL is not part of the Mendeley Data deposit and should not be added merely to increase data volume. Any later raw-data access mechanism requires a separate governance decision, sensitive-field review, licence assessment, access protocol and versioned record.

## Research claims

The released telemetry supports descriptive analysis of 63 controlled matched experiments across four payload families, nine declared techniques and three Windows environments. Twenty-seven Cobalt Strike experiments were retained only after the injection-labelled condition showed an outbound laboratory C2 connection. This is an acceptance condition for those cells, not evidence of universal C2 detection or a deployment-level detection rate. The release does not establish family attribution, causal superiority of one technique, resistance to adaptive attackers, vendor-level EDR performance or production false-positive rates. Snapshot rows within one launch are repeated measurements, and only 60 of the 63 pairs are scoreable by their matching enrolled host model.

## Responsible reuse

Users should cite the dataset version, keep run groups intact, avoid re-identification attempts, and refrain from combining the pseudonymous fields with external sources to infer laboratory identities. Findings that expose inadvertently included identifiers or secrets should be reported privately to the corresponding author named in `CITATION.cff`.
