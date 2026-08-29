# ULPF --- Universal Log Pre-processing Framework

## Working Architecture & End-to-End Flow --- Research Draft

> **Status: DRAFT / DISCUSSION BASELINE**
>
> This document is **not the final architecture**. It captures the
> current direction after the team's initial research. Before
> implementation starts, the team should challenge the design, verify
> assumptions, test alternatives, and freeze the architecture, schema,
> scope, and technology choices together.

------------------------------------------------------------------------

## 1. Problem We Are Solving

Enterprise and perimeter-security devices generate logs in heterogeneous
formats:

-   Syslog
-   JSON
-   CEF
-   LEEF
-   CSV
-   XML
-   key-value formats
-   proprietary/vendor-specific text formats

The same security concept may be represented using different field names
and structures.

Example:

``` text
Vendor A:
src=10.10.1.10 dst=192.168.1.20 act=deny dpt=443

Vendor B:
source_ip=10.10.1.10 destination_ip=192.168.1.20
action=blocked destination_port=443
```

ULPF should convert these heterogeneous events into a common
cybersecurity representation while:

1.  preserving the original event;
2.  extracting useful fields;
3.  mapping fields to a canonical cybersecurity schema;
4.  retaining fields that cannot be mapped;
5.  maintaining event lineage and integrity;
6.  allowing new sources to be onboarded without rewriting the entire
    pipeline;
7.  operating in an air-gapped/private network;
8.  supporting scalable streaming and long-term retention.

------------------------------------------------------------------------

# 2. Current Architectural Direction

## Canonical Schema

**Proposed: OCSF + lightweight ULPF extension/profile**

OCSF is the canonical cybersecurity event model.

ULPF should NOT create another completely independent universal schema.

Use OCSF for:

-   event classes
-   cybersecurity semantics
-   common objects
-   common attributes
-   profiles/extensions where appropriate

Use a small ULPF extension for processing/lineage metadata such as:

-   `event_id`
-   `source_id`
-   `parser_version`
-   `mapping_version`
-   `normalization_score`
-   `received_at`
-   `processed_at`
-   raw-event hash

For lossless handling:

-   `raw_data` should contain the original source event.
-   `unmapped` should contain parsed fields that could not be mapped to
    OCSF.

Important: these two concepts should not be conflated.

------------------------------------------------------------------------

# 3. High-Level Architecture

``` text
                         ┌──────────────────────────────────────┐
                         │       AIR-GAPPED / PRIVATE NETWORK   │
                         │          NO INTERNET REQUIRED        │
                         └──────────────────────────────────────┘

  LOG SOURCES
       │
       │ Syslog / JSON / CEF / LEEF / CSV / XML / Custom
       ▼
┌───────────────────────┐
│  INGESTION            │
│                       │
│  Apache Kafka         │
│  - buffering          │
│  - partitioning       │
│  - replay             │
│  - backpressure       │
└───────────┬───────────┘
            │
            ▼
┌────────────────────────────────────────────────────────────────┐
│                    ULPF PROCESSING ENGINE                      │
│                                                                │
│  1. Format / Source Detection                                 │
│                 │                                              │
│       ┌─────────┴─────────┐                                    │
│       │                   │                                    │
│       ▼                   ▼                                    │
│  KNOWN / STRUCTURED   UNKNOWN / UNSTRUCTURED                   │
│       │                   │                                    │
│       ▼                   ▼                                    │
│  ULPF Native Parser   Template Miner                          │
│  / optional Vector    Drain-inspired approach                 │
│  adapter              (asynchronous)                           │
│       │                   │                                    │
│       └─────────┬─────────┘                                    │
│                 ▼                                              │
│        Field Extraction / Type Detection                       │
│                 │                                              │
│                 ▼                                              │
│        Semantic Mapping Engine                                 │
│        Vendor fields → OCSF fields                             │
│                 │                                              │
│                 ▼                                              │
│             OCSF Mapper                                        │
│                 │                                              │
│                 ▼                                              │
│        Validation + Enrichment                                 │
│                 │                                              │
│                 ▼                                              │
│       Lossless + Lineage Layer                                 │
│       raw_data + unmapped + hash + metadata                    │
└─────────────────┬──────────────────────────────────────────────┘
                  │
                  ▼
          NORMALIZED EVENT BUS
                  │
       ┌──────────┼──────────────┐
       ▼          ▼              ▼
 OpenSearch   ClickHouse       MinIO
 Hot Search   Long-term        Raw Archive
              Analytics        / Parquet
       │          │              │
       └──────────┼──────────────┘
                  ▼
       Analytics / Dashboards / AI
                  │
             SARGEANT
        Local Natural Language
              Interface
```

------------------------------------------------------------------------

# 4. End-to-End Data Flow

## Step 0 --- Time Synchronization

Before processing events, all ULPF infrastructure nodes should use a
consistent internal time source.

Conceptually:

``` text
Approved NPL/NIC time reference
              │
              ▼
      Internal NTP server(s)
              │
       ┌──────┼──────┐
       ▼      ▼      ▼
     Kafka   ULPF   Storage
```

For a genuinely air-gapped environment, external NPL/NIC cannot simply
be queried from every node. An approved internal time-distribution
mechanism is required.

Store/track at least:

-   source event time;
-   ULPF receive time;
-   ULPF processing time.

Do not overwrite the original source event timestamp.

------------------------------------------------------------------------

# 5. Step 1 --- Log Sources

Initial prototype scope should focus on perimeter/network security logs.

Recommended initial sources:

1.  Firewall
2.  Router/switch/network device
3.  IDS/IPS
4.  Linux/Syslog source
5.  Generic application/custom source

Recommended initial formats:

1.  Syslog
2.  JSON
3.  CEF
4.  LEEF
5.  key-value/plain text

Do NOT attempt to support every vendor and every format in the first
implementation.

------------------------------------------------------------------------

# 6. Step 2 --- Kafka Ingestion Layer

Apache Kafka acts as the event streaming and buffering layer.

Responsibilities:

-   receive events;
-   buffer bursts;
-   partition workloads;
-   decouple ingestion from processing;
-   provide replay;
-   provide consumer-group based horizontal scaling;
-   isolate failures;
-   create separate paths for normal and unknown events.

Suggested topics:

``` text
raw-events
unknown-events
template-events
normalized-events
parser-errors
```

Possible flow:

``` text
Source
  ↓
raw-events
  ↓
ULPF consumer
  ├── known → processing path
  └── unknown → unknown-events
```

Kafka partitions should be used to scale processing horizontally.

------------------------------------------------------------------------

# 7. Step 3 --- Format and Source Detection

The first ULPF component determines:

-   format;
-   source type;
-   optional vendor/product;
-   parsing strategy.

Example:

``` text
CEF prefix detected
      ↓
CEF parser path

JSON syntax detected
      ↓
JSON parser path

RFC-style Syslog detected
      ↓
Syslog parser path

Unknown/plain text
      ↓
Discovery path
```

Detection should be deterministic wherever possible.

------------------------------------------------------------------------

# 8. Step 4 --- Parsing Strategy

## Proposed hybrid design

### Fast / deterministic path

For known formats and known structures:

``` text
ULPF Native Parser
       OR
Vector/VRL adapter
```

The final decision between a completely native implementation and an
external Vector adapter should be made after benchmarking and
implementation effort analysis.

### Discovery path

For unknown/unstructured logs:

``` text
Unknown log
    ↓
Template Miner
    ↓
Template + extracted parameters
    ↓
Semantic mapping
```

Drain3 is a useful research/reference implementation for the
template-mining concept, but it should not be described as an OCSF
mapper. Its job is template discovery and parameter extraction.

------------------------------------------------------------------------

# 9. Proposed ULPF Native Parser

If the team chooses to build its own parser, it should NOT attempt to
replace every generic parser in existence.

The ULPF parser should be cybersecurity-oriented.

Possible modules:

``` text
ulpf-parser/
│
├── detector/
│   ├── FormatDetector
│   ├── SyslogDetector
│   ├── JsonDetector
│   ├── CefDetector
│   └── LeefDetector
│
├── tokenizer/
│   ├── KeyValueTokenizer
│   ├── PlainTextTokenizer
│   └── StructuredTokenizer
│
├── template/
│   ├── TemplateMiner
│   ├── TemplateCluster
│   └── PatternMatcher
│
├── extractor/
│   ├── FieldExtractor
│   ├── TypeDetector
│   └── ParameterExtractor
│
├── semantic/
│   ├── FieldClassifier
│   ├── MappingEngine
│   └── ConfidenceScorer
│
├── ocsf/
│   ├── OcsfMapper
│   └── OcsfValidator
│
└── lineage/
    ├── EventIdGenerator
    ├── HashGenerator
    └── RawPreserver
```

The parser's differentiator should be **cybersecurity-aware semantic
extraction and OCSF mapping**, not merely another regex engine.

------------------------------------------------------------------------

# 10. Step 5 --- Field Extraction

The parser converts raw input into an intermediate representation.

Example:

``` text
src=10.10.1.10
dst=192.168.1.20
spt=52341
dpt=443
proto=tcp
act=blocked
```

Intermediate representation:

``` json
{
  "source_ip": "10.10.1.10",
  "destination_ip": "192.168.1.20",
  "source_port": 52341,
  "destination_port": 443,
  "protocol": "tcp",
  "action": "blocked"
}
```

This intermediate representation should remain separate from OCSF.

That separation makes parser implementations replaceable.

------------------------------------------------------------------------

# 11. Step 6 --- Semantic Mapping Engine

This is one of the main ULPF components.

Example mapping:

``` text
src
source_ip
sourceAddress
sip
       ↓
OCSF source endpoint IP

dst
destination_ip
destinationAddress
dip
       ↓
OCSF destination endpoint IP
```

The mapping registry should be configuration-driven.

Example:

``` yaml
source: firewall_vendor_x
format: cef

mapping:
  src: <OCSF source IP field>
  dst: <OCSF destination IP field>
  spt: <OCSF source port field>
  dpt: <OCSF destination port field>
  proto: <OCSF protocol field>
  act: <OCSF action/disposition field>
```

Do not hard-code every vendor mapping into application logic.

------------------------------------------------------------------------

# 12. Step 7 --- Confidence Scoring

Potential enhancement:

``` text
source_ip      → confidence 0.99
destination_ip → confidence 0.98
destination_port → confidence 0.99
action         → confidence 0.91
```

Possible policy:

``` text
confidence >= threshold
        ↓
automatic mapping

confidence < threshold
        ↓
review / AI-assisted mapping
```

The threshold should be experimentally determined rather than
arbitrarily presented as a final value.

------------------------------------------------------------------------

# 13. Step 8 --- OCSF Normalization

The semantic mapping layer maps extracted data to the appropriate OCSF
event class/object/attribute.

Conceptually:

``` text
Raw vendor field
      ↓
Intermediate field
      ↓
Semantic meaning
      ↓
OCSF field
```

Example:

``` text
src=10.10.1.10
      ↓
source_ip
      ↓
network source endpoint
      ↓
OCSF source endpoint field
```

The exact OCSF event class and field mapping should be finalized after
the team studies the current OCSF schema and selects the exact
perimeter-network event classes.

------------------------------------------------------------------------

# 14. Step 9 --- Lossless Preservation

Every normalized event should retain:

``` text
raw_data
unmapped
event_id
raw_hash
parser_version
mapping_version
source_id
received_at
processed_at
```

Conceptually:

``` json
{
  "event_id": "UUID",

  "time": "...",

  "raw_data": "<EXACT ORIGINAL EVENT>",

  "unmapped": {
    "vendor_specific_field": "value"
  },

  "ulpf": {
    "source_id": "FW-001",
    "parser_version": "1.0",
    "mapping_version": "1.0",
    "received_at": "...",
    "processed_at": "...",
    "raw_sha256": "..."
  }
}
```

`raw_data` and `unmapped` have different purposes:

-   `raw_data`: original source event;
-   `unmapped`: parsed fields that could not be mapped.

------------------------------------------------------------------------

# 15. Step 10 --- Validation and Enrichment

Validation:

-   OCSF structure validation;
-   type checking;
-   required field checks;
-   timestamp validation;
-   IP/port validation;
-   mapping consistency.

Optional enrichment:

-   GeoIP;
-   asset metadata;
-   threat intelligence;
-   user/identity metadata;
-   device metadata.

For the 20--25 day prototype, enrichment should be kept small and
local/offline.

Do not make Internet-based threat-intelligence APIs a dependency.

------------------------------------------------------------------------

# 16. Step 11 --- Storage Architecture

Recommended separation:

``` text
                    NORMALIZED EVENTS
                           │
              ┌────────────┼─────────────┐
              ▼            ▼             ▼
         OpenSearch    ClickHouse      MinIO
         HOT SEARCH    180-DAY         RAW DATA
                       ANALYTICS        ARCHIVE
```

### OpenSearch

Purpose:

-   fast search;
-   investigation;
-   filtering;
-   dashboards;
-   hot data.

Suggested prototype hot tier:

``` text
7–30 days
```

This is an architecture choice, not the legal retention period.

### ClickHouse

Purpose:

-   long-term normalized OCSF events;
-   time-series analytics;
-   aggregation;
-   high-volume analytical queries;
-   180-day retention.

### MinIO + Parquet

Purpose:

-   raw event archive;
-   forensic access;
-   long-term storage;
-   compressed columnar archival where appropriate.

All storage must reside inside the controlled deployment environment for
the intended air-gapped/sovereign deployment.

------------------------------------------------------------------------

# 17. 180-Day Retention

Retention should be implemented as an automatic policy.

Conceptually:

``` text
ClickHouse
    ↓
180-day retention policy

MinIO
    ↓
180-day object lifecycle policy
```

For engineering safety, the team may configure a small buffer above 180
days, but this should be described as a design decision rather than a
regulatory requirement.

Storage sizing must be based on measured data:

``` text
Daily logical data
=
EPS × average event size × 86,400

180-day logical data
=
Daily data × 180

Required physical storage
=
logical data ÷ measured compression ratio
+ indexes
+ replication
+ metadata
+ operational headroom
```

Do not claim a fixed compression ratio before benchmarking the actual
event corpus.

------------------------------------------------------------------------

# 18. Throughput and Scalability

ULPF should be measured in:

-   events/second (EPS);
-   MiB/s or GiB/s;
-   P50/P95/P99 processing latency;
-   Kafka consumer lag;
-   CPU;
-   memory;
-   storage write throughput;
-   parser failure rate;
-   OCSF mapping failure rate.

Architecture:

``` text
Kafka partitions
       ↓
ULPF Worker 1
ULPF Worker 2
ULPF Worker 3
...
ULPF Worker N
       ↓
Storage
```

As load increases, add workers.

The actual target EPS must be selected after benchmark testing.

For the SIH prototype, do NOT claim that the system processes billions
of events/day unless the benchmark supports that statement.

------------------------------------------------------------------------

# 19. Unknown Log / Async Discovery Flow

This is a separate path and must not block the primary pipeline.

``` text
Unknown Event
      ↓
Kafka: unknown-events
      ↓
Async Template Miner
      ↓
Template + Parameters
      ↓
Semantic Mapping
      ↓
AI / Human Review (if required)
      ↓
Mapping Registry
      ↓
OCSF
      ↓
normalized-events
```

The important principle:

> Unknown logs should not stop the deterministic fast path.

------------------------------------------------------------------------

# 20. AI / SARGEANT Position

SARGEANT should be a consumer/query interface, not a component in the
core normalization path.

Recommended:

``` text
OpenSearch / ClickHouse
          ↑
       SARGEANT
          ↑
    Local LLM / NLP
```

Use it for:

-   natural-language queries;
-   report generation;
-   threat-hunting assistance;
-   explanation of normalized events;
-   mapping suggestions.

Do not make an external/cloud LLM mandatory.

For an air-gapped deployment, use a locally deployed model if AI is
included.

------------------------------------------------------------------------

# 21. Example SARGEANT Flow

User:

> Show failed login attempts from 10.10.1.20 today.

Flow:

``` text
User
 ↓
SARGEANT
 ↓
Intent extraction
 ↓
OCSF-aware query generation
 ↓
OpenSearch / ClickHouse
 ↓
Results
 ↓
Natural-language response
```

The LLM should not directly modify raw data or the core processing
pipeline.

------------------------------------------------------------------------

# 22. Monitoring

Use:

### Prometheus

Metrics:

-   input EPS;
-   normalized EPS;
-   parser latency;
-   parser errors;
-   unknown-event count;
-   Kafka lag;
-   mapping failures;
-   storage write latency;
-   CPU;
-   memory;
-   disk usage.

### Grafana

Dashboards:

``` text
System health
Kafka health
ULPF throughput
Parser health
Normalization health
Storage capacity
Retention status
Unknown-log queue
```

------------------------------------------------------------------------

# 23. Proposed Technology Stack

  -----------------------------------------------------------------------
  Layer                   Proposed Technology     Purpose
  ----------------------- ----------------------- -----------------------
  Source ingestion        Syslog / file / HTTP /  Input
                          simulated generators    

  Streaming               Apache Kafka            Buffering, partitions,
                                                  replay

  Parser                  ULPF Native Parser      Core parsing

  Parser adapter          Optional Vector/VRL     Benchmark/production
                                                  adapter

  Unknown log mining      Drain-inspired / Drain3 Template discovery
                          reference               

  Mapping                 ULPF Mapping Engine     Source → OCSF

  Canonical schema        OCSF                    Cybersecurity
                                                  normalization

  Backend                 Java/Spring Boot or     APIs/orchestration
                          Python service          

  Parser implementation   Java/Python/Rust --- to Parsing engine
                          be finalized            

  Long-term normalized    ClickHouse              180-day analytics
  storage                                         

  Raw archive             MinIO + Parquet         180-day raw retention

  Hot search              OpenSearch              Search/investigation

  Analytics               PySpark --- optional    Batch analytics

  Monitoring              Prometheus              Metrics

  Dashboards              Grafana                 Visualization

  AI                      Local LLM               Offline SARGEANT

  Containerization        Docker Compose          Reproducible deployment
                          initially               

  Time sync               Internal NTP/Chrony     Timestamp consistency
                          architecture            
  -----------------------------------------------------------------------

------------------------------------------------------------------------

# 24. Suggested Implementation Stack for the First MVP

Because the team has approximately 20--25 days, avoid overengineering.

### Core MVP

``` text
Kafka
 +
ULPF Parser
 +
Mapping Engine
 +
OCSF
 +
ClickHouse
 +
MinIO
 +
OpenSearch
 +
Grafana
```

### Add after the core works

``` text
Drain-inspired discovery
AI mapping
SARGEANT
PySpark
advanced enrichment
```

The exact order should be revisited after the team estimates the
implementation effort.

------------------------------------------------------------------------

# 25. Suggested Repository Structure

``` text
ulpf/
│
├── README.md
├── docker-compose.yml
│
├── docs/
│   ├── architecture.md
│   ├── schema.md
│   ├── threat-model.md
│   └── benchmarks.md
│
├── ingestion/
│   └── kafka/
│
├── parser/
│   ├── detector/
│   ├── tokenizer/
│   ├── template/
│   ├── extractor/
│   └── tests/
│
├── mapping/
│   ├── registry/
│   ├── semantic/
│   └── tests/
│
├── ocsf/
│   ├── mapper/
│   ├── validator/
│   └── profile/
│
├── lineage/
│   ├── hashing/
│   └── event-id/
│
├── storage/
│   ├── clickhouse/
│   ├── minio/
│   └── opensearch/
│
├── monitoring/
│   ├── prometheus/
│   └── grafana/
│
├── ai/
│   └── sargeant/
│
├── datasets/
│   └── sample-logs/
│
└── benchmarks/
```

------------------------------------------------------------------------

# 26. Proposed Development Phases

## Phase 0 --- Architecture Freeze

**Before coding**

Decide:

-   exact OCSF version;
-   exact OCSF event classes;
-   parser implementation language;
-   Kafka topology;
-   storage schema;
-   retention implementation;
-   MVP log formats;
-   benchmark dataset.

------------------------------------------------------------------------

## Phase 1 --- Skeleton

Build:

``` text
Docker Compose
Kafka
ClickHouse
MinIO
OpenSearch
Prometheus
Grafana
```

Verify that all components run without Internet access.

------------------------------------------------------------------------

## Phase 2 --- Ingestion

Implement:

``` text
raw-events
unknown-events
normalized-events
parser-errors
```

and event IDs.

------------------------------------------------------------------------

## Phase 3 --- Parser

Implement initial formats:

``` text
Syslog
JSON
CEF
LEEF
Key-value/plain text
```

Start with a small number of representative firewall/network-device
formats.

------------------------------------------------------------------------

## Phase 4 --- OCSF Mapping

Implement:

``` text
Intermediate Event
       ↓
Mapping Registry
       ↓
OCSF Event
```

Freeze initial mappings.

------------------------------------------------------------------------

## Phase 5 --- Lossless + Lineage

Implement:

``` text
raw_data
unmapped
SHA-256
event_id
parser_version
mapping_version
timestamps
```

------------------------------------------------------------------------

## Phase 6 --- Storage

Implement:

``` text
OCSF → ClickHouse
Raw → MinIO
Recent OCSF → OpenSearch
```

Implement retention policies.

------------------------------------------------------------------------

## Phase 7 --- Unknown Log Discovery

Add:

``` text
unknown-events
      ↓
template miner
      ↓
mapping suggestion
```

Only after the main path is stable.

------------------------------------------------------------------------

## Phase 8 --- Dashboard

Build:

-   ingestion rate;
-   normalized rate;
-   parser success;
-   unknown events;
-   Kafka lag;
-   storage usage;
-   search;
-   raw/normalized lineage view.

------------------------------------------------------------------------

## Phase 9 --- SARGEANT / AI

Add only if the core system is stable.

------------------------------------------------------------------------

## Phase 10 --- Benchmark + Demo

Benchmark:

``` text
EPS
latency
CPU
memory
storage
compression
mapping accuracy
parser accuracy
unknown-log recovery
```

------------------------------------------------------------------------

# 27. Example Complete Scenario

### Firewall sends CEF

``` text
CEF:0|VendorX|Firewall|1.0|100|
Connection Blocked|7|
src=10.10.1.20 dst=192.168.1.10
spt=53211 dpt=443 proto=TCP
```

### Flow

``` text
Firewall
   ↓
Kafka/raw-events
   ↓
Format Detection
   ↓
CEF Parser
   ↓
Intermediate Event
   ↓
Mapping Registry
   ↓
OCSF Network Event
   ↓
Validation
   ↓
raw_data + unmapped + SHA-256 + lineage
   ↓
normalized-events
   ├── ClickHouse
   ├── OpenSearch
   └── downstream analytics
```

------------------------------------------------------------------------

# 28. Unknown Vendor Scenario

Input:

``` text
FW-7 BLOCK conn 10.1.1.10 -> 192.168.1.20
TCP/443 policy=SEC_12
```

No known parser.

``` text
Kafka
 ↓
unknown-events
 ↓
Template Miner
 ↓
"FW-7 BLOCK conn <IP> -> <IP> TCP/<PORT> policy=<POLICY>"
 ↓
Parameters
 ↓
Semantic mapping
 ↓
Human/AI confirmation
 ↓
Mapping Registry
 ↓
OCSF
 ↓
normalized-events
```

Next event from the same source should follow the learned deterministic
mapping.

------------------------------------------------------------------------

# 29. Security Design Principles

ULPF should include:

-   RBAC;
-   authenticated administrative APIs;
-   audit logging;
-   encrypted transport inside the controlled network where appropriate;
-   encrypted storage where appropriate;
-   raw-event integrity hashing;
-   parser/mapping versioning;
-   configuration audit trail;
-   no mandatory external API;
-   no mandatory cloud dependency.

For the SIH prototype, prioritize the security controls that can
actually be demonstrated.

------------------------------------------------------------------------

# 30. Important Open Decisions for the Team

Do NOT automatically treat the choices in this document as final.

The team should explicitly research and decide:

### Schema

-   Exact OCSF version?
-   Exact network event classes?
-   Which OCSF profiles?
-   What belongs in the ULPF extension?

### Parser

-   Fully native ULPF parser?
-   Vector/VRL adapter?
-   Which language?
-   Drain-inspired implementation vs Drain3?
-   What is the benchmark criterion?

### Kafka

-   Number of brokers for prototype?
-   Partition count?
-   Replication factor?
-   At-least-once vs stronger processing semantics?
-   What happens when storage is unavailable?

### Storage

-   ClickHouse table design?
-   MinIO bucket layout?
-   Parquet partition strategy?
-   OpenSearch hot retention?
-   Compression ratio?
-   Replication/erasure coding?
-   180-day capacity?

### Time

-   Internal NTP topology?
-   Approved authoritative time source?
-   Clock-drift monitoring?
-   How to handle malformed/missing timestamps?

### AI

-   Is AI necessary for MVP?
-   Which local model?
-   How will it work without Internet?
-   How will AI suggestions be validated?
-   What happens when AI is wrong?

### Performance

-   Target EPS?
-   Event-size distribution?
-   P95/P99 latency target?
-   Number of parser workers?
-   Kafka lag threshold?

------------------------------------------------------------------------

# 31. Research References / Starting Points

### OCSF

Use the current OCSF documentation/schema as the source of truth for the
canonical event model.

### Kafka

Kafka documentation is useful for partitions, consumer groups, replay,
delivery semantics, and horizontal processing. Kafka's design uses
ordered partitions and consumer groups to distribute processing, and its
current documentation distinguishes at-most-once, at-least-once, and
exactly-once semantics. citeturn0search0turn0search2

### Vector / VRL

VRL is compiled into native Rust code and includes parsing functions for
common formats such as Syslog, CEF, JSON/key-value and custom
regex-based parsing. This makes it useful as a benchmark or optional
adapter even if ULPF eventually implements its own parser.
citeturn1search0turn1search2

### Drain / Drain3

Drain3 is an online log-template miner based on the fixed-depth-tree
Drain algorithm. The original research paper is:

**Pinjia He, Jieming Zhu, Zibin Zheng, Michael R. Lyu --- "Drain: An
Online Log Parsing Approach with Fixed Depth Tree", ICWS 2017.**

Drain3 also supports persistence of learned state through Kafka, Redis
or files. citeturn1search3turn1search4

### Existing research already reviewed by the team

**Daniel Tovarňák and Tomáš Pitner --- "Normalization of Unstructured
Log Data into Streams of Structured Event Objects" (2019).**

This paper is useful as the conceptual foundation for the normalization
pipeline: input adaptation, deserialization, parsing, transformation,
enrichment, serialization and output adaptation.

------------------------------------------------------------------------

# 32. Current Working Architecture --- One-Line Version

``` text
Sources
 → Kafka
 → Format Detection
 → [ULPF Fast Parser | Async Template Discovery]
 → Intermediate Event
 → Semantic Mapping Registry
 → OCSF Normalization
 → Validation/Enrichment
 → raw_data + unmapped + Hash + Lineage
 → normalized Kafka
 → [OpenSearch | ClickHouse | MinIO]
 → [Grafana / PySpark / SARGEANT]
```

------------------------------------------------------------------------

# 33. What We Should NOT Do Tomorrow Morning

Do not immediately start coding every component.

First, the team should spend a short architecture-freeze session
answering:

1.  What exact OCSF event classes are in scope?
2.  What exact 4--5 input formats will the MVP support?
3.  Native parser or Vector adapter?
4.  What unknown-log algorithm will be implemented?
5.  What is the exact intermediate event model?
6.  What is the mapping registry format?
7.  What is the ClickHouse schema?
8.  What is the MinIO/Parquet partition strategy?
9.  What is the minimum benchmark target?
10. What features are explicitly OUT of scope?

Once these are agreed upon, freeze the MVP and start implementation.

------------------------------------------------------------------------

## Final Position of This Document

The current proposal is:

> **ULPF = Kafka-based ingestion + ULPF-owned/adaptable parsing layer +
> asynchronous unknown-log template discovery + configuration-driven
> semantic mapping + OCSF canonical normalization + lossless raw
> preservation + lineage/integrity + ClickHouse/MinIO 180-day storage +
> OpenSearch hot investigation + offline monitoring + optional local
> AI/SARGEANT.**

**This is a working proposal, not the final design.**

The most important thing tomorrow is to challenge this architecture
rather than blindly implement it.
