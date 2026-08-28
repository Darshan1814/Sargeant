/**
 * Derivations that turn a normalized ULPF envelope into operator-facing values.
 *
 * Two rules govern everything here:
 *
 *  1. Never invent a value. If a field cannot be determined from the envelope,
 *     these helpers return null and the UI renders an explicit dash. A missing
 *     value is information; a fabricated one is a defect.
 *
 *  2. Internal vocabulary stays internal. Format tokens, parser identifiers,
 *     fallback engine names and pipeline path tokens are translated to plain
 *     language for the main card, and surfaced verbatim ONLY under Processing
 *     Details where a developer needs them for traceability.
 */

// ── Format tokens → plain language ───────────────────────────────────────────
// Tokens are produced by the per-family detectors (backend/*/detector.py).
const FORMAT_LABELS = {
  // Windows
  'xml': 'Windows Event XML',
  'evtx-text': 'Windows Event Log (text)',
  'winkv': 'Windows Event (key–value)',
  'firewall-text': 'Windows Firewall log',
  'iis-w3c': 'IIS W3C Extended log',
  // Linux
  'rfc3164': 'Syslog (RFC 3164)',
  'rfc5424': 'Syslog (RFC 5424)',
  'journald_json': 'journald (JSON)',
  'auditd': 'Linux audit log',
  'dmesg': 'Kernel ring buffer',
  // Android
  'threadtime': 'Android logcat (threadtime)',
  'time': 'Android logcat (time)',
  'brief': 'Android logcat (brief)',
  'long': 'Android logcat (long)',
  'tag': 'Android logcat (tag)',
  'process': 'Android logcat (process)',
  'json': 'Structured JSON',
}

/** The per-family native block, if the event carries one. */
export function nativeBlock(normalized) {
  const um = normalized?.unmapped || {}
  for (const fam of ['windows', 'linux', 'android']) {
    if (um[fam]) return { family: fam, block: um[fam] }
  }
  return { family: null, block: null }
}

export function humanFormat(normalized) {
  const { block } = nativeBlock(normalized)
  const token = block?.format
  if (token) return FORMAT_LABELS[token] || token
  // No native block: the record went through a generic or fallback route, so the
  // concrete wire format was never positively identified. Say so.
  return null
}

/** What the pipeline concluded about the record's origin. */
export function detected(normalized) {
  const { family, block } = nativeBlock(normalized)
  const osFamily = normalized?.device?.os?.family
  const source =
    osFamily && osFamily !== 'Unknown'
      ? osFamily
      : family
        ? family.charAt(0).toUpperCase() + family.slice(1)
        : null

  // "Service" is whichever native concept names the emitting component.
  const service =
    block?.program ||        // linux: syslog program
    block?.tag ||            // android: logcat tag
    block?.provider ||       // windows: event provider
    normalized?.actor?.process?.name ||
    null

  return {
    format: humanFormat(normalized),
    source,
    service,
    eventType: normalized?.class_name || null,
    channel: block?.channel || null,
  }
}

/**
 * Fields actually lifted out of the raw text, paired with the canonical path
 * they were written to. The OCSF path is what makes the mapping auditable, so it
 * travels with every field for the comparison view.
 */
export function extractedFields(normalized) {
  if (!normalized) return []
  const n = normalized
  const candidates = [
    ['Host', n.device?.hostname, 'device.hostname'],
    ['Event ID', n.metadata?.event_code, 'metadata.event_code'],
    ['Provider', n.metadata?.log_provider, 'metadata.log_provider'],
    ['Process', n.actor?.process?.name, 'actor.process.name'],
    ['PID', n.actor?.process?.pid, 'actor.process.pid'],
    ['Command line', n.actor?.process?.cmd_line, 'actor.process.cmd_line'],
    ['User', n.actor?.user?.name, 'actor.user.name'],
    ['Domain', n.actor?.user?.domain, 'actor.user.domain'],
    ['Source IP', n.src_endpoint?.ip, 'src_endpoint.ip'],
    ['Source Port', n.src_endpoint?.port, 'src_endpoint.port'],
    ['Destination IP', n.dst_endpoint?.ip, 'dst_endpoint.ip'],
    ['Destination Port', n.dst_endpoint?.port, 'dst_endpoint.port'],
    ['Protocol', n.connection_info?.protocol_name, 'connection_info.protocol_name'],
    ['Auth Protocol', n.auth_protocol, 'auth_protocol'],
  ]
  return candidates
    .filter(([, v]) => v !== null && v !== undefined && v !== '')
    .map(([label, value, path]) => ({ label, value: String(value), path }))
}

/** The canonical event, as a short readable list rather than raw JSON. */
export function normalizedSummary(normalized) {
  if (!normalized) return []
  const n = normalized
  return [
    ['Event time', n.time],
    ['Category', n.category_name],
    ['Event type', n.class_name],
    ['Activity', n.activity_name],
    ['Severity', n.severity],
    ['Outcome', n.status],
    ['Host', n.device?.hostname],
    ['Operating system', n.device?.os?.name],
    ['User', n.actor?.user?.name],
    ['Message', n.message],
  ].filter(([, v]) => v !== null && v !== undefined && v !== '')
    .map(([label, value]) => ({ label, value: String(value) }))
}

/** OCSF classification, human labels first and the numeric class as detail. */
export function ocsfMapping(normalized) {
  if (!normalized) return null
  return {
    className: normalized.class_name || null,
    classUid: normalized.class_uid ?? null,
    category: normalized.category_name || null,
    activity: normalized.activity_name || null,
    activityId: normalized.activity_id ?? null,
    status: normalized.status || null,
    severity: normalized.severity || null,
    mapped: normalized.ocsf_mapping_status === 'mapped',
  }
}

/**
 * Operator-facing status. Mirrors backend `_user_facing_status` exactly — if the
 * two ever diverge the UI would contradict the API, so the rule is duplicated
 * deliberately and kept in this single client-side location.
 */
export function userStatus(normalized) {
  const ps = (normalized?.parse_status || '').toLowerCase()
  const ms = (normalized?.ocsf_mapping_status || '').toLowerCase()
  const cov = normalized?.confidence_breakdown?.field_coverage

  if (ps === 'failed') {
    return { code: 'ERROR', label: 'Processing failed' }
  }
  if (ps === 'fallback') {
    return { code: 'UNRESOLVED', label: 'Source or event type could not be determined' }
  }
  if (ms === 'mapped') {
    if (cov != null && cov < 1.0) {
      return { code: 'PARTIAL', label: 'Parsed, but some fields could not be mapped' }
    }
    return { code: 'SUCCESS', label: 'Successfully parsed and mapped' }
  }
  return { code: 'REVIEW', label: 'Processed with low mapping confidence' }
}

/** Why an event landed in the review queue, in plain language. */
export function reviewReason(normalized) {
  const reasons = []
  const n = normalized || {}
  const cb = n.confidence_breakdown || {}
  if (n.ocsf_mapping_status !== 'mapped') {
    reasons.push('Event type could not be confidently determined')
  }
  if ((n.device?.os?.family || 'Unknown') === 'Unknown') {
    reasons.push('Originating system could not be identified')
  }
  if (cb.field_coverage != null && cb.field_coverage < 1.0) {
    reasons.push('Some extracted fields have no schema equivalent')
  }
  if (n.metadata?.ocsf_class_note) {
    reasons.push('Proposed event class failed schema validation')
  }
  if (!n.device?.hostname && !n.actor?.user?.name) {
    reasons.push('No host or user could be extracted')
  }
  return reasons
}

/**
 * Developer-level traceability. This is the ONLY place internal identifiers are
 * shown, and it lives behind an expander so it never crowds the main card.
 */
export function technicalDetails(normalized, row) {
  if (!normalized) return []
  const n = normalized
  const md = n.metadata || {}
  const cb = n.confidence_breakdown || {}
  return [
    ['Event ID', md.uid || row?.event_id],
    ['Parser', md.parser_id || row?.parser_id],
    ['Processing path', n.parse_path],
    ['Parse status', n.parse_status],
    ['Mapping status', n.ocsf_mapping_status],
    ['Schema version', md.version],
    ['Product', md.product?.name],
    ['Log provider', md.log_provider],
    ['Source event code', md.event_code],
    ['Raw SHA-256', md.raw_sha256],
    ['Raw object', md.raw_object_id],
    ['Original time', md.original_time],
    ['Ingestion time', md.ingestion_time],
    ['Processed time', md.processed_time],
    ['Year source', md.timestamp_year_source],
    ['Timezone source', md.timestamp_timezone_source],
    ['Requested class', md.ocsf_class_requested],
    ['Class note', md.ocsf_class_note],
    ['Confidence · format', cb.format],
    ['Confidence · pattern', cb.pattern],
    ['Confidence · source', cb.source],
    ['Confidence · parser', cb.parser],
    ['Confidence · semantic', cb.semantic],
    ['Confidence · schema', cb.ocsf],
    ['Field coverage', cb.field_coverage],
  ].filter(([, v]) => v !== null && v !== undefined && v !== '')
    .map(([label, value]) => ({ label, value: String(value) }))
}

/** Stage list for the per-event pipeline trace. */
export function parseStages(normalized) {
  const raw = normalized?.parse_stages || []
  const LABELS = {
    format_detection: 'Format Detection',
    pattern_detection: 'Pattern Detection',
    source_detection: 'Source Detection',
    parser_identification: 'Parser Selection',
    syntax_parsing: 'Field Extraction',
    normalization: 'Normalization',
    ocsf_mapping: 'Schema Mapping',
    generic_parser: 'Generic Parsing',
    drain3_fallback: 'Template Fallback',
    failed: 'Failed',
    dlq: 'Retained Unparsed',
  }
  return raw.map(s => LABELS[s] || s)
}

/**
 * Highlight spans for the raw text: locates each extracted value inside the
 * original line so the comparison view can prove the value came from the source
 * rather than from an assumption. Only literal, unambiguous matches are marked.
 */
export function highlightRaw(raw, fields) {
  if (!raw || !fields?.length) return [{ text: raw || '', field: null }]
  const marks = []
  for (const f of fields) {
    const v = f.value
    if (!v || v.length < 2) continue
    let from = 0
    while (true) {
      const i = raw.indexOf(v, from)
      if (i === -1) break
      marks.push({ start: i, end: i + v.length, field: f })
      from = i + v.length
    }
  }
  if (!marks.length) return [{ text: raw, field: null }]
  marks.sort((a, b) => a.start - b.start || b.end - a.end)
  // Drop overlaps, keeping the earliest/longest match.
  const kept = []
  let cursor = -1
  for (const m of marks) {
    if (m.start >= cursor) { kept.push(m); cursor = m.end }
  }
  const out = []
  let pos = 0
  for (const m of kept) {
    if (m.start > pos) out.push({ text: raw.slice(pos, m.start), field: null })
    out.push({ text: raw.slice(m.start, m.end), field: m.field })
    pos = m.end
  }
  if (pos < raw.length) out.push({ text: raw.slice(pos), field: null })
  return out
}

/** Client-side filter predicate built from the filter bar state. */
export function matchesFilters(row, f) {
  const n = row.normalized || {}
  if (f.q) {
    const hay = [
      row.raw, n.message, n.device?.hostname, n.actor?.user?.name,
      n.class_name, n.activity_name, n.metadata?.event_code,
    ].filter(Boolean).join(' ').toLowerCase()
    if (!hay.includes(f.q.toLowerCase())) return false
  }
  if (f.source && (n.device?.os?.family || 'Unidentified') !== f.source) return false
  if (f.format && humanFormat(n) !== f.format) return false
  if (f.eventType && n.class_name !== f.eventType) return false
  if (f.status && userStatus(n).code !== f.status) return false
  if (f.severity && n.severity !== f.severity) return false
  if (f.outcome && n.status !== f.outcome) return false
  if (f.host && (n.device?.hostname || '') !== f.host) return false
  if (f.minConfidence) {
    const c = (row.confidence ?? 0) * 100
    if (c < Number(f.minConfidence)) return false
  }
  return true
}

/** Distinct values for a filter dropdown, derived from the loaded rows. */
export function distinct(rows, pick) {
  const s = new Set()
  for (const r of rows) {
    const v = pick(r.normalized || {}, r)
    if (v !== null && v !== undefined && v !== '') s.add(v)
  }
  return [...s].sort()
}
