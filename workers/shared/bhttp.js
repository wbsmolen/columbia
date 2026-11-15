// Binary HTTP (RFC 9292), known-length messages only: what Lander's client sends
// and what ohttp-go's gateway produced. QUIC varints (RFC 9000 §16).

export function readVarint(buf, pos) {
  if (pos >= buf.length) throw new Error('bhttp_truncated')
  const first = buf[pos]
  const len = 1 << (first >> 6)
  if (pos + len > buf.length) throw new Error('bhttp_truncated')
  let v = first & 0x3f
  for (let i = 1; i < len; i++) v = v * 256 + buf[pos + i]
  return [v, pos + len]
}

export function writeVarint(out, v) {
  if (v < 0x40) out.push(v)
  else if (v < 0x4000) out.push(0x40 | (v >> 8), v & 0xff)
  else if (v < 0x40000000) out.push(0x80 | (v >>> 24), (v >> 16) & 0xff, (v >> 8) & 0xff, v & 0xff)
  else {
    const hi = Math.floor(v / 2 ** 32), lo = v >>> 0
    out.push(0xc0 | (hi >>> 24), (hi >> 16) & 0xff, (hi >> 8) & 0xff, hi & 0xff,
      lo >>> 24, (lo >> 16) & 0xff, (lo >> 8) & 0xff, lo & 0xff)
  }
}

function readSlice(buf, pos) {
  const [len, p] = readVarint(buf, pos)
  if (p + len > buf.length) throw new Error('bhttp_truncated')
  return [buf.subarray(p, p + len), p + len]
}

const dec = new TextDecoder(), enc = new TextEncoder()

function readFields(buf, pos) {
  const [section, next] = readSlice(buf, pos)
  const fields = []
  let p = 0
  while (p < section.length) {
    let name, value
    ;[name, p] = readSlice(section, p)
    ;[value, p] = readSlice(section, p)
    fields.push([dec.decode(name), dec.decode(value)])
  }
  return [fields, next]
}

const METHODS = new Set(['GET', 'POST', 'DELETE', 'PATCH', 'PUT', 'OPTIONS', 'TRACE', 'HEAD', 'CONNECT'])

// Decode a known-length request (framing indicator 0). A message may be
// truncated after the content (trailers omitted), as RFC 9292 §3.8 allows.
export function decodeRequest(buf) {
  let p = 0, framing
  ;[framing, p] = readVarint(buf, p)
  if (framing !== 0) throw new Error('bhttp_unsupported_framing')
  let method, scheme, authority, path
  ;[method, p] = readSlice(buf, p)
  ;[scheme, p] = readSlice(buf, p)
  ;[authority, p] = readSlice(buf, p)
  ;[path, p] = readSlice(buf, p)
  method = dec.decode(method)
  if (!METHODS.has(method)) throw new Error('bhttp_bad_method')
  let headers = [], body = new Uint8Array(0)
  if (p < buf.length) [headers, p] = readFields(buf, p)
  if (p < buf.length) [body, p] = readSlice(buf, p)
  return { method, scheme: dec.decode(scheme), authority: dec.decode(authority), path: dec.decode(path), headers, body }
}

// Encode a known-length response (framing indicator 1) the way ohttp-go did:
// final status, header section, content, empty trailer section.
export function encodeResponse(status, headers, body) {
  const out = []
  writeVarint(out, 1)
  writeVarint(out, status)
  const fieldBytes = []
  for (const [name, value] of headers) {
    const n = enc.encode(name.toLowerCase()), v = enc.encode(value)
    writeVarint(fieldBytes, n.length); for (const b of n) fieldBytes.push(b)
    writeVarint(fieldBytes, v.length); for (const b of v) fieldBytes.push(b)
  }
  writeVarint(out, fieldBytes.length)
  const head = Uint8Array.from(out.concat(fieldBytes))
  const lenPrefix = []
  writeVarint(lenPrefix, body.length)
  const result = new Uint8Array(head.length + lenPrefix.length + body.length + 1)
  result.set(head, 0)
  result.set(lenPrefix, head.length)
  result.set(body, head.length + lenPrefix.length)
  result[result.length - 1] = 0 // empty trailer section
  return result
}
