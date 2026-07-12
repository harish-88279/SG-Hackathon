// Thin client for the SBOMGuard FastAPI backend.
const BASE = ''

async function j(path, opts) {
  const r = await fetch(BASE + path, opts)
  if (!r.ok) {
    let detail
    try { detail = (await r.json()).detail } catch { detail = r.statusText }
    throw new Error(detail || `Request failed (${r.status})`)
  }
  return r.json()
}

export const api = {
  summary:      ()               => j('/api/summary'),
  findings:     (q = {})         => j('/api/findings?' + new URLSearchParams(q)),
  finding:      (id)             => j(`/api/finding/${id}`),
  narrative:    (id)             => j(`/api/intel/narrative/${id}`, { method: 'POST' }),
  cve:          (id)             => j(`/api/cve/${encodeURIComponent(id)}`),
  cveList:      (q = '')         => j('/api/cves?' + new URLSearchParams({ q, limit: 8 })),
  graph:        (q = {})         => j('/api/graph?' + new URLSearchParams(q)),
  remediation:  ()               => j('/api/remediation'),
  correlation:  ()               => j('/api/correlation'),
  compliance:   ()               => j('/api/compliance'),
  clusters:     ()               => j('/api/intel/clusters'),
  model:        ()               => j('/api/intel/model'),
  llmStatus:    ()               => j('/api/intel/llm-status'),
  gate:         (policy)         => j('/api/gate', {
                                       method: 'POST',
                                       headers: { 'Content-Type': 'application/json' },
                                       body: JSON.stringify({ policy }),
                                     }),
  evaluate:     ()               => j('/api/eval'),
  upload:       (file)           => {
                                     const fd = new FormData()
                                     fd.append('file', file)
                                     return j('/api/upload', { method: 'POST', body: fd })
                                   },
}
