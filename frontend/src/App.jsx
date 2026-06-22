import { useEffect, useMemo, useRef, useState, useCallback } from 'react'
import cytoscape from 'cytoscape'
import './App.css'

function useTheme() {
  const [theme, setTheme] = useState(() => {
    if (typeof window !== 'undefined') {
      return localStorage.getItem('theme') || 'light'
    }
    return 'light'
  })

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('theme', theme)
  }, [theme])

  const toggle = useCallback(() => {
    setTheme((prev) => (prev === 'light' ? 'dark' : 'light'))
  }, [])

  return { theme, toggle }
}

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8001'

const SOURCE_LABELS = {
  etherscan: 'Etherscan',
  crtsh: 'crt.sh',
  whois: 'WHOIS',
  wayback: 'Wayback',
  scamdb: 'ScamDB',
  web_mentions: 'Web',
}

function App() {
  const { theme, toggle: toggleTheme } = useTheme()
  const [input, setInput] = useState('')
  const [domain, setDomain] = useState('')
  const [analysis, setAnalysis] = useState(null)
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(false)
  const [reportLoading, setReportLoading] = useState(false)
  const [pdfLoading, setPdfLoading] = useState(false)
  const [deepScanLoading, setDeepScanLoading] = useState(false)
  const [error, setError] = useState('')

  // SSE source progress
  const [sourceProgress, setSourceProgress] = useState({})
  const [activeSources, setActiveSources] = useState([])

  async function runAnalysis(event) {
    event?.preventDefault()
    setLoading(true)
    setError('')
    setReport(null)
    setAnalysis(null)
    setSourceProgress({})
    setActiveSources([])

    try {
      const response = await fetch(`${API_BASE}/analyze/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input, domain }),
      })

      if (!response.ok) {
        const errData = await response.json().catch(() => ({}))
        throw new Error(errData.error || 'Analysis failed')
      }

      const reader = response.body.getReader()
      const decoder = new TextDecoder()
      let buffer = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n')
        buffer = lines.pop() || ''

        for (const line of lines) {
          if (!line.startsWith('data: ')) continue
          try {
            const event = JSON.parse(line.slice(6))

            if (event.event === 'sources') {
              setActiveSources(event.sources)
              const initial = {}
              event.sources.forEach((s) => {
                initial[s] = { status: 'waiting', duration: null }
              })
              setSourceProgress(initial)
            } else if (event.event === 'source_done') {
              setSourceProgress((prev) => ({
                ...prev,
                [event.source]: {
                  status: 'done',
                  duration: event.duration,
                  error: event.error,
                },
              }))
            } else if (event.event === 'complete') {
              setAnalysis(event.result)
            }
          } catch {
            // skip unparseable lines
          }
        }
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  // Mark currently-running sources as 'scanning'
  useEffect(() => {
    if (!loading || activeSources.length === 0) return
    setSourceProgress((prev) => {
      const updated = { ...prev }
      for (const key of activeSources) {
        if (updated[key]?.status === 'waiting') {
          updated[key] = { ...updated[key], status: 'scanning' }
        }
      }
      return updated
    })
  }, [loading, activeSources])

  async function generateReport() {
    if (!analysis) return
    setReportLoading(true)
    setError('')

    try {
      const response = await fetch(`${API_BASE}/report`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ analysis }),
      })
      const data = await response.json()
      if (!response.ok) {
        throw new Error(data.error || 'Report failed')
      }
      setReport(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setReportLoading(false)
    }
  }

  async function downloadPdf() {
    if (!analysis) return
    setPdfLoading(true)
    setError('')

    try {
      const response = await fetch(`${API_BASE}/report/pdf`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          analysis,
          narrative: report?.narrative || null,
        }),
      })
      if (!response.ok) {
        const errData = await response.json().catch(() => ({}))
        throw new Error(errData.error || 'PDF generation failed')
      }

      const blob = await response.blob()
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `scam_report_${(analysis.input || 'unknown').slice(0, 30)}.pdf`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err) {
      setError(err.message)
    } finally {
      setPdfLoading(false)
    }
  }

  async function runDeepScan() {
    if (!analysis) return
    const connected = analysis.raw?.wallet?.connected_addresses || []
    if (connected.length === 0) return

    setDeepScanLoading(true)
    setError('')

    try {
      const response = await fetch(`${API_BASE}/deep-scan`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          analysis,
          addresses: connected.slice(0, 10),
        }),
      })
      const data = await response.json()
      if (!response.ok) {
        throw new Error(data.error || 'Deep scan failed')
      }
      setAnalysis(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setDeepScanLoading(false)
    }
  }

  const risk = analysis?.risk || { score: 0, level: 'READY', reasons: [] }
  const summary = analysis?.summary || {}
  const wallet = summary.wallet || {}
  const domainInfo = summary.domain || {}
  const scamdb = summary.scamdb || {}
  const classification = analysis?.classification || null
  const deepScanData = analysis?.deep_scan || null
  const connectedWallets = analysis?.raw?.wallet?.connected_addresses || []

  return (
    <main className="app">
      <header className="header">
        <div className="header-text">
          <h1>Crypto Scam Mapper</h1>
          <p>Investigate wallet addresses and domains using public OSINT sources.</p>
        </div>
        <div className="theme-toggle">
          <button
            className="theme-toggle-track"
            onClick={toggleTheme}
            aria-label={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`}
            title={`Switch to ${theme === 'light' ? 'dark' : 'light'} mode`}
          >
            <span className="theme-toggle-knob">
              <span className="theme-toggle-icon">{theme === 'light' ? '☀️' : '🌙'}</span>
            </span>
          </button>
        </div>
      </header>

      <form onSubmit={runAnalysis} className="search-form">
        <div className="field">
          <label htmlFor="artifact">Wallet or domain</label>
          <input
            id="artifact"
            value={input}
            onChange={(e) => setInput(e.target.value)}
            placeholder="Enter wallet address or domain"
          />
        </div>
        <div className="field">
          <label htmlFor="domain">Linked domain (optional)</label>
          <input
            id="domain"
            value={domain}
            onChange={(e) => setDomain(e.target.value)}
            placeholder="For wallet lookups"
          />
        </div>
        <button className="btn btn-primary" type="submit" disabled={loading || !input.trim()}>
          {loading ? 'Scanning...' : 'Analyze'}
        </button>
      </form>

      {error && <div className="error">{error}</div>}

      <div className="stats-row">
        <div className="stat">
          <span className="stat-value">{risk.score}</span>
          <span className="stat-label">Risk score</span>
          <span className={`stat-risk risk-${risk.level.toLowerCase()}`}>{risk.level}</span>
        </div>
        <div className="stat">
          <span className="stat-value">{wallet.impact?.total_eth_received ?? '—'}</span>
          <span className="stat-label">ETH received</span>
        </div>
        <div className="stat">
          <span className="stat-value">{wallet.connected_wallets ?? '—'}</span>
          <span className="stat-label">Wallet links</span>
        </div>
        <div className="stat">
          <span className="stat-value">{domainInfo.sibling_domains ?? '—'}</span>
          <span className="stat-label">Sibling domains</span>
        </div>
        <div className="stat">
          <span className="stat-value">{scamdb.confirmed ?? '—'}</span>
          <span className="stat-label">ScamDB hits</span>
        </div>
      </div>

      {/* Deep Scan */}
      {analysis && connectedWallets.length > 0 && (
        <div className="deep-scan-section">
          <button
            className="btn-deep-scan"
            onClick={runDeepScan}
            disabled={deepScanLoading}
          >
            {deepScanLoading
              ? '🔍 Deep scanning...'
              : `🔍 Deep Scan (${connectedWallets.length} connected wallets)`}
          </button>
          {deepScanLoading && (
            <span className="deep-scan-info">Scanning connected wallets in parallel...</span>
          )}
          {deepScanData && (
            <div className="deep-scan-stats">
              <span>Wallets scanned: <strong>{deepScanData.wallets_scanned}</strong></span>
              <span>New nodes: <strong>{deepScanData.new_nodes}</strong></span>
              <span>New edges: <strong>{deepScanData.new_edges}</strong></span>
            </div>
          )}
        </div>
      )}

      <div className="graph-section">
        <h2>Infrastructure graph</h2>
        <div className="graph-container">
          <GraphView analysis={analysis} loading={loading} theme={theme} />
        </div>
      </div>

      <div className="bottom-grid">
        <FindingsCard analysis={analysis} />
        <EvidenceCard analysis={analysis} />
        <ReportCard
          analysis={analysis}
          report={report}
          loading={reportLoading}
          pdfLoading={pdfLoading}
          onGenerate={generateReport}
          onDownloadPdf={downloadPdf}
        />
      </div>
    </main>
  )
}

/* ============================================================ */
/* Graph                                                         */
/* ============================================================ */
function GraphView({ analysis, loading, theme }) {
  const containerRef = useRef(null)
  const cyRef = useRef(null)
  const graphData = useMemo(() => toCytoscapeElements(analysis), [analysis])

  // Re-style graph when theme changes
  useEffect(() => {
    if (!cyRef.current) return
    const isDark = theme === 'dark'
    cyRef.current.style()
      .selector('node')
      .style({
        color: isDark ? '#a1a1aa' : '#555',
        'border-color': isDark ? '#3f3f46' : '#ddd',
      })
      .selector('node:active, node:selected')
      .style({
        'border-color': isDark ? '#d4d4d8' : '#333',
      })
      .selector('edge')
      .style({
        'line-color': isDark ? '#3f3f46' : '#ccc',
        'target-arrow-color': isDark ? '#52525b' : '#bbb',
        color: isDark ? '#71717a' : '#999',
        'text-background-color': isDark ? '#1e2028' : '#fafafa',
      })
      .update()
  }, [theme])
  const [selectedNode, setSelectedNode] = useState(null)

  useEffect(() => {
    if (!containerRef.current || !graphData.length) {
      setSelectedNode(null)
      return undefined
    }

    const cy = cytoscape({
      container: containerRef.current,
      elements: graphData,
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(label)',
            'background-color': 'data(color)',
            color: '#555',
            width: 36,
            height: 36,
            'font-size': 10,
            'font-weight': 500,
            'text-wrap': 'wrap',
            'text-max-width': 100,
            'text-valign': 'bottom',
            'text-margin-y': 6,
            'border-width': 1,
            'border-color': '#ddd',
            'overlay-opacity': 0,
          },
        },
        {
          selector: 'node[?deep_scanned]',
          style: {
            'border-width': 2,
            'border-color': '#667eea',
            'border-style': 'double',
          },
        },
        {
          selector: 'node:active, node:selected',
          style: {
            'border-color': '#333',
            'border-width': 2,
          },
        },
        {
          selector: 'edge',
          style: {
            label: 'data(label)',
            width: 1,
            'line-color': '#ccc',
            'target-arrow-color': '#bbb',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            color: '#999',
            'font-size': 8,
            'text-background-color': '#fafafa',
            'text-background-opacity': 0.9,
            'text-background-padding': 2,
          },
        },
      ],
      layout: {
        name: 'breadthfirst',
        directed: true,
        spacingFactor: 1.5,
        animate: false,
        padding: 30,
      },
    })

    cyRef.current = cy

    cy.on('tap', 'node', (evt) => {
      const node = evt.target
      setSelectedNode({
        id: node.id(),
        label: node.data('label'),
        type: node.data('type') || 'unknown',
        color: node.data('color'),
      })
    })

    cy.on('tap', (evt) => {
      if (evt.target === cy) setSelectedNode(null)
    })

    cy.fit(undefined, 20)
    return () => {
      cy.destroy()
      cyRef.current = null
    }
  }, [graphData])

  return (
    <div style={{ position: 'relative', width: '100%', height: '100%' }}>
      {loading && (
        <div className="graph-placeholder">
          <span className="loading-text">Scanning infrastructure...</span>
        </div>
      )}
      
      {!loading && !analysis && (
        <div className="graph-placeholder">
          Enter a wallet or domain above to map infrastructure
        </div>
      )}

      <div 
        className="graph-canvas" 
        ref={containerRef} 
        style={{ 
          display: (!loading && analysis) ? 'block' : 'none',
          visibility: (!loading && analysis) ? 'visible' : 'hidden'
        }} 
      />

      {selectedNode && !loading && analysis && (
        <div className="node-detail">
          <div className="node-dot" style={{ background: selectedNode.color }} />
          <div className="node-info">
            <div className="node-label">{selectedNode.label}</div>
            <div className="node-type">{selectedNode.type.replace(/_/g, ' ')}</div>
          </div>
          <button className="node-close" onClick={() => setSelectedNode(null)} aria-label="Close">×</button>
        </div>
      )}
    </div>
  )
}

/* ============================================================ */
/* Findings                                                      */
/* ============================================================ */
function FindingsCard({ analysis }) {
  const findings = analysis?.findings || []
  return (
    <div className="card">
      <div className="card-title">Findings</div>
      {findings.length ? (
        <ul className="findings-list">
          {findings.slice(0, 12).map((item, i) => (
            <li key={`${item}-${i}`}>{item}</li>
          ))}
        </ul>
      ) : (
        <p className="muted-text">No findings yet</p>
      )}
    </div>
  )
}

/* ============================================================ */
/* Evidence                                                      */
/* ============================================================ */
function EvidenceCard({ analysis }) {
  const nodes = analysis?.nodes || []
  const edges = analysis?.edges || []
  const grouped = nodes.reduce((acc, node) => {
    acc[node.type] = (acc[node.type] || 0) + 1
    return acc
  }, {})

  return (
    <div className="card">
      <div className="card-title">Evidence</div>
      <div className="evidence-counts">
        <div>
          <strong>{nodes.length}</strong>
          <span>Nodes</span>
        </div>
        <div>
          <strong>{edges.length}</strong>
          <span>Edges</span>
        </div>
      </div>
      <div className="type-tags">
        {Object.entries(grouped).map(([type, count]) => (
          <span key={type}>{type.replace(/_/g, ' ')}<b>{count}</b></span>
        ))}
      </div>
    </div>
  )
}

/* ============================================================ */
/* Report                                                        */
/* ============================================================ */
function ReportCard({ analysis, report, loading, pdfLoading, onGenerate, onDownloadPdf }) {
  const handleCopy = useCallback(() => {
    if (report?.narrative) {
      navigator.clipboard.writeText(report.narrative).catch(() => {})
    }
  }, [report])

  return (
    <div className="card">
      <div className="card-title">Report</div>
      <div className="report-actions">
        <button className="btn btn-secondary" type="button" onClick={onGenerate} disabled={!analysis || loading}>
          {loading ? 'Generating...' : 'Generate report'}
        </button>
        <button className="btn-pdf" type="button" onClick={onDownloadPdf} disabled={!analysis || pdfLoading}>
          {pdfLoading ? 'Creating PDF...' : '📄 Download PDF'}
        </button>
        {report?.narrative && (
          <button className="btn btn-secondary" type="button" onClick={handleCopy}>
            Copy
          </button>
        )}
      </div>
      {report ? (
        <>
          <p className="report-text">{report.narrative}</p>
          <span className="report-source">{report.provider === 'gemini' ? 'Gemini' : 'Local'}</span>
        </>
      ) : (
        <p className="muted-text">Generate a summary report from analysis results</p>
      )}
    </div>
  )
}

/* ============================================================ */
/* Helpers                                                       */
/* ============================================================ */
function toCytoscapeElements(analysis) {
  if (!analysis) return []
  const nodes = (analysis.nodes || []).map((node) => ({
    data: {
      id: node.id,
      label: node.label,
      color: colorForType(node.type),
      type: node.type,
      deep_scanned: node.data?.deep_scanned || false,
    },
  }))
  const edges = (analysis.edges || []).map((edge) => ({
    data: {
      id: edge.id,
      source: edge.source,
      target: edge.target,
      label: edge.relation,
    },
  }))
  return [...nodes, ...edges]
}

function colorForType(type) {
  const colors = {
    wallet: '#5b9bd5',
    deployer: '#e07b39',
    domain: '#6aab73',
    subdomain: '#8fb83a',
    sibling_domain: '#d4a238',
    email: '#9b72cf',
    snapshot: '#999',
    scamdb_flag: '#d44',
    web_mention: '#5aada8',
  }
  return colors[type] || '#aaa'
}

export default App
