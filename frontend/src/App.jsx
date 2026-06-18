import { useEffect, useMemo, useRef, useState, useCallback } from 'react'
import cytoscape from 'cytoscape'
import {
  AlertTriangle,
  Binary,
  CircleDollarSign,
  Copy,
  Database,
  FileText,
  GitBranch,
  Globe,
  Loader2,
  Network,
  Search,
  ShieldAlert,
  X,
} from 'lucide-react'
import './App.css'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:8001'

const sampleInputs = [
  { label: 'example.com', icon: 'domain' },
  { label: 'binance.com', icon: 'domain' },
  { label: '0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe', icon: 'wallet' },
]

function App() {
  const [input, setInput] = useState('')
  const [domain, setDomain] = useState('')
  const [analysis, setAnalysis] = useState(null)
  const [report, setReport] = useState(null)
  const [loading, setLoading] = useState(false)
  const [reportLoading, setReportLoading] = useState(false)
  const [error, setError] = useState('')

  async function runAnalysis(event) {
    event?.preventDefault()
    setLoading(true)
    setError('')
    setReport(null)

    try {
      const response = await fetch(`${API_BASE}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ input, domain }),
      })
      const data = await response.json()
      if (!response.ok) {
        throw new Error(data.error || 'Analysis failed')
      }
      setAnalysis(data)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

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

  return (
    <main className="app-shell">
      <section className="topbar">
        <div>
          <p className="eyebrow">OSINT investigation workspace</p>
          <h1>Crypto Scam Infrastructure Mapper</h1>
        </div>
        <div className="status-pill">
          <Database size={14} />
          Public sources only
        </div>
      </section>

      <section className="workspace">
        <aside className="control-panel">
          <form onSubmit={runAnalysis} className="search-panel">
            <label htmlFor="artifact">Artifact</label>
            <div className="input-row">
              <Search size={16} />
              <input
                id="artifact"
                value={input}
                onChange={(event) => setInput(event.target.value)}
                placeholder="Enter wallet address or domain…"
              />
            </div>

            <label htmlFor="domain">Linked domain</label>
            <div className="input-row">
              <Globe size={16} />
              <input
                id="domain"
                value={domain}
                onChange={(event) => setDomain(event.target.value)}
                placeholder="Optional — for wallet cases"
              />
            </div>

            <button className="primary-button" type="submit" disabled={loading || !input.trim()}>
              {loading ? <Loader2 className="spin" size={16} /> : <Network size={16} />}
              {loading ? 'Scanning…' : 'Analyze'}
            </button>
          </form>

          <div className="sample-strip">
            {sampleInputs.map((item) => (
              <button key={item.label} type="button" onClick={() => setInput(item.label)} title={item.label}>
                {item.icon === 'wallet' ? <Binary size={14} /> : <Globe size={14} />}
                {item.label.startsWith('0x') ? `${item.label.slice(0, 8)}…` : item.label}
              </button>
            ))}
          </div>

          <RiskPanel analysis={analysis} />
          <SummaryPanel analysis={analysis} />
        </aside>

        <section className="main-panel">
          {error && (
            <div className="error-banner">
              <AlertTriangle size={16} />
              {error}
            </div>
          )}

          <div className="graph-band">
            <GraphView analysis={analysis} loading={loading} />
          </div>

          <div className="lower-grid">
            <FindingsPanel analysis={analysis} />
            <EvidencePanel analysis={analysis} />
            <ReportPanel
              analysis={analysis}
              report={report}
              loading={reportLoading}
              onGenerate={generateReport}
            />
          </div>
        </section>
      </section>
    </main>
  )
}

/* ================================================================== */
/* Graph Visualization                                                 */
/* ================================================================== */
function GraphView({ analysis, loading }) {
  const containerRef = useRef(null)
  const cyRef = useRef(null)
  const graphData = useMemo(() => toCytoscapeElements(analysis), [analysis])
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
            color: '#cbd5e1',
            width: 42,
            height: 42,
            'font-size': 10,
            'font-weight': 600,
            'text-wrap': 'wrap',
            'text-max-width': 100,
            'text-valign': 'bottom',
            'text-margin-y': 8,
            'border-width': 2,
            'border-color': 'rgba(255,255,255,0.15)',
            'overlay-opacity': 0,
            'transition-property': 'border-color, border-width, width, height',
            'transition-duration': '0.2s',
          },
        },
        {
          selector: 'node:active, node:selected',
          style: {
            'border-color': '#06b6d4',
            'border-width': 3,
            width: 50,
            height: 50,
          },
        },
        {
          selector: 'edge',
          style: {
            label: 'data(label)',
            width: 1.5,
            'line-color': 'rgba(100, 116, 139, 0.4)',
            'target-arrow-color': 'rgba(100, 116, 139, 0.5)',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            color: '#64748b',
            'font-size': 8,
            'text-background-color': '#111827',
            'text-background-opacity': 0.85,
            'text-background-padding': 2,
          },
        },
      ],
      layout: {
        name: 'cose',
        animate: false,
        padding: 38,
        nodeRepulsion: 9000,
        idealEdgeLength: 120,
      },
    })

    cyRef.current = cy

    // Node tap handler — show details
    cy.on('tap', 'node', (evt) => {
      const node = evt.target
      setSelectedNode({
        id: node.id(),
        label: node.data('label'),
        type: node.data('type') || 'unknown',
        color: node.data('color'),
      })
    })

    // Tap on background to deselect
    cy.on('tap', (evt) => {
      if (evt.target === cy) {
        setSelectedNode(null)
      }
    })

    cy.fit(undefined, 28)
    return () => {
      cy.destroy()
      cyRef.current = null
    }
  }, [graphData])

  if (loading) {
    return (
      <div className="graph-empty">
        <div className="scanning-indicator">
          <div className="scan-bars">
            <span /><span /><span /><span /><span />
          </div>
          <p>Scanning infrastructure…</p>
        </div>
      </div>
    )
  }

  if (!analysis) {
    return (
      <div className="graph-empty">
        <div className="graph-empty-content">
          <GitBranch size={36} />
          <p>Enter a wallet address or domain above to begin infrastructure mapping</p>
        </div>
      </div>
    )
  }

  return (
    <>
      <div className="graph-canvas" ref={containerRef} />
      {selectedNode && (
        <div className="node-detail fade-in">
          <div className="node-detail-dot" style={{ background: selectedNode.color }} />
          <div className="node-detail-info">
            <div className="node-detail-label">{selectedNode.label}</div>
            <div className="node-detail-type">{selectedNode.type.replace(/_/g, ' ')}</div>
          </div>
          <button className="node-detail-close" onClick={() => setSelectedNode(null)} aria-label="Close">
            <X size={16} />
          </button>
        </div>
      )}
    </>
  )
}

/* ================================================================== */
/* Side Panels                                                         */
/* ================================================================== */
function RiskPanel({ analysis }) {
  const risk = analysis?.risk || { score: 0, level: 'READY', reasons: [] }
  return (
    <section className={`panel risk-panel ${risk.level.toLowerCase()}`}>
      <div className="panel-title">
        <ShieldAlert size={16} />
        Risk Assessment
      </div>
      <div className="risk-score">{risk.score}</div>
      <div className="risk-level">{risk.level}</div>
      <div className="meter">
        <span style={{ width: `${Math.min(risk.score || 0, 100)}%` }} />
      </div>
    </section>
  )
}

function SummaryPanel({ analysis }) {
  const summary = analysis?.summary || {}
  const wallet = summary.wallet || {}
  const domain = summary.domain || {}
  const scamdb = summary.scamdb || {}

  return (
    <section className="panel metric-list">
      <Metric icon={<CircleDollarSign size={16} />} label="ETH received" value={wallet.impact?.total_eth_received ?? '—'} />
      <Metric icon={<Network size={16} />} label="Wallet links" value={wallet.connected_wallets ?? '—'} />
      <Metric icon={<Globe size={16} />} label="Sibling domains" value={domain.sibling_domains ?? '—'} />
      <Metric icon={<Database size={16} />} label="ScamDB hits" value={scamdb.confirmed ?? '—'} />
    </section>
  )
}

function Metric({ icon, label, value }) {
  return (
    <div className="metric">
      {icon}
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  )
}

/* ================================================================== */
/* Lower Panels                                                        */
/* ================================================================== */
function FindingsPanel({ analysis }) {
  const findings = analysis?.findings || []
  return (
    <section className="panel evidence-card fade-in">
      <div className="panel-title">
        <AlertTriangle size={16} />
        Findings
      </div>
      {findings.length ? (
        <ul className="finding-list">
          {findings.slice(0, 8).map((item, index) => (
            <li key={`${item}-${index}`}>{item}</li>
          ))}
        </ul>
      ) : (
        <p className="muted">No findings yet — run an analysis to begin</p>
      )}
    </section>
  )
}

function EvidencePanel({ analysis }) {
  const nodes = analysis?.nodes || []
  const edges = analysis?.edges || []
  const grouped = nodes.reduce((acc, node) => {
    acc[node.type] = (acc[node.type] || 0) + 1
    return acc
  }, {})

  return (
    <section className="panel evidence-card fade-in">
      <div className="panel-title">
        <GitBranch size={16} />
        Evidence
      </div>
      <div className="evidence-grid">
        <strong>{nodes.length}</strong>
        <span>Nodes</span>
        <strong>{edges.length}</strong>
        <span>Edges</span>
      </div>
      <div className="type-list">
        {Object.entries(grouped).map(([type, count]) => (
          <span key={type}>
            {type.replace(/_/g, ' ')} <b>{count}</b>
          </span>
        ))}
      </div>
    </section>
  )
}

function ReportPanel({ analysis, report, loading, onGenerate }) {
  const handleCopy = useCallback(() => {
    if (report?.narrative) {
      navigator.clipboard.writeText(report.narrative).catch(() => {})
    }
  }, [report])

  return (
    <section className="panel report-card fade-in">
      <div className="panel-title">
        <FileText size={16} />
        Report
      </div>
      <div style={{ display: 'flex', gap: '8px' }}>
        <button className="secondary-button" type="button" onClick={onGenerate} disabled={!analysis || loading}>
          {loading ? <Loader2 className="spin" size={14} /> : <FileText size={14} />}
          Generate
        </button>
        {report?.narrative && (
          <button className="secondary-button" type="button" onClick={handleCopy} title="Copy to clipboard">
            <Copy size={14} />
          </button>
        )}
      </div>
      {report ? (
        <>
          <p className="report-narrative">{report.narrative}</p>
          <span className="report-provider">{report.provider === 'gemini' ? '✦ Gemini AI' : 'Local'}</span>
        </>
      ) : (
        <p className="muted">Generate an investigation summary report</p>
      )}
    </section>
  )
}

/* ================================================================== */
/* Graph Data Helpers                                                  */
/* ================================================================== */
function toCytoscapeElements(analysis) {
  if (!analysis) return []
  const nodes = (analysis.nodes || []).map((node) => ({
    data: {
      id: node.id,
      label: node.label,
      color: colorForType(node.type),
      type: node.type,
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
    wallet: '#38bdf8',
    deployer: '#f97316',
    domain: '#22c55e',
    subdomain: '#84cc16',
    sibling_domain: '#f59e0b',
    email: '#a855f7',
    snapshot: '#64748b',
    scamdb_flag: '#ef4444',
    web_mention: '#14b8a6',
  }
  return colors[type] || '#94a3b8'
}

export default App
