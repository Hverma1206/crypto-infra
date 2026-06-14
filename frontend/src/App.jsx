import { useEffect, useMemo, useRef, useState } from 'react'
import cytoscape from 'cytoscape'
import {
  AlertTriangle,
  Binary,
  CircleDollarSign,
  Database,
  FileText,
  GitBranch,
  Globe,
  Loader2,
  Network,
  Search,
  ShieldAlert,
} from 'lucide-react'
import './App.css'

const API_BASE = import.meta.env.VITE_API_BASE || 'http://localhost:5000'

const sampleInputs = ['github.com', 'binance.com', '0xde0B295669a9FD93d5F28D9Ec85E40f4cb697BAe']

function App() {
  const [input, setInput] = useState(sampleInputs[0])
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
          <Database size={16} />
          Public sources
        </div>
      </section>

      <section className="workspace">
        <aside className="control-panel">
          <form onSubmit={runAnalysis} className="search-panel">
            <label htmlFor="artifact">Artifact</label>
            <div className="input-row">
              <Search size={18} />
              <input
                id="artifact"
                value={input}
                onChange={(event) => setInput(event.target.value)}
                placeholder="Wallet or domain"
              />
            </div>

            <label htmlFor="domain">Linked domain</label>
            <div className="input-row">
              <Globe size={18} />
              <input
                id="domain"
                value={domain}
                onChange={(event) => setDomain(event.target.value)}
                placeholder="Optional for wallet cases"
              />
            </div>

            <button className="primary-button" type="submit" disabled={loading || !input.trim()}>
              {loading ? <Loader2 className="spin" size={18} /> : <Network size={18} />}
              Analyze
            </button>
          </form>

          <div className="sample-strip">
            {sampleInputs.map((item) => (
              <button key={item} type="button" onClick={() => setInput(item)} title={item}>
                {item.startsWith('0x') ? <Binary size={16} /> : <Globe size={16} />}
              </button>
            ))}
          </div>

          <RiskPanel analysis={analysis} />
          <SummaryPanel analysis={analysis} />
        </aside>

        <section className="main-panel">
          {error && (
            <div className="error-banner">
              <AlertTriangle size={18} />
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

function GraphView({ analysis, loading }) {
  const containerRef = useRef(null)
  const graphData = useMemo(() => toCytoscapeElements(analysis), [analysis])

  useEffect(() => {
    if (!containerRef.current || !graphData.length) return undefined

    const cy = cytoscape({
      container: containerRef.current,
      elements: graphData,
      style: [
        {
          selector: 'node',
          style: {
            label: 'data(label)',
            'background-color': 'data(color)',
            color: '#172033',
            width: 46,
            height: 46,
            'font-size': 11,
            'text-wrap': 'wrap',
            'text-max-width': 96,
            'text-valign': 'bottom',
            'text-margin-y': 8,
            'border-width': 2,
            'border-color': '#ffffff',
          },
        },
        {
          selector: 'edge',
          style: {
            label: 'data(label)',
            width: 2,
            'line-color': '#99a3b3',
            'target-arrow-color': '#99a3b3',
            'target-arrow-shape': 'triangle',
            'curve-style': 'bezier',
            color: '#657084',
            'font-size': 9,
            'text-background-color': '#f8fafc',
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

    cy.fit(undefined, 28)
    return () => cy.destroy()
  }, [graphData])

  if (loading) {
    return (
      <div className="graph-empty">
        <Loader2 className="spin" size={36} />
      </div>
    )
  }

  if (!analysis) {
    return (
      <div className="graph-empty">
        <GitBranch size={40} />
      </div>
    )
  }

  return <div className="graph-canvas" ref={containerRef} />
}

function RiskPanel({ analysis }) {
  const risk = analysis?.risk || { score: 0, level: 'READY', reasons: [] }
  return (
    <section className={`panel risk-panel ${risk.level.toLowerCase()}`}>
      <div className="panel-title">
        <ShieldAlert size={18} />
        Risk
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
      <Metric icon={<CircleDollarSign size={18} />} label="ETH received" value={wallet.impact?.total_eth_received ?? '0'} />
      <Metric icon={<Network size={18} />} label="Wallet links" value={wallet.connected_wallets ?? '0'} />
      <Metric icon={<Globe size={18} />} label="Sibling domains" value={domain.sibling_domains ?? '0'} />
      <Metric icon={<Database size={18} />} label="ScamDB hits" value={scamdb.confirmed ?? '0'} />
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

function FindingsPanel({ analysis }) {
  const findings = analysis?.findings || []
  return (
    <section className="panel evidence-card">
      <div className="panel-title">
        <AlertTriangle size={18} />
        Findings
      </div>
      {findings.length ? (
        <ul className="finding-list">
          {findings.slice(0, 8).map((item, index) => (
            <li key={`${item}-${index}`}>{item}</li>
          ))}
        </ul>
      ) : (
        <p className="muted">No findings yet</p>
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
    <section className="panel evidence-card">
      <div className="panel-title">
        <GitBranch size={18} />
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
            {type.replace('_', ' ')} <b>{count}</b>
          </span>
        ))}
      </div>
    </section>
  )
}

function ReportPanel({ analysis, report, loading, onGenerate }) {
  return (
    <section className="panel report-card">
      <div className="panel-title">
        <FileText size={18} />
        Report
      </div>
      <button className="secondary-button" type="button" onClick={onGenerate} disabled={!analysis || loading}>
        {loading ? <Loader2 className="spin" size={16} /> : <FileText size={16} />}
        Generate
      </button>
      <p>{report?.narrative || 'No report generated'}</p>
    </section>
  )
}

function toCytoscapeElements(analysis) {
  if (!analysis) return []
  const nodes = (analysis.nodes || []).map((node) => ({
    data: {
      id: node.id,
      label: node.label,
      color: colorForType(node.type),
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
