import AdvancedLab from './AdvancedLab';
import React,{useEffect,useState} from 'react';
import {createRoot} from 'react-dom/client';
import {Shield,Activity,AlertTriangle,Terminal,RefreshCw,Play,ChevronRight,FileWarning} from 'lucide-react';
import './styles.css';
const API='http://127.0.0.1:8000/api';
async function api(path,opts){const r=await fetch(API+path,{headers:{'Content-Type':'application/json'},...opts}); return r.json();}
function App(){
 const [metrics,setMetrics]=useState({events:0,incidents:0,critical:0,open_incidents:0,users:5}); const [incidents,setIncidents]=useState([]); const [events,setEvents]=useState([]); const [scenario,setScenario]=useState('multi_stage'); const [count,setCount]=useState(100); const [selected,setSelected]=useState(null); const [loading,setLoading]=useState(false); const [page,setPage]=useState('dashboard');
 const refresh=async()=>{setMetrics(await api('/metrics'));setIncidents(await api('/incidents'));setEvents(await api('/events?limit=100'));}; useEffect(()=>{refresh()},[]);
 
const generate = async () => {
    setLoading(true);
    setSimError('');
    setSimResult(null);
  
    try {
      const result = await api('/simulator/generate', {
        method: 'POST',
        body: JSON.stringify({
          scenario,
          count: Number(count),
          seed: 42
        })
      });
  
      if (!result || result.run_id === undefined) {
        throw new Error(result?.detail || 'Unexpected simulator response.');
      }
  
      setSimResult(result);
      await refresh();
      setPage('simulator');
    } catch (error) {
      setSimError(error.message || 'Could not generate simulation.');
    } finally {
      setLoading(false);
    }
  };
  
 const openIncident=async id=>{setSelected(await api('/incidents/'+id));setPage('detail')};
 const [simResult, setSimResult] = useState(null);
const [simError, setSimError] = useState('');
 return <div className="app"><aside><div className="brand"><Shield/> <span>AEGIS<span>OS</span></span></div>
 

<nav>
  {[
    ['dashboard', 'Dashboard', Activity],
    ['incidents', 'Incidents', AlertTriangle],
    ['events', 'Events', FileWarning],
    ['simulator', 'Attack Simulator', Terminal],
    ['advanced', 'Advanced Lab', Activity]
  ].map(([p, l, I]) => (
    <button
      className={page === p ? 'active' : ''}
      onClick={() => setPage(p)}
      key={p}
    >
      <I size={18} />
      {l}
    </button>
  ))}
</nav>
</aside>
 <main>
 {page==='dashboard'&&<Dashboard metrics={metrics} incidents={incidents} openIncident={openIncident}/>} {page==='simulator'&&
  <Simulator
    scenario={scenario}
    setScenario={setScenario}
    count={count}
    setCount={setCount}
    generate={generate}
    loading={loading}
    simResult={simResult}
    simError={simError}
  />
} {page==='events'&&<Events events={events}/>} {page==='incidents'&&<Incidents incidents={incidents} openIncident={openIncident}/>} {page==='detail'&&<Detail data={selected} openIncident={openIncident}/>}{page === 'advanced' && <AdvancedLab />}</main></div>}

function Cards({metrics}){return <div className="cards">{[['EVENTS',metrics.events,'blue'],['INCIDENTS',metrics.incidents,'purple'],['CRITICAL',metrics.critical,'red'],['OPEN INCIDENTS',metrics.open_incidents,'orange']].map(x=><div className="card" key={x[0]}><small>{x[0]}</small><strong className={x[2]}>{x[1]}</strong><span>Live database metric</span></div>)}</div>}
function Dashboard({metrics,incidents,openIncident}){return <><Cards metrics={metrics}/><div className="grid2"><section className="panel"><div className="panelhead"><h2>Active Incidents</h2><button onClick={()=>location.reload()}>View all</button></div>{incidents.slice(0,5).map(i=><div className="incidentrow" key={i.id} onClick={()=>openIncident(i.id)}><span className={'dot '+i.severity.toLowerCase()}></span><div><b>{i.title}</b><small>{i.user} · {i.source_ip}</small></div><strong>{i.risk_score}</strong><ChevronRight size={17}/></div>)}{!incidents.length&&<Empty/>}</section><section className="panel"><div className="panelhead"><h2>Detection Pipeline</h2></div><div className="pipeline">{['Event Ingestion','Rule Detection','ML Anomaly','Correlation','Risk Scoring','Incident'].map((x,i)=><div key={x}><span>{i+1}</span>{x}</div>)}</div></section></div></>}

function Simulator({
    scenario, setScenario, count, setCount,
    generate, loading, simResult, simError
  }) {
    return (
      <>
        <section className="sim panel">
          <div className="simintro">
            <div>
              <small>SAFE TEST ENVIRONMENT</small>
              <h2>Generate realistic security telemetry</h2>
              <p>
                Run controlled security scenarios and inspect
                detection results. No real attack is performed.
              </p>
            </div>
            <Terminal size={55} />
          </div>
  
          <div className="formgrid">
            <label>
              Scenario
              <select
                value={scenario}
                onChange={e => setScenario(e.target.value)}
              >
                <option value="multi_stage">Multi-stage Account Compromise</option>
                <option value="normal">Normal Activity</option>
                <option value="brute_force">Brute Force</option>
                <option value="account_takeover">Account Takeover</option>
                <option value="privilege_escalation">Privilege Escalation</option>
                <option value="exfiltration">Data Exfiltration</option>
              </select>
            </label>
  
            <label>
              Number of events (10–1000)
              <input
                type="number"
                min="10"
                max="1000"
                value={count}
                onChange={e => setCount(e.target.value)}
              />
            </label>
          </div>
  
          <button
            className="primary"
            onClick={generate}
            disabled={loading || Number(count) < 10 || Number(count) > 1000}
          >
            <Play size={18} />
            {loading ? 'Analyzing telemetry...' : 'Run Security Simulation'}
          </button>
  
          {simError && (
            <div className="sim-error">
              <b>Simulation failed</b>
              <p>{simError}</p>
            </div>
          )}
        </section>
  
        {simResult && (
          <section className="panel sim-results">
            <div className="panelhead">
              <div>
                <small>ANALYSIS COMPLETE</small>
                <h2>Simulation Results</h2>
              </div>
              <span className="badge high">{simResult.scenario}</span>
            </div>
  
            <p className="run-id">
              Run ID: <code>{simResult.run_id}</code>
            </p>
  
            <div className="cards">
              {[
                ['EVENTS GENERATED', simResult.events_created, 'blue'],
                ['ALERTS DETECTED', simResult.alerts_detected, 'orange'],
                ['INCIDENTS CREATED', simResult.incidents_created, 'purple'],
                [
                  'ANOMALY SCORE',
                  Number(simResult.anomaly_score || 0).toFixed(3),
                  'red'
                ]
              ].map(([label, value, color]) => (
                <div className="card" key={label}>
                  <small>{label}</small>
                  <strong className={color}>{value}</strong>
                  <span>Current simulation run</span>
                </div>
              ))}
            </div>
  
            <h3>Detected Alerts</h3>
  
            {simResult.alerts?.length ? (
              simResult.alerts.map((alert, index) => (
                <div className="sim-alert" key={`${alert.type}-${index}`}>
                  <span className={`badge ${(alert.severity || 'medium').toLowerCase()}`}>
                    {alert.severity}
                  </span>
                  <div>
                    <b>{alert.type.replaceAll('_', ' ')}</b>
                    <p>{alert.reason}</p>
                    <small>
                      User: {alert.user || 'Unknown'} · Source: {alert.source_ip || 'Unknown'}
                    </small>
                  </div>
                </div>
              ))
            ) : (
              <div className="empty">
                No rule-based alerts were detected in this run.
              </div>
            )}
  
            <h3>Created Incidents</h3>
  
            {simResult.incidents?.length ? (
              simResult.incidents.map(incident => (
                <div className="sim-alert" key={incident.id}>
                  <span className={`badge ${(incident.severity || 'medium').toLowerCase()}`}>
                    {incident.severity}
                  </span>
                  <div>
                    <b>{incident.title}</b>
                    <p>{incident.summary}</p>
                    <small>
                      Risk score: {incident.risk_score}/100 · Status: {incident.status}
                    </small>
                  </div>
                </div>
              ))
            ) : (
              <div className="empty">
                No correlated incidents were created for this run.
              </div>
            )}
          </section>
        )}
      </>
    );
  }
  
function Incidents({incidents,openIncident}){return <section className="panel"><div className="panelhead"><h2>Incident Queue</h2><span>{incidents.length} total</span></div>{incidents.map(i=><div className="bigrow" key={i.id} onClick={()=>openIncident(i.id)}><div><span className={'badge '+i.severity.toLowerCase()}>{i.severity}</span><h3>{i.title}</h3><p>{i.summary}</p><small>{i.user} · {i.source_ip} · {new Date(i.created_at).toLocaleString()}</small></div><div className="risk"><b>{i.risk_score}</b><span>RISK</span></div><ChevronRight/></div>)}{!incidents.length&&<Empty/>}</section>}
function Events({events}){return <section className="panel tablewrap"><div className="panelhead"><h2>Security Events</h2><span>{events.length} shown</span></div><table><thead><tr><th>Time</th><th>Type</th><th>User</th><th>Source IP</th><th>Device</th><th>Country</th><th>Action</th></tr></thead><tbody>{events.map(e=><tr key={e.id}><td>{new Date(e.timestamp).toLocaleTimeString()}</td><td><b>{e.event_type}</b></td><td>{e.user}</td><td>{e.source_ip}</td><td>{e.device}</td><td>{e.country}</td><td>{e.action||'—'}</td></tr>)}</tbody></table></section>}
function Detail({data}){if(!data)return <Empty/>; const inv=data.investigation||{}; return <><section className="detailhero"><div><span className={'badge '+data.severity.toLowerCase()}>{data.severity}</span><h2>{data.title}</h2><p>{data.summary}</p></div><div className="score"><b>{data.risk_score}</b><span>/ 100</span><small>RISK SCORE</small></div></section><div className="grid2"><section className="panel"><h2>AI Investigation</h2><div className="bluf"><b>BLUF</b><p>{inv.bluf}</p><span>Confidence: {inv.confidence||0}%</span></div><h3>Evidence</h3>{(inv.evidence||[]).map(x=><div className="evidence" key={x}>✓ {x}</div>)}<h3>Recommended Response</h3>{(inv.recommendations||[]).map((x,i)=><div className="recommend" key={x}><span>{i+1}</span>{x}</div>)}</section><section className="panel"><h2>Attack Timeline</h2>{(data.events||[]).map(e=><div className="timeline" key={e.id}><div className="time">{new Date(e.timestamp).toLocaleTimeString()}</div><div><b>{e.event_type}</b><p>{e.action||e.resource||'Security event'}</p></div></div>)}<h2>MITRE ATT&CK</h2>{(data.mitre||[]).map(x=><div className="mitre" key={x}>{x}</div>)}</section></div></>}
function Empty(){return <div className="empty">No data yet. Open Attack Simulator and generate a scenario.</div>}
createRoot(document.getElementById('root')).render(<App/>);
