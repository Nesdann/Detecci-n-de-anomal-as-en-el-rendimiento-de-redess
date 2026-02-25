
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";
import { useEffect, useState } from "react";

function App() {
  const [page, setPage] = useState("overview");

  return (
    <div className="flex min-h-screen bg-gray-950 text-gray-200">
      <Sidebar page={page} setPage={setPage} />
      <div className="flex-1 p-10">
        {page === "overview" && <Overview />}
        {page === "config" && <Configuration />}
        {page === "about" && <About />}
        {page === "actions" && <Actions />}
        {page === "about_me" && <About_me />}
      </div>
    </div>
  );
}

function Sidebar({ page, setPage }) {
  const itemClass = (name) =>
    `w-full text-left px-4 py-3 rounded-xl mb-2 transition ${
      page === name
        ? "bg-gray-800 text-white font-medium"
        : "text-gray-400 hover:bg-gray-800 hover:text-white"
    }`;

  return (
    <div className="w-72 bg-gray-900 p-8 flex flex-col border-r border-gray-800">
      <h1 className="text-2xl font-semibold mb-12 tracking-wide text-blue-500">
        Sentinel
      </h1>
      <button onClick={() => setPage("overview")} className={itemClass("overview")}>Overview</button>
      <button onClick={() => setPage("config")} className={itemClass("config")}>Configuration</button>
      <button onClick={() => setPage("actions")} className={itemClass("actions")}>Security Actions</button>
      <button onClick={() => setPage("about")} className={itemClass("about")}>Engine Info</button>
      <button onClick={() => setPage("about_me")} className={itemClass("about_me")}>About me</button>
      <div className="mt-auto text-xs text-gray-600 uppercase tracking-widest">
        v0.1 Engine • Neural Network
      </div>
    </div>
  );
}

function Overview() {
  const [data, setData] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const threshold = 70;

  useEffect(() => {
    const fetchData = async () => {
      try {
        const response = await fetch('http://localhost:8000/api/alerts');
        const latestAlerts = await response.json();
        
        setAlerts(latestAlerts);
        
        if (latestAlerts.length > 0) {
          const chartData = latestAlerts.slice(0, 20).reverse().map((a, i) => ({
            time: a.timestamp,
            score: a.score
          }));
          setData(chartData);
        }
      } catch (err) {
        console.warn("Backend offline");
      }
    };

    const interval = setInterval(fetchData, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div>
      <h2 className="text-3xl font-semibold mb-10 tracking-tight text-white">
        Network Overview
      </h2>

      <div className="grid grid-cols-4 gap-6 mb-10">
        <StatCard title="Real-time Flows" value={alerts.length > 0 ? "Active" : "Idle"} />
        <StatCard title="Total Analysed" value={alerts.length} />
        <StatCard title="System Threats" value={alerts.filter(a => a.tipo !== 'NORMAL').length} highlight />
        <StatCard title="IA Sensitivity" value={`${threshold}%`} />
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-8 mb-10">
        <h3 className="text-lg mb-6 text-gray-400 font-medium">Neural Confidence Score (%)</h3>
        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data}>
              <XAxis dataKey="time" stroke="#374151" fontSize={10} />
              <YAxis domain={[0, 100]} stroke="#374151" fontSize={10} />
              <Tooltip 
                contentStyle={{ backgroundColor: '#111827', border: '1px solid #374151' }}
                itemStyle={{ color: '#3b82f6' }}
              />
              <Line
                type="monotone"
                dataKey="score"
                stroke="#3b82f6"
                strokeWidth={3}
                dot={{ r: 4, fill: '#3b82f6' }}
                animationDuration={300}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-8 text-white">
        <h3 className="text-lg mb-6 text-gray-400 font-medium">Detection Log</h3>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-gray-500 border-b border-gray-800">
              <th className="text-left pb-4">Timestamp</th>
              <th className="text-left pb-4">Origin</th>
              <th className="text-left pb-4">Target</th>
              <th className="text-left pb-4">Classification</th>
              <th className="text-left pb-4">Confidence</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {alerts.slice(0, 10).map((alert, i) => (
              <tr key={i} className="hover:bg-gray-800/30 transition">
                <td className="py-4 text-gray-400">{alert.timestamp}</td>
                <td className="py-4 font-mono">{alert.origen}</td>
                <td className="py-4 font-mono">{alert.destino}</td>
                <td className={`py-4 font-bold ${alert.tipo !== 'NORMAL' ? 'text-red-500' : 'text-emerald-500'}`}>
                  {alert.tipo}
                </td>
                <td className="py-4 font-medium">{alert.score}%</td>
              </tr>
            ))}
          </tbody>
        </table>
        {alerts.length === 0 && <p className="text-gray-600 mt-6 text-center">Waiting for engine data...</p>}
      </div>
    </div>
  );
}

function Actions() {
  const [bans, setBans] = useState([
    { id: 1, ip: "192.168.1.105", reason: "Potential Flooding" },
  ]);

  const addBan = () => {
    const newIP = `192.168.1.${Math.floor(Math.random() * 254)}`;
    setBans([{ id: Date.now(), ip: newIP, reason: "Anomalous Pattern" }, ...bans]);
  };

  return (
    <div>
      <h2 className="text-3xl font-semibold mb-8 text-white">Security Actions</h2>
      <button onClick={addBan} className="bg-red-600 hover:bg-red-700 text-white font-medium px-6 py-2.5 rounded-xl mb-8 transition shadow-lg shadow-red-900/20">
        Manual IP Block
      </button>

      <div className="bg-gray-900 border border-gray-800 rounded-2xl overflow-hidden">
        <table className="w-full text-sm">
          <thead className="bg-gray-800/50 text-gray-400">
            <tr>
              <th className="text-left p-4">Identity</th>
              <th className="text-left p-4">Violation</th>
              <th className="text-left p-4">Management</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {bans.map((ban) => (
              <tr key={ban.id} className="hover:bg-gray-800/20">
                <td className="p-4 font-mono">{ban.ip}</td>
                <td className="p-4 text-gray-400">{ban.reason}</td>
                <td className="p-4 space-x-6">
                  <button onClick={() => setBans(bans.filter(b => b.id !== ban.id))} className="text-emerald-500 hover:text-emerald-400 font-medium">Revoke</button>
                  <button className="text-gray-500 hover:text-white">Audit</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function StatCard({ title, value, highlight }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6">
      <p className="text-xs uppercase tracking-widest text-gray-500 mb-2">{title}</p>
      <p className={`text-3xl font-bold ${highlight ? "text-red-500" : "text-white"}`}>
        {value}
      </p>
    </div>
  );
}

function About_me() {
  return (
    <div className="max-w-4xl">
      <h2 className="text-3xl font-semibold mb-10 text-white">Developer Profile</h2>
      <div className="bg-gray-900 border border-gray-800 rounded-3xl p-10 relative overflow-hidden">
        <div className="absolute top-0 right-0 w-32 h-32 bg-blue-600/10 blur-3xl rounded-full -mr-16 -mt-16"></div>
        <h3 className="text-2xl font-bold text-blue-500 mb-6">Nesdan</h3>
        <p className="text-gray-300 text-lg leading-relaxed mb-6">Computer Science student at FaMAF. Focused on Cybersecurity, Network Forensics, and Neural Detection architectures.</p>
        <div className="flex gap-4">
          <span className="bg-gray-800 px-4 py-1.5 rounded-full text-xs font-mono text-gray-400">FaMAF</span>
          <span className="bg-gray-800 px-4 py-1.5 rounded-full text-xs font-mono text-gray-400">Python/IA</span>
          <span className="bg-gray-800 px-4 py-1.5 rounded-full text-xs font-mono text-gray-400">React/Tailwind</span>
        </div>
      </div>
    </div>
  );
}

function Configuration() {
  return (
    <div className="max-w-2xl">
      <h2 className="text-3xl font-semibold mb-10 text-white">Configuration</h2>
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-8 space-y-8">
        <div>
          <div className="flex justify-between mb-4">
            <label className="text-sm font-medium text-gray-300">Model Sensitivity</label>
            <span className="text-blue-500 text-sm">Adaptive</span>
          </div>
          <input type="range" className="w-full h-2 bg-gray-800 rounded-lg appearance-none cursor-pointer accent-blue-600" />
        </div>
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-4">Analysis Window</label>
          <select className="w-full bg-gray-800 border border-gray-700 text-white p-3 rounded-xl focus:ring-2 focus:ring-blue-600 outline-none">
            <option>Short (60s)</option>
            <option>Standard (300s)</option>
            <option>Deep (15m)</option>
          </select>
        </div>
        <button className="w-full bg-blue-600 hover:bg-blue-500 text-white font-bold py-4 rounded-xl transition shadow-lg shadow-blue-900/20">
          Commit Changes
        </button>
      </div>
    </div>
  );
}

function About() {
  return (
    <div className="max-w-2xl">
      <h2 className="text-3xl font-semibold mb-10 text-white">Engine Info</h2>
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-8 space-y-2">
        <Info label="Architecture" value="Multilayer Perceptron (MLP)" />
        <Info label="Input Features" value="9 Protocol Metrics" />
        <Info label="Training Set" value="Fused Traffic Logs" />
        <Info label="Status" value="Operational" highlight />
      </div>
    </div>
  );
}

function Info({ label, value, highlight }) {
  return (
    <div className="flex justify-between py-4 border-b border-gray-800 last:border-0">
      <span className="text-gray-500 font-medium">{label}</span>
      <span className={highlight ? "text-emerald-500 font-bold" : "text-gray-200"}>{value}</span>
    </div>
  );
}

export default App;