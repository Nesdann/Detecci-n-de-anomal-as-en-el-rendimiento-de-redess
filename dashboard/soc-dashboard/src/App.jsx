
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
    `px-4 py-3 rounded-xl mb-2 transition ${
      page === name
        ? "bg-gray-800 text-white"
        : "text-gray-400 hover:bg-gray-800 hover:text-white"
    }`;

  return (
    <div className="w-72 bg-gray-900 p-8 flex flex-col border-r border-gray-800">
      <h1 className="text-2xl font-semibold mb-12 tracking-wide">
        Sentinel
      </h1>

      <button onClick={() => setPage("overview")} className={itemClass("overview")}>
        Overview
      </button>

      <button onClick={() => setPage("config")} className={itemClass("config")}>
        Configuration
      </button>

      <button onClick={() => setPage("about")} className={itemClass("about")}>
        Engine Info
      </button>
      <button onClick={() => setPage("about_me")} className="block mb-2">
      About me
     </button>

      <button onClick={() => setPage("actions")} className="block mb-2">
       Actions
      </button>


      <div className="mt-auto text-xs text-gray-600">
        v0.1 Engine
      </div>
    </div>
  );
}



function Overview() {
  const [data, setData] = useState([
    { time: 1, score: 0.2 },
    { time: 2, score: 0.3 },
    { time: 3, score: 0.4 },
  ]);

  const [alerts, setAlerts] = useState([]);

  const threshold = 0.8;

  useEffect(() => {
    const interval = setInterval(() => {
      setData((prev) => {
        const newScore = Math.random().toFixed(2);
        const next = [
          ...prev.slice(-19),
          { time: prev.length + 1, score: Number(newScore) },
        ];

        if (newScore > threshold) {
          setAlerts((a) => [
            {
              id: Date.now(),
              host: "10.0.0." + Math.floor(Math.random() * 10),
              score: newScore,
            },
            ...a,
          ]);
        }

        return next;
      });
    }, 2000);

    return () => clearInterval(interval);
  }, []);

  return (
    <div>
      <h2 className="text-3xl font-semibold mb-10 tracking-tight">
        Network Overview
      </h2>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-6 mb-10">
        <StatCard title="Flows/sec" value="24" />
        <StatCard title="Active Hosts" value="12" />
        <StatCard title="Active Alerts" value={alerts.length} highlight />
        <StatCard title="Threshold" value={threshold} />
      </div>

      {/* Graph */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-8 mb-10">
        <h3 className="text-lg mb-6 text-gray-400">Anomaly Score</h3>

        <div className="h-64">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data}>
              <XAxis dataKey="time" stroke="#555" />
              <YAxis domain={[0, 1]} stroke="#555" />
              <Tooltip />
              <Line
                type="monotone"
                dataKey="score"
                stroke="#3b82f6"
                strokeWidth={2}
                dot={false}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Alerts Table */}
      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-8">
        <h3 className="text-lg mb-6 text-gray-400">Recent Alerts</h3>

        <table className="w-full text-sm">
          <thead>
            <tr className="text-gray-500 border-b border-gray-800">
              <th className="text-left pb-3">Host</th>
              <th className="text-left pb-3">Score</th>
              <th className="text-left pb-3">Severity</th>
            </tr>
          </thead>
          <tbody>
            {alerts.slice(0, 5).map((alert) => (
              <tr key={alert.id} className="border-b border-gray-800">
                <td className="py-3">{alert.host}</td>
                <td className="py-3">{alert.score}</td>
                <td className="py-3 text-red-500">High</td>
              </tr>
            ))}
          </tbody>
        </table>

        {alerts.length === 0 && (
          <p className="text-gray-600 mt-4">No alerts triggered</p>
        )}
      </div>
    </div>
  );
}
function About_me() {
  return (
    <div>
      <h2 className="text-3xl font-semibold mb-10 tracking-tight">
        About the Developer
      </h2>

      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-10 max-w-4xl">
        <h3 className="text-xl font-medium text-blue-400 mb-6">
          Nesdan — Computer Science Student
        </h3>

        <p className="text-gray-300 mb-4 leading-relaxed">
          I am currently a third-year Computer Science student at FaMAF
          (Faculty of Mathematics, Astronomy, Physics and Computing).
        </p>

        <p className="text-gray-400 mb-4 leading-relaxed">
          This dashboard is part of a personal cybersecurity project focused
          on anomaly detection and network monitoring systems. The objective
          is to simulate a Security Operations Center (SOC) environment
          capable of identifying suspicious activity in real time.
        </p>

        <p className="text-gray-400 leading-relaxed">
          The long-term goal is to integrate real traffic analysis,
          statistical modeling, and machine learning techniques into this
          platform.
        </p>
      </div>
    </div>
  );
}

function Actions() {
  const [bans, setBans] = useState([
    { id: 1, ip: "192.168.0.12", reason: "High anomaly score" },
  ]);

  function removeBan(id) {
    setBans(bans.filter((ban) => ban.id !== id));
  }

  function addBan() {
    const newIP = "10.0.0." + Math.floor(Math.random() * 100);
    setBans([
      {
        id: Date.now(),
        ip: newIP,
        reason: "Manual block",
      },
      ...bans,
    ]);
  }

  return (
    <div>
      <h2 className="text-3xl font-semibold mb-8 tracking-tight">
        Security Actions
      </h2>

      <div className="mb-6">
        <button
          onClick={addBan}
          className="bg-red-600 hover:bg-red-700 px-4 py-2 rounded-xl"
        >
          Add Manual Ban
        </button>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-8">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-gray-500 border-b border-gray-800">
              <th className="text-left pb-3">IP Address</th>
              <th className="text-left pb-3">Reason</th>
              <th className="text-left pb-3">Actions</th>
            </tr>
          </thead>
          <tbody>
            {bans.map((ban) => (
              <tr key={ban.id} className="border-b border-gray-800">
                <td className="py-3">{ban.ip}</td>
                <td className="py-3">{ban.reason}</td>
                <td className="py-3 space-x-4">
                  <button
                    onClick={() => removeBan(ban.id)}
                    className="text-green-400 hover:text-green-300"
                  >
                    Remove Ban
                  </button>

                  <button className="text-blue-400 hover:text-blue-300">
                    View Info
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>

        {bans.length === 0 && (
          <p className="text-gray-600 mt-4">No active bans</p>
        )}
      </div>
    </div>
  );
}


function StatCard({ title, value, highlight }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-2xl p-6 hover:border-gray-700 transition">
      <p className="text-sm text-gray-500 mb-3">{title}</p>
      <p
        className={`text-3xl font-semibold ${
          highlight ? "text-red-500" : "text-white"
        }`}
      >
        {value}
      </p>
    </div>
  );
}

function Configuration() {
  return (
    <div>
      <h2 className="text-3xl font-semibold mb-10">
        Configuration
      </h2>

      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-8 space-y-6">
        <div>
          <label className="text-sm text-gray-400">Threshold</label>
          <input
            type="range"
            min="0"
            max="1"
            step="0.01"
            className="w-full mt-2"
          />
        </div>

        <div>
          <label className="text-sm text-gray-400">Window Size</label>
          <select className="w-full mt-2 bg-gray-800 p-3 rounded-xl border border-gray-700">
            <option>60s</option>
            <option>120s</option>
            <option>300s</option>
          </select>
        </div>

        <button className="bg-blue-600 hover:bg-blue-500 transition px-6 py-3 rounded-xl">
          Save Configuration
        </button>
      </div>
    </div>
  );
}

function About() {
  return (
    <div>
      <h2 className="text-3xl font-semibold mb-10">
        Engine Information
      </h2>

      <div className="bg-gray-900 border border-gray-800 rounded-2xl p-8 space-y-4">
        <Info label="Model" value="IsolationForest_v1" />
        <Info label="Baseline Mode" value="Adaptive (7 days)" />
        <Info label="Window" value="60 seconds" />
        <Info label="Threshold" value="0.8" />
        <Info label="Engine Status" value="Running" highlight />
      </div>
    </div>
  );
}

function Info({ label, value, highlight }) {
  return (
    <div className="flex justify-between border-b border-gray-800 pb-3">
      <span className="text-gray-500">{label}</span>
      <span className={highlight ? "text-green-500" : "text-white"}>
        {value}
      </span>
    </div>
  );
}

export default App;
