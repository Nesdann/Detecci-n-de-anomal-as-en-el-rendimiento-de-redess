import { useState, useEffect } from 'react';


export const AlertsDashboard = () => {
  const [alerts, setAlerts] = useState([]);

  useEffect(() => {
    const fetchAlerts = async () => {
      try {
        const response = await fetch('http://localhost:8000/api/alerts');
        const data = await response.json();
        setAlerts(data);
      } catch (error) {
        
        console.warn("Esperando conexión con el servidor de IA...");
      }
    };

    
    const interval = setInterval(fetchAlerts, 1000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{ padding: '20px', fontFamily: 'sans-serif', backgroundColor: '#111', color: '#fff', minHeight: '100vh' }}>
      <h1>Control Central IDS v1.0</h1>
      <div style={{ overflowX: 'auto' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', marginTop: '20px' }}>
          <thead>
            <tr style={{ borderBottom: '2px solid #444' }}>
              <th>Hora</th>
              <th>IP Origen</th>
              <th>IP Destino</th>
              <th>Tipo de Tráfico</th>
              <th>Confianza IA</th>
            </tr>
          </thead>
          <tbody>
            {alerts.map((alert, index) => (
              <tr key={index} style={{ 
                borderBottom: '1px solid #333', 
                color: alert.tipo !== 'NORMAL' ? '#ff4d4d' : '#4dff88' 
              }}>
                <td style={{ padding: '10px' }}>{alert.timestamp}</td>
                <td>{alert.origen}</td>
                <td>{alert.destino}</td>
                <td style={{ fontWeight: 'bold' }}>{alert.tipo}</td>
                <td>{alert.score}%</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};