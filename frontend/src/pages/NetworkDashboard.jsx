import React, { useState, useEffect } from "react";
import { saveAs } from "file-saver";
import Papa from "papaparse";
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
} from "recharts";
import { fetchNetflowPredictions } from "../api/netflow";
import { toast, ToastContainer } from "react-toastify";
import "react-toastify/dist/ReactToastify.css";

const getColorByPrediction = (prediction) => {
  if (prediction === "Anomaly") return "text-red-500 font-semibold";
  if (prediction.includes("Ping Sweep")) return "text-yellow-500 font-semibold";
  return "text-green-600";
};

export default function NetworkDashboard() {
  const [activeTab, setActiveTab] = useState("netflow");
  const [historicNetflow, setHistoricNetflow] = useState([]);
  const [historicPayload, setHistoricPayload] = useState([]);
  const [netflowData, setNetflowData] = useState({});
  const [protocolFilter, setProtocolFilter] = useState("");
  const [srcFilter, setSrcFilter] = useState("");
  const [dstFilter, setDstFilter] = useState("");
  const [allColumns, setAllColumns] = useState([]);
  const [trendData, setTrendData] = useState([]);
  const [payloadData, setPayloadData] = useState([]);

  const displayColumns = [
    "Flow ID",
    "Flow Duration",
    "Total Fwd Packet",
    "Total Bwd packets",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Packet Length Mean",
    "Down/Up Ratio",
    "Active Mean",
    "Idle Mean",
    "Prediction",
  ];

  const displayColumnsHistoric = [
    "flow_id",
    "flow_duration",
    "total_fwd_packet",
    "total_bwd_packets",
    "flow_bytes_per_s",
    "flow_packets_per_s",
    "packet_length_mean",
    "down_up_ratio",
    "active_mean",
    "idle_mean",
    "prediction",
  ];

  const [prevFlowIDs, setPrevFlowIDs] = useState(new Set());
  const [newFlows, setNewFlows] = useState(new Set());

  const [payloadTrendData, setPayloadTrendData] = useState([]);
  const [prevPayloadIDs, setPrevPayloadIDs] = useState(new Set());
  const [newPayloads, setNewPayloads] = useState(new Set());


  useEffect(() => {
    const interval = setInterval(async () => {
      const data = await fetchNetflowPredictions();
      if (data) {
        const anomalies = Object.values(data).filter(
          (flow) => flow.Prediction === "Anomaly"
        );
        const potential = Object.values(data).filter(
          (flow) => flow.Prediction === "Ping Sweep (Potential Anomaly)"
        );

        if (anomalies.length > 0) {
          toast.error(`⚠️ ${anomalies.length} anomaly flow(s) detected!`, {
            position: "top-right",
            autoClose: 5000,
          });
        }

        if (potential.length > 0) {
          toast.error(`⚠️ ${potential.length} potential anomaly flow(s) detected!`, {
            position: "top-right",
            autoClose: 5000,
          });
        }

        const currentIDs = new Set(Object.keys(data));
        const newSet = new Set(
          [...currentIDs].filter((id) => !prevFlowIDs.has(id))
        );
        setPrevFlowIDs(currentIDs);
        setNewFlows(newSet);

        // Collect all columns available
        const allKeys = new Set();
        Object.values(data).forEach((flow) => {
          Object.keys(flow).forEach((k) => allKeys.add(k));
        });
        setAllColumns([...allKeys]);

        setNetflowData(data);

        // Update trendData
        const count = { Benign: 0, Anomaly: 0 };
        Object.values(data).forEach((flow) => {
          count[flow.Prediction] = (count[flow.Prediction] || 0) + 1;
        });

        const newPoint = {
          time: new Date().toLocaleTimeString(),
          ...count,
        };

        setTrendData((prev) => [...prev.slice(-19), newPoint]);
      }
    }, 3000);

    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const fetchPayload = async () => {
      try {
        const res = await fetch("http://127.0.0.1:5000/predict/payload");
        const rawData = await res.json();

        // Convert dictionary to array
        const data = Object.values(rawData);

        const currentIDs = new Set(data.map((d) => d["Flow ID"]));
        const newSet = new Set([...currentIDs].filter((id) => !prevPayloadIDs.has(id)));

        setPrevPayloadIDs(currentIDs);
        setNewPayloads(newSet);

        const anomalyCount = data.filter((d) => d.Prediction === "Anomaly").length;
        const benignCount = data.filter((d) => d.Prediction === "Benign").length;
        const newPoint = {
          time: new Date().toLocaleTimeString(),
          Benign: benignCount,
          Anomaly: anomalyCount,
        };
        setPayloadTrendData((prev) => [...prev.slice(-19), newPoint]);

        setPayloadData(data);
      } catch (error) {
        console.error("Failed to fetch payload data", error);
      }
    };

    const interval = setInterval(fetchPayload, 3000);
    return () => clearInterval(interval);
  }, []);

  useEffect(() => {
    const fetchHistoricData = async () => {
      try {
        const [res1, res2] = await Promise.all([
          fetch("http://127.0.0.1:5000/predict/netflow/all"),
          fetch("http://127.0.0.1:5000/predict/payload/all"),
        ]);
        const netflow = await res1.json();
        const payload = await res2.json();
        setHistoricNetflow(netflow);
        setHistoricPayload(payload);
      } catch (err) {
        console.error("Error fetching historic data", err);
      }
    };
    fetchHistoricData();
  }, []);


  const exportCSV = () => {
    const rows = Object.values(netflowData).map((flow) => {
      const row = {};
      allColumns.forEach((col) => {
        row[col] = flow[col] ?? "";
      });
      return row;
    });

    const csv = Papa.unparse(rows);
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    saveAs(blob, "netflow_data.csv");
  };

  const exportPayloadCSV = () => {
    const csv = Papa.unparse(payloadData);
    const blob = new Blob([csv], { type: "text/csv;charset=utf-8" });
    saveAs(blob, "payload_data.csv");
  };


  const filteredData = Object.values(netflowData).filter((flow) => {
    const flowId = flow["Flow ID"] || "";
    let parts = flowId.split("-")

    return (
      (protocolFilter === "" || parts[4].includes(protocolFilter.toLowerCase())) &&
      (srcFilter === "" || parts[0].includes(srcFilter)) &&
      (dstFilter === "" || parts[1].includes(dstFilter))
    );
  });

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-3xl font-bold mb-4">Network Monitoring Dashboard</h1>

      <div className="flex flex-wrap gap-2">
        <button
          onClick={() => setActiveTab("netflow")}
          className={`px-4 py-2 rounded-lg border ${activeTab === "netflow" ? "bg-blue-500 text-white" : "bg-white text-black"
            }`}
        >
          NETFLOW
        </button>

        <button
          onClick={() => setActiveTab("payload")}
          className={`px-4 py-2 rounded-lg border ${activeTab === "payload" ? "bg-blue-500 text-white" : "bg-white text-black"}`}
        >
          PAYLOAD
        </button>

        <button
          onClick={() => setActiveTab("historic")}
          className={`px-4 py-2 rounded-lg border ${activeTab === "historic" ? "bg-blue-500 text-white" : "bg-white text-black"}`}
        >
          HISTORIC
        </button>

      </div>

      {activeTab === "netflow" && (
        <div className="bg-white rounded-xl p-4 shadow overflow-auto">
          <h2 className="text-xl font-semibold mb-4">Live Netflow Stats</h2>

          <div className="flex gap-4 mb-4 flex-wrap">
            <input
              className="border p-2 rounded"
              placeholder="Filter by protocol"
              value={protocolFilter}
              onChange={(e) => setProtocolFilter(e.target.value)}
            />
            <input
              className="border p-2 rounded"
              placeholder="Filter by source IP"
              value={srcFilter}
              onChange={(e) => setSrcFilter(e.target.value)}
            />
            <input
              className="border p-2 rounded"
              placeholder="Filter by destination IP"
              value={dstFilter}
              onChange={(e) => setDstFilter(e.target.value)}
            />
            <button
              className="bg-green-600 text-white px-4 rounded hover:bg-green-700 transition"
              onClick={exportCSV}
            >
              Export CSV
            </button>
          </div>

          <div className="bg-white p-4 mt-6 rounded shadow">
            <h3 className="text-lg font-semibold mb-2">Prediction Trend (Last 20 Polls)</h3>
            <LineChart width={800} height={300} data={trendData}>
              <CartesianGrid stroke="#ccc" />
              <XAxis dataKey="time" />
              <YAxis />
              <Tooltip />
              <Line type="monotone" dataKey="Benign" stroke="#4ade80" />
              <Line type="monotone" dataKey="Anomaly" stroke="#f87171" />
              <Line type="monotone" dataKey="Ping Sweep (Potential Anomaly)" stroke="#ffd500" />
            </LineChart>
          </div>

          <div className="overflow-auto max-w-full">
            {/* Table */}
            <table className="table-auto w-full border">
              <thead className="bg-gray-100">
                <tr>
                  {displayColumns.map((key) => (
                    <th key={key} className="p-2 border text-sm whitespace-nowrap">
                      {key}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredData.map((flow, i) => (
                  <tr
                    key={i}
                    className={`transition-all duration-300 ${newFlows.has(flow["Flow ID"]) ? "bg-yellow-100 animate-pulse" : ""
                      }`}
                  >
                    {displayColumns.map((key) => (
                      <td
                        key={key}
                        className={`p-2 border text-sm whitespace-nowrap ${key === "Prediction" ? getColorByPrediction(flow[key]) : ""
                          }`}
                      >
                        {typeof flow[key] === "number"
                          ? flow[key].toFixed(2)
                          : flow[key]}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {activeTab === "payload" && (
        <div className="bg-white rounded-xl p-4 shadow overflow-auto">
          <div className="flex justify-between items-center mb-4">
            <h2 className="text-xl font-semibold">Live Payload Stats</h2>
            <button
              className="bg-green-600 text-white px-4 py-1 rounded hover:bg-green-700 transition"
              onClick={exportPayloadCSV}
            >
              Export CSV
            </button>
          </div>

          <div className="bg-white p-4 mb-6 rounded shadow">
            <h3 className="text-lg font-semibold mb-2">Payload Anomaly Trend (Last 20 Polls)</h3>
            <LineChart width={800} height={300} data={payloadTrendData}>
              <CartesianGrid stroke="#ccc" />
              <XAxis dataKey="time" />
              <YAxis allowDecimals={false} />
              <Tooltip />
              <Line type="monotone" dataKey="Benign" stroke="#4ade80" />
              <Line type="monotone" dataKey="Anomaly" stroke="#f87171" />
            </LineChart>
          </div>

          {payloadData.length === 0 ? (
            <div className="text-gray-500 text-center py-4">Loading payload data...</div>
          ) : (
            <table className="table-auto w-full border">
              <thead className="bg-gray-100">
                <tr>
                  {["Flow ID", "Stime", "Timestamp", "Prediction"].map((key) => (
                    <th key={key} className="p-2 border text-sm whitespace-nowrap">
                      {key}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {payloadData.map((item, i) => (
                  <tr
                    key={i}
                    className={`transition-all duration-300 ${newPayloads.has(item["Flow ID"]) ? "bg-blue-100 animate-pulse" : ""
                      }`}
                  >
                    <td className="p-2 border text-sm whitespace-nowrap">{item["Flow ID"]}</td>
                    <td className="p-2 border text-sm whitespace-nowrap">{item["Stime"]}</td>
                    <td className="p-2 border text-sm whitespace-nowrap">{item["Timestamp"]}</td>
                    <td className={`p-2 border text-sm whitespace-nowrap ${getColorByPrediction(item["Prediction"])}`}>
                      {item["Prediction"]}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {activeTab === "historic" && (
        <div className="bg-white rounded-xl p-4 shadow overflow-auto space-y-6">
          <h2 className="text-xl font-semibold">Historic Anomalies</h2>

          <div>
            <h3 className="text-lg font-semibold mb-2">Netflow Anomalies</h3>
            <table className="table-auto w-full border">
              <thead className="bg-gray-100">
                <tr>
                  {displayColumnsHistoric.map((key) => (
                    <th key={key} className="p-2 border text-sm whitespace-nowrap">
                      {key}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {historicNetflow.map((flow, i) => (
                  <tr
                    key={flow["id"]}
                    className={newFlows.has(flow["id"]) ? "bg-yellow-100 animate-pulse" : ""}
                  >
                    {displayColumnsHistoric.map((key) => (
                      <td
                        key={key}
                        className={`p-2 border text-sm whitespace-nowrap ${key === "Prediction" ? getColorByPrediction(flow[key]) : ""
                          }`}
                      >
                        {flow[key] ?? ""}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>

            </table>
          </div>

          <div>
            <h3 className="text-lg font-semibold mb-2">Payload Anomalies</h3>
            <table className="table-auto w-full border">
              <thead className="bg-gray-100">
                <tr>
                  {["Flow ID", "Stime", "Prediction", "Timestamp"].map((key) => (
                    <th key={key} className="p-2 border text-sm whitespace-nowrap">
                      {key}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {historicPayload.map((item, i) => (
                  <tr key={i}>
                    <td className="p-2 border text-sm">{item["flow_id"]}</td>
                    <td className="p-2 border text-sm">{item["stime"]}</td>
                    <td className={`p-2 border text-sm ${getColorByPrediction(item["prediction"])}`}>{item["prediction"]}</td>
                    <td className="p-2 border text-sm">{item["timestamp"]}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

    </div>
  );
}
