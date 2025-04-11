import React, { useRef, useEffect, useState, useMemo } from "react";
import { Card, CardContent } from "@/components/ui/card";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Download, Maximize2, Minimize2, Search, Activity, Wifi } from "lucide-react";
import { ForceGraph2D } from 'react-force-graph';
import html2canvas from 'html2canvas';
import jsPDF from 'jspdf';
import { LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend } from 'recharts';

const NetworkTopology = () => {
  const fgRef = useRef();
  const containerRef = useRef();
  const [topologyData, setTopologyData] = useState({ nodes: [], links: [] });
  const [packetStats, setPacketStats] = useState({});
  const [selectedNode, setSelectedNode] = useState(null);
  const [hoverNode, setHoverNode] = useState(null);
  const [loading, setLoading] = useState(true);
  const [fullscreen, setFullscreen] = useState(false);
  const [bandwidthHistory, setBandwidthHistory] = useState([]);

  useEffect(() => {
    const fetchData = async () => {
      try {
        const topoRes = await fetch("http://127.0.0.1:5000/network/topology");
        const topoJson = await topoRes.json();

        const statsRes = await fetch("http://127.0.0.1:5000/network/packet_stats");
        const statsJson = await statsRes.json();

        const nodes = Object.values(topoJson).map(device => ({
          id: device.MAC,
          label: device.Vendor || device.MAC,
          ip: device.Current_IP,
          vendor: device.Vendor,
          suspicious: device.Suspicious,
          Previous_IPs: device.Previous_IPs || [],
          First_Seen: device.First_Seen,
          Last_Seen: device.Last_Seen,
          Online: device.Online,
          Time_Since_Last_Seen: device.Time_Since_Last_Seen,
          Packets_Sent: device.Packets_Sent || 0,
          Packets_Received: device.Packets_Received || 0,
          Bytes_Sent: device.Bytes_Sent || 0,
          Bytes_Received: device.Bytes_Received || 0
        }));

        const links = [];
        const macs = Object.keys(topoJson);
        for (let i = 0; i < macs.length; i++) {
          for (let j = i + 1; j < macs.length; j++) {
            const d1 = topoJson[macs[i]];
            const d2 = topoJson[macs[j]];
            if (d1.Current_IP?.startsWith("192.168.") && d2.Current_IP?.startsWith("192.168.")) {
              links.push({ source: d1.MAC, target: d2.MAC });
            }
          }
        }

        setTopologyData({ nodes, links });
        setPacketStats(statsJson || {});

        const timestamp = new Date().toLocaleTimeString();
        const historySnapshot = Object.entries(statsJson).map(([mac, stats]) => ({
          time: timestamp,
          mac,
          packetsSent: stats.Packets_Sent || 0,
          packetsReceived: stats.Packets_Received || 0,
          bytesSent: stats.Bytes_Sent || 0,
          bytesReceived: stats.Bytes_Received || 0,
        }));
        setBandwidthHistory(prev => [...prev.slice(-20), ...historySnapshot]);

      } catch (err) {
        console.error("Error fetching network data", err);
      } finally {
        setLoading(false);
      }
    };

    fetchData();
    const interval = setInterval(fetchData, 10000);
    return () => clearInterval(interval);
  }, []);

  const graphData = useMemo(() => {
    const nodes = (topologyData.nodes || []).map(node => {
      const stats = packetStats[node.id] || {};
      return {
        ...node,
        MAC: node.id,
        Vendor: node.vendor || "Unknown",
        Current_IP: node.ip || "N/A",
        Previous_IPs: node.Previous_IPs || stats.Previous_IPs || [],
        First_Seen: node.First_Seen || stats.First_Seen || "Unknown",
        Last_Seen: node.Last_Seen || stats.Last_Seen || "Unknown",
        Online: node.Online !== undefined ? node.Online : (stats.Online !== undefined ? stats.Online : true),
        Suspicious: node.suspicious || false,
        Time_Since_Last_Seen: node.Time_Since_Last_Seen || stats.Time_Since_Last_Seen || "Unknown",
        Packets_Sent: node.Packets_Sent || stats.Packets_Sent || 0,
        Packets_Received: node.Packets_Received || stats.Packets_Received || 0,
        Bytes_Sent: node.Bytes_Sent || stats.Bytes_Sent || 0,
        Bytes_Received: node.Bytes_Received || stats.Bytes_Received || 0
      };
    });

    const links = (topologyData.links || []).map(link => {
      const src = packetStats[link.source] || {};
      const tgt = packetStats[link.target] || {};
      const totalBytes = (src.Bytes_Sent || 0) + (tgt.Bytes_Received || 0);
      return {
        ...link,
        particleCount: Math.min(20, Math.ceil(totalBytes / 10000)),
        particleSpeed: Math.min(0.02, totalBytes / 500000),
      };
    });

    return { nodes, links };
  }, [topologyData, packetStats]);

  useEffect(() => {
    if (fgRef.current && graphData.nodes.length > 0) {
      setTimeout(() => {
        fgRef.current.zoomToFit(400, 50);
      }, 300);
    }
  }, [graphData]);

  const handleDownloadJSON = () => {
    const blob = new Blob([JSON.stringify(graphData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = "network_topology.json";
    link.click();
    URL.revokeObjectURL(url);
  };

  const handleDownloadPDF = () => {
    const input = document.getElementById("graph-container");
    if (!input) return;
    html2canvas(input, {
      useCORS: true,
      backgroundColor: "#ffffff",
      scrollX: 0,
      scrollY: -window.scrollY
    }).then((canvas) => {
      const imgData = canvas.toDataURL("image/png");
      const pdf = new jsPDF("landscape", "mm", "a4");
      const imgProps = pdf.getImageProperties(imgData);
      const pdfWidth = pdf.internal.pageSize.getWidth();
      const pdfHeight = (imgProps.height * pdfWidth) / imgProps.width;
      pdf.addImage(imgData, "PNG", 0, 0, pdfWidth, pdfHeight);
      pdf.save("network_topology.pdf");
    });
  };

  const handleFocusSelected = () => {
    if (selectedNode && fgRef.current) {
      fgRef.current.centerAt(selectedNode.x, selectedNode.y, 1000);
      fgRef.current.zoom(4, 1000);
    }
  };

  const selectedNodeHistory = bandwidthHistory.filter(entry => entry.mac === (selectedNode?.id || selectedNode?.MAC));

  // Format bytes to a readable format
  const formatBytes = (bytes, decimals = 2) => {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  };

  return (
    <div className="bg-gray-50 p-6 rounded-lg shadow-sm">
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-gray-800 flex items-center">
          <Wifi className="mr-2 text-blue-500" /> Network Topology Monitor
        </h1>
        <p className="text-gray-500">
          Monitoring {graphData.nodes.length} devices and {graphData.links.length} connections
        </p>
      </div>

      <Tabs defaultValue="topology" className="w-full">
        <div className="flex justify-between items-center border-b pb-4 mb-4">
          <TabsList className="bg-gray-100 p-1 rounded-lg">
            <TabsTrigger value="topology" className="rounded-md px-4 py-2 data-[state=active]:bg-white data-[state=active]:shadow-sm">
              Topology View
            </TabsTrigger>
            <div className="w-4" />
            <TabsTrigger value="details" className="rounded-md px-4 py-2 data-[state=active]:bg-white data-[state=active]:shadow-sm">
              Device Details
            </TabsTrigger>
          </TabsList>
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => fgRef.current?.zoomToFit(400, 50)} className="bg-white hover:bg-gray-50">
              Center Graph
            </Button>
            <Button variant="outline" size="sm" onClick={handleFocusSelected} className="bg-white hover:bg-gray-50">
              <Search className="w-4 h-4 mr-2" /> Focus Node
            </Button>
          </div>
        </div>

        <TabsContent value="topology">

          <Card className={`bg-white rounded-lg shadow-md overflow-hidden ${fullscreen ? 'fixed inset-0 z-50 bg-white' : ''}`} ref={containerRef}>
            {loading ? (
              <div className="flex justify-center items-center h-96">
                <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
              </div>
            ) : (
              <CardContent className="p-0">
                <div id="graph-container" className="relative">
                  <div className="absolute top-4 right-4 z-10 flex gap-2">
                    <Button variant="outline" size="sm" onClick={() => setFullscreen(!fullscreen)} className="bg-white hover:bg-gray-50">
                      {fullscreen ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
                    </Button>
                    <Button variant="outline" size="sm" onClick={handleDownloadJSON} className="bg-white hover:bg-gray-50">
                      <Download className="w-4 h-4 mr-2" /> JSON
                    </Button>
                    <Button variant="outline" size="sm" onClick={handleDownloadPDF} className="bg-white hover:bg-gray-50">
                      <Download className="w-4 h-4 mr-2" /> PDF
                    </Button>
                  </div>
                  <ForceGraph2D
                    width={fullscreen ? window.innerWidth : window.innerWidth - 100}
                    height={fullscreen ? window.innerHeight - 100 : 600}
                    ref={fgRef}
                    graphData={graphData}
                    onNodeClick={(node, event) => {
                      event.preventDefault();

                      // Find the full node data with all necessary properties
                      const latestNode = {
                        ...node,
                        MAC: node.id,
                        Vendor: node.vendor || node.Vendor || "Unknown",
                        Current_IP: node.ip || node.Current_IP || "N/A",
                        Previous_IPs: node.Previous_IPs || [],
                        First_Seen: node.First_Seen || "Unknown",
                        Last_Seen: node.Last_Seen || "Unknown",
                        Online: node.Online !== undefined ? node.Online : true,
                        Suspicious: node.suspicious || node.Suspicious || false,
                        Time_Since_Last_Seen: node.Time_Since_Last_Seen || "Unknown",
                        Packets_Sent: node.Packets_Sent || 0,
                        Packets_Received: node.Packets_Received || 0,
                        Bytes_Sent: node.Bytes_Sent || 0,
                        Bytes_Received: node.Bytes_Received || 0
                      };

                      setSelectedNode(latestNode);
                    }}
                    onNodeHover={setHoverNode}
                    linkDirectionalParticles="particleCount"
                    linkDirectionalParticleSpeed={0.005}
                    nodeLabel={node => `${node.label} (${node.Current_IP})\nSent: ${node.Packets_Sent} | Received: ${node.Packets_Received}`}
                    nodeAutoColorBy="vendor"
                    nodeCanvasObject={(node, ctx, globalScale) => {
                      const fontSize = 12 / globalScale;
                      ctx.font = `${fontSize}px Sans-Serif`;
                      ctx.textAlign = 'left';
                      ctx.textBaseline = 'middle';

                      // Node circle
                      ctx.beginPath();
                      ctx.arc(node.x, node.y, 6, 0, 2 * Math.PI, false);

                      // Different colors based on status
                      if (node.Suspicious) {
                        ctx.fillStyle = '#ef4444'; // red for suspicious
                      } else if (node.Online) {
                        ctx.fillStyle = '#22c55e'; // green for online
                      } else {
                        ctx.fillStyle = '#d1d5db'; // gray for offline
                      }
                      ctx.fill();

                      // Selected node outline
                      if (node === selectedNode) {
                        ctx.lineWidth = 3.5;
                        ctx.strokeStyle = '#3b82f6'; // blue outline
                        ctx.stroke();
                      } else if (node === hoverNode) {
                        ctx.lineWidth = 1.5;
                        ctx.strokeStyle = '#6b7280'; // gray outline on hover
                        ctx.stroke();
                      }

                      // Node text
                      ctx.fillStyle = node.Online ? (node.Suspicious ? '#ef4444' : '#1f2937') : '#6b7280';
                      const shortenedLabel = node.label.length > 20 ? node.label.substring(0, 20) + '...' : node.label;
                      ctx.fillText(`${shortenedLabel}`, node.x + 8, node.y - 2);

                      // Traffic stats in smaller text
                      const smallerFontSize = (fontSize * 0.8);
                      ctx.font = `${smallerFontSize}px Sans-Serif`;
                      ctx.fillStyle = '#6b7280';
                      ctx.fillText(`${node.Packets_Received}↓/${node.Packets_Sent}↑`, node.x + 8, node.y + smallerFontSize + 2);
                    }}
                    linkColor={() => '#e5e7eb'} // Light gray links
                    linkWidth={1.5}
                    backgroundColor="#ffffff"
                  />
                </div>
              </CardContent>
            )}
          </Card>
        </TabsContent>

        <TabsContent value="details">
          <div className="grid gap-6 md:grid-cols-3">
            <Card className="bg-white rounded-lg shadow-md md:col-span-1">
              <CardContent className="p-6">
                {selectedNode ? (
                  <>
                    <div className="flex items-center justify-between mb-4">
                      <h2 className="text-xl font-bold text-gray-800">Device Info</h2>
                      <div className={`px-2 py-1 rounded-full text-xs font-medium ${selectedNode.Online ? (selectedNode.suspicious || selectedNode.Suspicious ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800') : 'bg-gray-100 text-gray-800'}`}>
                        {selectedNode.Online ? (selectedNode.suspicious || selectedNode.Suspicious ? 'Suspicious' : 'Online') : 'Offline'}
                      </div>
                    </div>

                    <div className="space-y-3">
                      <div className="grid grid-cols-3 gap-1 text-sm">
                        <span className="text-gray-500 font-medium">MAC:</span>
                        <span className="col-span-2 font-mono">{selectedNode.id || selectedNode.MAC}</span>
                      </div>
                      <div className="grid grid-cols-3 gap-1 text-sm">
                        <span className="text-gray-500 font-medium">Vendor:</span>
                        <span className="col-span-2">{selectedNode.vendor || selectedNode.Vendor}</span>
                      </div>
                      <div className="grid grid-cols-3 gap-1 text-sm">
                        <span className="text-gray-500 font-medium">IP:</span>
                        <span className="col-span-2 font-mono">{selectedNode.ip || selectedNode.Current_IP}</span>
                      </div>
                      <div className="grid grid-cols-3 gap-1 text-sm">
                        <span className="text-gray-500 font-medium">Previous IPs:</span>
                        <span className="col-span-2 font-mono break-all">{(selectedNode.Previous_IPs || []).join(", ") || "None"}</span>
                      </div>
                      <div className="grid grid-cols-3 gap-1 text-sm">
                        <span className="text-gray-500 font-medium">First Seen:</span>
                        <span className="col-span-2">{selectedNode.First_Seen || "Unknown"}</span>
                      </div>
                      <div className="grid grid-cols-3 gap-1 text-sm">
                        <span className="text-gray-500 font-medium">Last Seen:</span>
                        <span className="col-span-2">{selectedNode.Last_Seen || "Unknown"}</span>
                      </div>
                      <div className="grid grid-cols-3 gap-1 text-sm">
                        <span className="text-gray-500 font-medium">Time Since:</span>
                        <span className="col-span-2">{selectedNode.Time_Since_Last_Seen || "Unknown"}</span>
                      </div>
                    </div>

                    <div className="mt-6">
                      <h3 className="text-lg font-semibold text-gray-800 flex items-center">
                        <Activity className="w-4 h-4 mr-2 text-blue-500" /> Traffic Statistics
                      </h3>

                      <div className="mt-4 grid grid-cols-2 gap-4">
                        <div className="bg-gray-50 p-3 rounded-lg">
                          <p className="text-gray-500 text-xs">Packets Sent</p>
                          <p className="text-xl font-bold">{selectedNode.Packets_Sent?.toLocaleString() || 0}</p>
                        </div>
                        <div className="bg-gray-50 p-3 rounded-lg">
                          <p className="text-gray-500 text-xs">Packets Received</p>
                          <p className="text-xl font-bold">{selectedNode.Packets_Received?.toLocaleString() || 0}</p>
                        </div>
                        <div className="bg-gray-50 p-3 rounded-lg">
                          <p className="text-gray-500 text-xs">Bytes Sent</p>
                          <p className="text-xl font-bold">{formatBytes(selectedNode.Bytes_Sent || 0)}</p>
                        </div>
                        <div className="bg-gray-50 p-3 rounded-lg">
                          <p className="text-gray-500 text-xs">Bytes Received</p>
                          <p className="text-xl font-bold">{formatBytes(selectedNode.Bytes_Received || 0)}</p>
                        </div>
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="flex flex-col items-center justify-center py-12 text-center">
                    <Wifi className="h-12 w-12 text-gray-300 mb-4" />
                    <p className="text-gray-500">Select a node from the topology view to see detailed information</p>
                  </div>
                )}
              </CardContent>
            </Card>

            <Card className="bg-white rounded-lg shadow-md md:col-span-2">
              <CardContent className="p-6">
                <h3 className="text-lg font-semibold text-gray-800 mb-4">Bandwidth Trend</h3>

                {selectedNode ? (
                  selectedNodeHistory.length > 0 ? (
                    <div className="h-72">
                      <ResponsiveContainer width="100%" height="100%">
                        <LineChart data={selectedNodeHistory} margin={{ top: 5, right: 30, left: 20, bottom: 5 }}>
                          <CartesianGrid strokeDasharray="3 3" stroke="#f3f4f6" />
                          <XAxis
                            dataKey="time"
                            stroke="#9ca3af"
                            tick={{ fontSize: 12 }}
                          />
                          <YAxis
                            stroke="#9ca3af"
                            tick={{ fontSize: 12 }}
                            tickFormatter={(value) => formatBytes(value, 0)}
                          />
                          <Tooltip
                            contentStyle={{ backgroundColor: 'rgba(255, 255, 255, 0.9)', borderRadius: '6px', border: '1px solid #e5e7eb' }}
                            formatter={(value) => [formatBytes(value), '']}
                          />
                          <Legend />
                          <Line
                            type="monotone"
                            dataKey="bytesSent"
                            name="Bytes Sent"
                            stroke="#6366f1"
                            activeDot={{ r: 6 }}
                            strokeWidth={2}
                          />
                          <Line
                            type="monotone"
                            dataKey="bytesReceived"
                            name="Bytes Received"
                            stroke="#10b981"
                            activeDot={{ r: 6 }}
                            strokeWidth={2}
                          />
                        </LineChart>
                      </ResponsiveContainer>
                    </div>
                  ) : (
                    <div className="flex flex-col items-center justify-center py-12 text-center">
                      <Activity className="h-12 w-12 text-gray-300 mb-4" />
                      <p className="text-gray-500">No bandwidth history available for this node yet.</p>
                      <p className="text-gray-400 text-sm mt-2">Data will appear after a few refresh cycles.</p>
                    </div>
                  )
                ) : (
                  <div className="flex flex-col items-center justify-center py-12 text-center">
                    <Activity className="h-12 w-12 text-gray-300 mb-4" />
                    <p className="text-gray-500">Select a node to view bandwidth trends</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>

      <div className="mt-4 text-xs text-gray-400 text-right">
        Last updated: {new Date().toLocaleString()}
      </div>
    </div>
  );
};

export default NetworkTopology;