import 'aframe';
import 'aframe-extras';
import React, { useEffect, useState, useCallback, useMemo } from 'react';
import { ForceGraph2D } from 'react-force-graph';
import axios from 'axios';
import { io } from 'socket.io-client';

// Constants
const API_BASE_URL = 'http://127.0.0.1:5000';
const SOCKET_URL = API_BASE_URL;

// Device type icons mapping
const deviceIcons = {
  Router: '🛜',
  Switch: '🔌',
  Server: '🖥️',
  Smartphone: '📱',
  Laptop: '💻',
  Desktop: '🖥️',
  Tablet: '📟',
  IoT: '🔄',
  Unknown: '🟦'
};

// Status colors
const statusColors = {
  active: '#4CAF50',   // Green for online
  inactive: '#F44336', // Red for offline
  warning: '#FFC107',  // Yellow for warning
  unknown: '#9E9E9E'   // Grey for unknown state
};

// Bandwidth thresholds (in Mbps)
const BANDWIDTH_THRESHOLDS = {
  low: 5,
  medium: 50,
  high: 100
};

const NetworkTopology = () => {
  // State management
  const [data, setData] = useState({ nodes: [], links: [] });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [bandwidthData, setBandwidthData] = useState({});
  const [searchTerm, setSearchTerm] = useState('');
  const [socketConnected, setSocketConnected] = useState(false);
  const [viewMode, setViewMode] = useState('2d'); // '2d' or '3d'
  const [showLabels, setShowLabels] = useState(true);
  const [lastUpdated, setLastUpdated] = useState(null);
  const [packetData, setPacketData] = useState({});

  // Socket connection
  const socket = useMemo(() => io(SOCKET_URL, {
    reconnectionAttempts: 5,
    reconnectionDelay: 1000
  }), []);

  // Filter data based on search term
  const filteredData = useMemo(() => {
    if (!searchTerm.trim()) return data;
    
    const filteredNodes = data.nodes.filter(node => 
      node.id.toLowerCase().includes(searchTerm.toLowerCase()) || 
      node.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      (node.deviceType && node.deviceType.toLowerCase().includes(searchTerm.toLowerCase()))
    );
    
    const nodeIds = new Set(filteredNodes.map(node => node.id));
    
    const filteredLinks = data.links.filter(link => 
      nodeIds.has(typeof link.source === 'object' ? link.source.id : link.source) && 
      nodeIds.has(typeof link.target === 'object' ? link.target.id : link.target)
    );
    
    return { nodes: filteredNodes, links: filteredLinks };
  }, [data, searchTerm]);

  // Format topology data
  const formatTopologyData = useCallback((topologyData, bandwidthInfo = {}, packetInfo = {}) => {
    const nodes = topologyData.map(device => {
      const deviceType = device.name || 'Unknown';
      const deviceId = device.id;
      const bandwidth = bandwidthInfo[deviceId] || { bytes_sent: 0, bytes_received: 0 };
      const packets = packetInfo[deviceId] || { sent: 0, received: 0 };
      
      return {
        id: deviceId,
        name: `${deviceIcons[deviceType] || deviceIcons.Unknown} ${deviceType}`,
        fullName: deviceType,
        deviceType: deviceType,
        status: device.status || 'unknown',
        ip: deviceId,
        mac: device.mac || 'Unknown',
        bandwidth: {
          sent: bandwidth.bytes_sent || 0,
          received: bandwidth.bytes_received || 0,
          total: (bandwidth.bytes_sent || 0) + (bandwidth.bytes_received || 0)
        },
        packets: {
          sent: packets.sent || 0,
          received: packets.received || 0,
          total: (packets.sent || 0) + (packets.received || 0)
        },
        group: deviceType === "Router" ? 1 : 
               deviceType === "Switch" ? 2 : 3,
        lastSeen: new Date().toISOString()
      };
    });
  
    const links = topologyData.flatMap(device => 
      device.connections.map(connection => {
        const sourceBw = bandwidthInfo[device.id] || { bytes_sent: 0 };
        const targetBw = bandwidthInfo[connection] || { bytes_received: 0 };
        const averageBw = Math.max(sourceBw.bytes_sent, targetBw.bytes_received) || 0;
        
        // Packet rate between devices
        const sourcePackets = packetInfo[device.id]?.sent || 0;
        const targetPackets = packetInfo[connection]?.received || 0;
        const packetRate = Math.max(sourcePackets, targetPackets);
        
        return {
          source: device.id,
          target: connection,
          bandwidth: averageBw,
          packetRate: packetRate,
          value: Math.log(averageBw + 1) * 2 // For link thickness
        };
      })
    );
  
    return { nodes, links };
  }, []);

  // Handle node click
  const handleNodeClick = useCallback((node) => {
    setSelectedNode(prev => prev && prev.id === node.id ? null : node);
  }, []);

  // Close details panel
  const closeDetailsPanel = useCallback(() => {
    setSelectedNode(null);
  }, []);

  // Render node in canvas
  const handleNodeCanvas = useCallback((node, ctx, globalScale) => {
    const statusColor = statusColors[node.status] || statusColors.unknown;
    const isOffline = node.status === 'inactive';
    
    // Pulsating effect for offline nodes
    const pulseSize = isOffline 
      ? Math.sin(Date.now() * 0.005) * 3 + 10 
      : 0;
    
    const size = 8 + pulseSize; 
    
    // Activity indication based on bandwidth/packet data
    const activitySize = Math.min(
      4, 
      Math.log(node.bandwidth.total / 1024 + 1)
    );
    
    // Draw main node circle
    ctx.beginPath();
    ctx.arc(node.x, node.y, size + activitySize, 0, 2 * Math.PI);
    ctx.fillStyle = statusColor;
    ctx.fill();
    
    // Draw border
    ctx.strokeStyle = '#FFFFFF';
    ctx.lineWidth = 0.5;
    ctx.stroke();
    
    // Draw inner circle for bandwidth activity
    if (node.bandwidth.total > 0) {
      ctx.beginPath();
      ctx.arc(node.x, node.y, size - 2, 0, 2 * Math.PI);
      ctx.fillStyle = node.bandwidth.total > BANDWIDTH_THRESHOLDS.high * 1024 
        ? '#FF5722' 
        : node.bandwidth.total > BANDWIDTH_THRESHOLDS.medium * 1024 
          ? '#2196F3' 
          : '#FFFFFF';
      ctx.fill();
    }
    
    // Draw label if enabled
    if (showLabels) {
      const label = node.name;
      const fontSize = 12 / globalScale;
      ctx.font = `${fontSize}px Sans-Serif`;
      ctx.textAlign = 'center';
      ctx.fillStyle = '#FFFFFF';
      ctx.fillText(label, node.x, node.y - size - 4);
    }
  }, [showLabels]);

  // Link particle customization
  const handleLinkParticleWidth = useCallback((link) => {
    const bandwidth = typeof link.bandwidth === 'number' ? link.bandwidth : 0;
    const normalizedBw = Math.log(bandwidth + 1) / 10;
    return Math.max(0.5, Math.min(4, normalizedBw));
  }, []);

  const handleLinkParticleSpeed = useCallback((link) => {
    const bandwidth = typeof link.bandwidth === 'number' ? link.bandwidth : 0;
    // Higher bandwidth = faster particles
    return bandwidth > 0 ? Math.min(0.05, bandwidth / 100000) : 0.01;
  }, []);

  const getLinkColor = useCallback((link) => {
    const bandwidth = typeof link.bandwidth === 'number' ? link.bandwidth : 0;
    const bwInMbps = bandwidth / (1024 * 1024);
    
    if (bwInMbps > BANDWIDTH_THRESHOLDS.high) return '#FF5722'; // High
    if (bwInMbps > BANDWIDTH_THRESHOLDS.medium) return '#2196F3'; // Medium
    if (bwInMbps > BANDWIDTH_THRESHOLDS.low) return '#4CAF50'; // Low
    return '#9E9E9E'; // Minimal
  }, []);

  // Fetch initial topology data
  useEffect(() => {
    const fetchTopology = async () => {
      try {
        const response = await axios.get(`${API_BASE_URL}/network/topology`);
        if (response.data && response.data.network_topology) {
          const formattedData = formatTopologyData(
            response.data.network_topology, 
            bandwidthData,
            packetData
          );
          setData(formattedData);
          setLastUpdated(new Date());
        } else {
          throw new Error('Invalid data format');
        }
        setLoading(false);
      } catch (error) {
        console.error('Error fetching topology data:', error);
        setError('Failed to load network topology. Please try again later.');
        setLoading(false);
      }
    };

    fetchTopology();
  }, [formatTopologyData, bandwidthData, packetData]);

  // Setup socket listeners
  useEffect(() => {
    // Connection status
    socket.on('connect', () => {
      setSocketConnected(true);
      console.log('Socket connected');
    });

    socket.on('disconnect', () => {
      setSocketConnected(false);
      console.log('Socket disconnected');
    });

    // Topology updates
    socket.on('network_topology_update', (newTopology) => {
      if (newTopology && newTopology.network_topology) {
        setData(formatTopologyData(
          newTopology.network_topology, 
          bandwidthData,
          packetData
        ));
        setLastUpdated(new Date());
      }
    });

    // Bandwidth updates
    socket.on('network_bandwidth', (newBandwidthData) => {
      setBandwidthData(prev => {
        const updated = { ...prev, ...newBandwidthData };
        
        // Update the graph with new bandwidth data
        setData(prevData => {
          if (prevData.nodes.length === 0) return prevData;
          
          const updatedNodes = prevData.nodes.map(node => {
            const nodeId = node.id;
            const bwData = updated[nodeId] || { bytes_sent: 0, bytes_received: 0 };
            
            return {
              ...node,
              bandwidth: {
                sent: bwData.bytes_sent || 0,
                received: bwData.bytes_received || 0,
                total: (bwData.bytes_sent || 0) + (bwData.bytes_received || 0)
              }
            };
          });
          
          const updatedLinks = prevData.links.map(link => {
            const sourceBw = updated[link.source.id || link.source] || { bytes_sent: 0 };
            const targetBw = updated[link.target.id || link.target] || { bytes_received: 0 };
            const averageBw = Math.max(sourceBw.bytes_sent, targetBw.bytes_received) || 0;
            
            return {
              ...link,
              bandwidth: averageBw,
              value: Math.log(averageBw + 1) * 2
            };
          });
          
          return { nodes: updatedNodes, links: updatedLinks };
        });
        
        return updated;
      });
    });

    // Packet data updates
    socket.on('network_packets', (newPacketData) => {
      setPacketData(prev => {
        const updated = { ...prev, ...newPacketData };
        
        // Update existing data with packet information
        setData(prevData => {
          if (prevData.nodes.length === 0) return prevData;
          
          const updatedNodes = prevData.nodes.map(node => {
            const nodeId = node.id;
            const packets = updated[nodeId] || { sent: 0, received: 0 };
            
            return {
              ...node,
              packets: {
                sent: packets.sent || 0,
                received: packets.received || 0,
                total: (packets.sent || 0) + (packets.received || 0)
              }
            };
          });
          
          const updatedLinks = prevData.links.map(link => {
            const sourcePackets = updated[link.source.id || link.source]?.sent || 0;
            const targetPackets = updated[link.target.id || link.target]?.received || 0;
            const packetRate = Math.max(sourcePackets, targetPackets);
            
            return {
              ...link,
              packetRate: packetRate
            };
          });
          
          return { nodes: updatedNodes, links: updatedLinks };
        });
        
        return updated;
      });
    });

    // Device status updates
    socket.on('device_status_update', (statusData) => {
      setData(prevData => {
        const updatedNodes = prevData.nodes.map(node => {
          if (statusData[node.id]) {
            return {
              ...node,
              status: statusData[node.id],
              lastSeen: new Date().toISOString()
            };
          }
          return node;
        });
        
        return { ...prevData, nodes: updatedNodes };
      });
    });

    return () => {
      socket.off('connect');
      socket.off('disconnect');
      socket.off('network_topology_update');
      socket.off('network_bandwidth');
      socket.off('network_packets');
      socket.off('device_status_update');
      socket.disconnect();
    };
  }, [socket, formatTopologyData, bandwidthData, packetData]);

  // Loading and error states
  if (loading) {
    return (
      <div className="loading-container">
        <div className="spinner"></div>
        <p>Loading Network Topology...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="error-container">
        <p className="error-message">{error}</p>
        <button onClick={() => window.location.reload()}>Retry</button>
      </div>
    );
  }

  // Format bytes to human-readable form
  const formatBytes = (bytes, decimals = 2) => {
    if (bytes === 0) return '0 Bytes';
    
    const k = 1024;
    const dm = decimals < 0 ? 0 : decimals;
    const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
    
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    
    return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
  };

  return (
    <div className="network-topology-container">
      <div className='options' style={{
        display: "flex",
        flexDirection : 'row',
        justifyContent : "space-between"
      }}>
        {/* Control Panel */}
        <div className="control-panel">
          <div className="search-container">
            <input
              type="text"
              placeholder="Search devices by IP, name, or type..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="search-input"
            />
            {searchTerm && (
              <button
                className="clear-search"
                onClick={() => setSearchTerm('')}
              >
                ✖
              </button>
            )}
          </div>
          
          <div className="view-toggles">
            <label>
              <input
                type="checkbox"
                checked={showLabels}
                onChange={() => setShowLabels(!showLabels)}
              />
              Show Labels
            </label>
            
            <div className="connection-status">
              Status: 
              <span className={socketConnected ? 'connected' : 'disconnected'}>
                {socketConnected ? 'Connected' : 'Disconnected'}
              </span>
            </div>
            
            {lastUpdated && (
              <div className="last-updated">
                Last updated: {lastUpdated.toLocaleTimeString()}
              </div>
            )}
          </div>
          
          {/* Network Stats */}
          <div className="network-stats">
            <div className="stat-item">
              <span className="stat-label">Devices:</span>
              <span className="stat-value">{data.nodes.length}</span>
            </div>
            <div className="stat-item">
              <span className="stat-label">Connections:</span>
              <span className="stat-value">{data.links.length}</span>
            </div>
            <div className="stat-item">
              <span className="stat-label">Active:</span>
              <span className="stat-value">
                {data.nodes.filter(node => node.status === 'active').length}
              </span>
            </div>
            <div className="stat-item">
              <span className="stat-label">Inactive:</span>
              <span className="stat-value">
                {data.nodes.filter(node => node.status === 'inactive').length}
              </span>
            </div>
          </div>
        </div>
        
        {/* Bandwidth Legend */}
        <div className="bandwidth-legend">
          <h4>Bandwidth Legend</h4>
          <div className="legend-items">
            <div className="legend-item">
              <span className="color-indicator" style={{ backgroundColor: '#4CAF50' }}></span>
              <span>Low Bandwidth (&lt;{BANDWIDTH_THRESHOLDS.low} Mbps)</span>
            </div>
            <div className="legend-item">
              <span className="color-indicator" style={{ backgroundColor: '#2196F3' }}></span>
              <span>Medium Bandwidth ({BANDWIDTH_THRESHOLDS.low}-{BANDWIDTH_THRESHOLDS.high} Mbps)</span>
            </div>
            <div className="legend-item">
              <span className="color-indicator" style={{ backgroundColor: '#FF5722' }}></span>
              <span>High Bandwidth (&gt;{BANDWIDTH_THRESHOLDS.high} Mbps)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Main Graph Container */}
      <div className="graph-container">
        <ForceGraph2D
          graphData={filteredData}
          nodeLabel={node => `${node.fullName}\nIP: ${node.ip}\nStatus: ${node.status}\nBandwidth: ${formatBytes(node.bandwidth.total)}/s`}
          onNodeClick={handleNodeClick}
          linkColor={getLinkColor}
          linkWidth={link => Math.max(1, (link.value || 1) / 2)}
          nodeCanvasObject={handleNodeCanvas}
          linkDirectionalParticles={3}
          linkDirectionalParticleWidth={handleLinkParticleWidth}
          linkDirectionalParticleSpeed={handleLinkParticleSpeed}
          cooldownTicks={100}
          nodeRelSize={8}
          backgroundColor="#1a1a2e"
        />
      </div>

      {/* Node Details Panel */}
      {selectedNode && (
        <div className="node-details-panel">
          <div className="panel-header">
            <h3>Device Details</h3>
            <button className="close-button" onClick={closeDetailsPanel}>✖</button>
          </div>
          
          <div className="device-icon">
            {deviceIcons[selectedNode.deviceType] || deviceIcons.Unknown}
          </div>
          
          <div className="details-content">
            <div className="detail-row">
              <span className="detail-label">Device Type:</span>
              <span className="detail-value">{selectedNode.deviceType}</span>
            </div>
            
            <div className="detail-row">
              <span className="detail-label">IP Address:</span>
              <span className="detail-value">{selectedNode.ip}</span>
            </div>
            
            <div className="detail-row">
              <span className="detail-label">MAC Address:</span>
              <span className="detail-value">{selectedNode.mac}</span>
            </div>
            
            <div className="detail-row">
              <span className="detail-label">Status:</span>
              <span className={`detail-value status-${selectedNode.status}`}>
                {selectedNode.status.charAt(0).toUpperCase() + selectedNode.status.slice(1)}
              </span>
            </div>
            
            <div className="detail-row">
              <span className="detail-label">Last Seen:</span>
              <span className="detail-value">
                {new Date(selectedNode.lastSeen).toLocaleString()}
              </span>
            </div>
            
            <div className="bandwidth-section">
              <h4>Bandwidth</h4>
              <div className="detail-row">
                <span className="detail-label">Download:</span>
                <span className="detail-value">
                  {formatBytes(selectedNode.bandwidth.received)}/s
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Upload:</span>
                <span className="detail-value">
                  {formatBytes(selectedNode.bandwidth.sent)}/s
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Total:</span>
                <span className="detail-value">
                  {formatBytes(selectedNode.bandwidth.total)}/s
                </span>
              </div>
            </div>
            
            <div className="packets-section">
              <h4>Packet Data</h4>
              <div className="detail-row">
                <span className="detail-label">Packets Received:</span>
                <span className="detail-value">
                  {selectedNode.packets.received.toLocaleString()}/s
                </span>
              </div>
              <div className="detail-row">
                <span className="detail-label">Packets Sent:</span>
                <span className="detail-value">
                  {selectedNode.packets.sent.toLocaleString()}/s
                </span>
              </div>
            </div>
            
            <div className="connections-section">
              <h4>Connections</h4>
              <div className="connections-list">
                {filteredData.links
                  .filter(link => 
                    link.source.id === selectedNode.id || 
                    link.target.id === selectedNode.id
                  )
                  .map((link, index) => {
                    const connectedNodeId = link.source.id === selectedNode.id 
                      ? link.target.id 
                      : link.source.id;
                    const connectedNode = filteredData.nodes.find(n => n.id === connectedNodeId);
                    
                    return connectedNode ? (
                      <div key={index} className="connection-item">
                        <span className="connected-device">
                          {connectedNode.name}
                        </span>
                        <span className="connection-bandwidth">
                          {formatBytes(link.bandwidth)}/s
                        </span>
                      </div>
                    ) : null;
                  })
                }
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default NetworkTopology;