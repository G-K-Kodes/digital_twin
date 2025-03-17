import 'aframe';
import 'aframe-extras';
import React, { useEffect, useState } from 'react';
import { ForceGraph2D } from 'react-force-graph';
import axios from 'axios';
import { io } from 'socket.io-client';

// Initialize Socket.IO
const socket = io('http://127.0.0.1:5000');

// Icon mapping based on vendor types
const vendorIcons = {
    Cisco: '🟦',
    Router: '🛜',
    Unknown: '❓'
};

// Status colors
const statusColors = {
    active: '#4CAF50',    // Green for online
    inactive: '#F44336',  // Red for offline
    unknown: '#FFC107'    // Yellow for unknown state
};

const NetworkTopology = () => {
    const [data, setData] = useState({ nodes: [], links: [] });
    const [loading, setLoading] = useState(true);

    const formatTopologyData = (topologyData) => {
        const nodes = topologyData.map(device => ({
            id: device.id,
            name: `${vendorIcons[device.name] || '❓'} ${device.name} (${device.id})`,
            status: device.status,
            bandwidth: Math.random() * 100 + 50,  // Mock data for bandwidth
            group: device.name === "Router" ? 2 : 1
        }));

        const links = topologyData.flatMap(device =>
            device.connections.map(connection => ({
                source: device.id,
                target: connection,
                bandwidth: Math.random() * 100 + 10  // Mock data for bandwidth
            }))
        );

        return { nodes, links };
    };

    useEffect(() => {
        const fetchTopology = async () => {
            try {
                const response = await axios.get('http://127.0.0.1:5000/network/topology');
                console.log('Topology Data:', response.data);

                const formattedData = formatTopologyData(response.data.network_topology);
                setData(formattedData);
                setLoading(false);
            } catch (error) {
                console.error('Error fetching topology data:', error);
            }
        };

        fetchTopology();

        // Live updates via Socket.IO
        socket.on('network_topology_update', (newTopology) => {
            console.log('Live update received:', newTopology);
            setData(formatTopologyData(newTopology.network_topology));
        });

        return () => socket.disconnect();  // Clean up Socket.IO connection
    }, []);

    if (loading) return <div>Loading Network Topology...</div>;

    return (
        <div style={{ width: '100%', height: '1500px', color: '#FFF', borderRadius: '12px', boxShadow: '0 4px 15px rgba(0, 0, 0, 0.3)' }}>
            <ForceGraph2D
                graphData={data}
                nodeLabel="name"
                nodeAutoColorBy="group"
                linkDirectionalParticles={2}
                linkDirectionalParticleWidth={link => link.bandwidth / 50}  // Bandwidth visualization
                linkDirectionalParticleSpeed={() => 0.02}
                nodeCanvasObject={(node, ctx, globalScale) => {
                    const label = node.name;
                    const fontSize = 14 / globalScale;
                    ctx.font = `${fontSize}px Sans-Serif`;

                    // Dynamic color coding for device status
                    ctx.fillStyle = statusColors[node.status] || '#9E9E9E';
                    ctx.textAlign = 'center';
                    ctx.fillText(label, node.x, node.y - 10);

                    // Draw circles for nodes with bandwidth-based radius
                    const radius = Math.min(5, node.bandwidth / 15);
                    ctx.beginPath();
                    ctx.arc(node.x, node.y, radius, 0, 2 * Math.PI, false);
                    ctx.fill();
                }}
            />
        </div>
    );
};

export default NetworkTopology;
