import 'dart:async';
import 'dart:convert';
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;
import 'package:graphview/GraphView.dart';
import 'package:fl_chart/fl_chart.dart';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:path_provider/path_provider.dart';
import 'package:printing/printing.dart';
import 'package:flutter_spinkit/flutter_spinkit.dart';

class NetworkTopologyPage extends StatefulWidget {
  const NetworkTopologyPage({Key? key}) : super(key: key);

  @override
  _NetworkTopologyPageState createState() => _NetworkTopologyPageState();
}

class _NetworkTopologyPageState extends State<NetworkTopologyPage>
    with SingleTickerProviderStateMixin {
  late TabController _tabController;
  final GlobalKey _graphKey = GlobalKey();

  // Graph state
  final Graph graph = Graph()..isTree = false;
  final Algorithm algorithm = FruchtermanReingoldAlgorithm();

  // Data states
  bool _isLoading = true;
  bool _isFullscreen = false;
  Map<String, dynamic> _topologyData = {'nodes': [], 'links': []};
  Map<String, dynamic> _packetStats = {};
  Map<String, dynamic>? _selectedNode;
  Map<String, dynamic>? _hoveredNode;
  List<Map<String, dynamic>> _bandwidthHistory = [];

  @override
  void initState() {
    super.initState();
    _tabController = TabController(length: 2, vsync: this);
    _fetchData();
    // Set up periodic data refresh
    Timer.periodic(const Duration(seconds: 10), (timer) => _fetchData());
  }

  @override
  void dispose() {
    _tabController.dispose();
    super.dispose();
  }

  Future<void> _fetchData() async {
    try {
      setState(() {
        _isLoading = true;
      });

      // Fetch topology data
      final topoResponse =
          await http.get(Uri.parse('http://127.0.0.1:5000/network/topology'));
      final topoJson = json.decode(topoResponse.body);

      // Fetch packet stats
      final statsResponse = await http
          .get(Uri.parse('http://127.0.0.1:5000/network/packet_stats'));
      final statsJson = json.decode(statsResponse.body);

      // Process nodes
      List<Map<String, dynamic>> nodes = [];
      topoJson.values.forEach((device) {
        nodes.add({
          'id': device['MAC'],
          'label': device['Vendor'] ?? device['MAC'],
          'ip': device['Current_IP'],
          'vendor': device['Vendor'],
          'suspicious': device['Suspicious'],
          'Previous_IPs': device['Previous_IPs'] ?? [],
          'First_Seen': device['First_Seen'],
          'Last_Seen': device['Last_Seen'],
          'Online': device['Online'],
          'Time_Since_Last_Seen': device['Time_Since_Last_Seen'],
          'Packets_Sent': device['Packets_Sent'] ?? 0,
          'Packets_Received': device['Packets_Received'] ?? 0,
          'Bytes_Sent': device['Bytes_Sent'] ?? 0,
          'Bytes_Received': device['Bytes_Received'] ?? 0
        });
      });

      // Process links
      List<Map<String, dynamic>> links = [];
      List<String> macs = topoJson.keys.toList();
      for (int i = 0; i < macs.length; i++) {
        for (int j = i + 1; j < macs.length; j++) {
          final d1 = topoJson[macs[i]];
          final d2 = topoJson[macs[j]];
          if ((d1['Current_IP'] ?? '').startsWith('192.168.') &&
              (d2['Current_IP'] ?? '').startsWith('192.168.')) {
            links.add({'source': d1['MAC'], 'target': d2['MAC']});
          }
        }
      }

      // Update bandwidth history
      final timestamp = DateTime.now().toLocal().toString().substring(11, 19);
      List<Map<String, dynamic>> historySnapshot = [];

      statsJson.forEach((mac, stats) {
        historySnapshot.add({
          'time': timestamp,
          'mac': mac,
          'packetsSent': stats['Packets_Sent'] ?? 0,
          'packetsReceived': stats['Packets_Received'] ?? 0,
          'bytesSent': stats['Bytes_Sent'] ?? 0,
          'bytesReceived': stats['Bytes_Received'] ?? 0,
        });
      });

      // Limit history to last 20 entries
      List<Map<String, dynamic>> newHistory = [
        ..._bandwidthHistory,
        ...historySnapshot
      ];
      if (newHistory.length > 20) {
        newHistory = newHistory.sublist(newHistory.length - 20);
      }

      setState(() {
        _topologyData = {'nodes': nodes, 'links': links};
        _packetStats = statsJson;
        _bandwidthHistory = newHistory;
        _isLoading = false;

        // Rebuild graph
        _buildGraph();
      });
    } catch (e) {
      setState(() {
        _isLoading = false;
      });
    }
  }

  void _buildGraph() {
    // Clear existing graph
    graph.nodes.clear();
    graph.edges.clear();

    // Map to store node IDs
    Map<String, Node> nodeMap = {};

    // Add nodes
    for (var nodeData in _topologyData['nodes']) {
      final node = Node.Id(nodeData['id']);
      graph.addNode(node);
      nodeMap[nodeData['id']] = node;
    }

    // Add edges
    for (var linkData in _topologyData['links']) {
      final sourceNode = nodeMap[linkData['source']];
      final targetNode = nodeMap[linkData['target']];
      if (sourceNode != null && targetNode != null) {
        graph.addEdge(sourceNode, targetNode);
      }
    }
  }

  void _selectNode(Map<String, dynamic> node) {
    setState(() {
      _selectedNode = node;
    });
  }

  void _hoverNode(Map<String, dynamic>? node) {
    setState(() {
      _hoveredNode = node;
    });
  }

  String _formatBytes(int bytes, [int decimals = 2]) {
    if (bytes <= 0) return '0 B';
    const suffixes = ['B', 'KB', 'MB', 'GB', 'TB'];
    var i = (math.log(bytes) / math.log(1024)).floor();
    return '${(bytes / math.pow(1024, i)).toStringAsFixed(decimals)} ${suffixes[i]}';
  }

  Future<void> _exportToPdf() async {
    final pdf = pw.Document();

    // Create PDF content
    pdf.addPage(
      pw.Page(
        pageFormat: PdfPageFormat.a4.landscape,
        build: (pw.Context context) {
          return pw.Column(
            crossAxisAlignment: pw.CrossAxisAlignment.start,
            children: [
              pw.Header(
                level: 0,
                child: pw.Text('Network Topology Report'),
              ),
              pw.SizedBox(height: 20),
              pw.Text('Generated on: ${DateTime.now().toString()}'),
              pw.SizedBox(height: 10),
              pw.Text('Devices detected: ${_topologyData['nodes'].length}'),
              pw.SizedBox(height: 10),
              pw.Text('Connections: ${_topologyData['links'].length}'),
              pw.SizedBox(height: 30),
              pw.Table.fromTextArray(
                headers: [
                  'MAC',
                  'Vendor',
                  'IP',
                  'Status',
                  'Packets Sent',
                  'Packets Received'
                ],
                data: _topologyData['nodes'].map<List<String>>((node) {
                  String status = node['Online'] == true
                      ? (node['suspicious'] == true ? 'Suspicious' : 'Online')
                      : 'Offline';
                  return [
                    node['id'],
                    node['vendor'] ?? 'Unknown',
                    node['ip'] ?? 'N/A',
                    status,
                    node['Packets_Sent'].toString(),
                    node['Packets_Received'].toString(),
                  ];
                }).toList(),
              ),
            ],
          );
        },
      ),
    );

    // Save and print
    await Printing.sharePdf(
        bytes: await pdf.save(), filename: 'network_topology.pdf');
  }

  Future<void> _exportToJson() async {
    final jsonContent = json.encode(_topologyData);
    // Use printing package to share JSON as text
    final pdf = pw.Document();
    pdf.addPage(
      pw.Page(
        build: (pw.Context context) {
          return pw.Text(jsonContent);
        },
      ),
    );
    await Printing.sharePdf(
        bytes: await pdf.save(), filename: 'network_topology.json');
  }

  Widget _buildTopologyView() {
    return Container(
      key: _graphKey,
      color: Colors.white,
      child: Stack(
        children: [
          InteractiveViewer(
            constrained: false,
            boundaryMargin: EdgeInsets.all(100),
            minScale: 0.1,
            maxScale: 5.0,
            child: GraphView(
              graph: graph,
              algorithm: algorithm,
              builder: (Node node) {
                // Find node data
                Map<String, dynamic>? nodeData;
                for (var n in _topologyData['nodes']) {
                  if (n['id'] == node.key?.value) {
                    nodeData = n;
                    break;
                  }
                }

                if (nodeData == null) {
                  return Container(width: 1, height: 1);
                }

                // Determine node color based on status
                Color nodeColor;
                if (nodeData['suspicious'] == true) {
                  nodeColor = Colors.red;
                } else if (nodeData['Online'] == true) {
                  nodeColor = Colors.green;
                } else {
                  nodeColor = Colors.grey;
                }

                // Determine border based on selection
                Border nodeBorder = Border.all(
                  color: _selectedNode != null &&
                          _selectedNode!['id'] == nodeData['id']
                      ? Colors.blue
                      : (_hoveredNode != null &&
                              _hoveredNode!['id'] == nodeData['id']
                          ? Colors.grey
                          : Colors.transparent),
                  width: _selectedNode != null &&
                          _selectedNode!['id'] == nodeData['id']
                      ? 3
                      : 1,
                );

                // Determine text color based on status
                Color textColor = nodeData['Online'] == true
                    ? (nodeData['suspicious'] == true
                        ? Colors.red
                        : Colors.black87)
                    : Colors.grey;

                // Build the node widget
                return GestureDetector(
                  onTap: () => _selectNode(nodeData!),
                  child: Column(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Container(
                        width: 16,
                        height: 16,
                        decoration: BoxDecoration(
                          color: nodeColor,
                          shape: BoxShape.circle,
                          border: nodeBorder,
                        ),
                      ),
                      SizedBox(height: 4),
                      Container(
                        constraints: BoxConstraints(maxWidth: 120),
                        child: Column(
                          crossAxisAlignment: CrossAxisAlignment.start,
                          mainAxisSize: MainAxisSize.min,
                          children: [
                            Text(
                              nodeData['label']?.toString() ?? '',
                              style: TextStyle(
                                fontSize: 12,
                                color: textColor,
                                overflow: TextOverflow.ellipsis,
                              ),
                              maxLines: 1,
                            ),
                            Text(
                              '${nodeData['Packets_Received']}↓/${nodeData['Packets_Sent']}↑',
                              style: TextStyle(
                                fontSize: 10,
                                color: Colors.grey,
                              ),
                            ),
                          ],
                        ),
                      ),
                    ],
                  ),
                );
              },
              // These parameters help with edge appearance
              paint: Paint()
                ..color = Colors.grey.shade300
                ..strokeWidth = 1.5
                ..style = PaintingStyle.stroke,
            ),
          ),
          Positioned(
            top: 16,
            right: 16,
            child: Row(
              children: [
                IconButton(
                  icon: Icon(
                      _isFullscreen ? Icons.fullscreen_exit : Icons.fullscreen),
                  onPressed: () {
                    setState(() {
                      _isFullscreen = !_isFullscreen;
                    });
                  },
                  color: Colors.blue,
                  tooltip: _isFullscreen ? 'Exit Fullscreen' : 'Fullscreen',
                ),
                IconButton(
                  icon: Icon(Icons.center_focus_strong),
                  onPressed: () {
                    // Reset zoom - in a real app you would use a controller
                    setState(() {
                      algorithm.step(Graph());
                    });
                  },
                  color: Colors.blue,
                  tooltip: 'Center Graph',
                ),
                IconButton(
                  icon: Icon(Icons.file_download),
                  onPressed: _exportToPdf,
                  color: Colors.blue,
                  tooltip: 'Export PDF',
                ),
                IconButton(
                  icon: Icon(Icons.code),
                  onPressed: _exportToJson,
                  color: Colors.blue,
                  tooltip: 'Export JSON',
                ),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDeviceDetailsView() {
    return SingleChildScrollView(
      child: Column(
        children: [
          if (_selectedNode != null) ...[
            // Device Info Card
            Card(
              margin: EdgeInsets.all(8),
              child: Padding(
                padding: EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Row(
                      mainAxisAlignment: MainAxisAlignment.spaceBetween,
                      children: [
                        Text(
                          'Device Info',
                          style: TextStyle(
                              fontSize: 18, fontWeight: FontWeight.bold),
                        ),
                        Container(
                          padding:
                              EdgeInsets.symmetric(horizontal: 8, vertical: 4),
                          decoration: BoxDecoration(
                            color: _selectedNode!['Online'] == true
                                ? (_selectedNode!['suspicious'] == true
                                    ? Colors.red.shade100
                                    : Colors.green.shade100)
                                : Colors.grey.shade100,
                            borderRadius: BorderRadius.circular(16),
                          ),
                          child: Text(
                            _selectedNode!['Online'] == true
                                ? (_selectedNode!['suspicious'] == true
                                    ? 'Suspicious'
                                    : 'Online')
                                : 'Offline',
                            style: TextStyle(
                              fontSize: 12,
                              fontWeight: FontWeight.bold,
                              color: _selectedNode!['Online'] == true
                                  ? (_selectedNode!['suspicious'] == true
                                      ? Colors.red.shade800
                                      : Colors.green.shade800)
                                  : Colors.grey.shade800,
                            ),
                          ),
                        ),
                      ],
                    ),
                    SizedBox(height: 16),
                    _buildDetailRow('MAC:', _selectedNode!['id'].toString()),
                    _buildDetailRow(
                        'Vendor:', _selectedNode!['vendor'] ?? 'Unknown'),
                    _buildDetailRow('IP:', _selectedNode!['ip'] ?? 'N/A'),
                    _buildDetailRow(
                        'Previous IPs:',
                        (_selectedNode!['Previous_IPs'] as List?)?.join(', ') ??
                            'None'),
                    _buildDetailRow('First Seen:',
                        _selectedNode!['First_Seen'] ?? 'Unknown'),
                    _buildDetailRow(
                        'Last Seen:', _selectedNode!['Last_Seen'] ?? 'Unknown'),
                    _buildDetailRow('Time Since:',
                        _selectedNode!['Time_Since_Last_Seen'] ?? 'Unknown'),
                    SizedBox(height: 24),
                    Row(
                      children: [
                        Icon(Icons.show_chart, size: 16, color: Colors.blue),
                        SizedBox(width: 8),
                        Text(
                          'Traffic Statistics',
                          style: TextStyle(
                              fontSize: 16, fontWeight: FontWeight.bold),
                        ),
                      ],
                    ),
                    SizedBox(height: 16),
                    GridView.count(
                      shrinkWrap: true,
                      physics: NeverScrollableScrollPhysics(),
                      crossAxisCount: 2,
                      crossAxisSpacing: 8,
                      mainAxisSpacing: 8,
                      childAspectRatio: 2.5,
                      children: [
                        _buildStatCard('Packets Sent',
                            _selectedNode!['Packets_Sent'].toString()),
                        _buildStatCard('Packets Received',
                            _selectedNode!['Packets_Received'].toString()),
                        _buildStatCard('Bytes Sent',
                            _formatBytes(_selectedNode!['Bytes_Sent'] ?? 0)),
                        _buildStatCard(
                            'Bytes Received',
                            _formatBytes(
                                _selectedNode!['Bytes_Received'] ?? 0)),
                      ],
                    ),
                  ],
                ),
              ),
            ),

            // Bandwidth Chart Card
            Card(
              margin: EdgeInsets.all(8),
              child: Padding(
                padding: EdgeInsets.all(16),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      'Bandwidth Trend',
                      style:
                          TextStyle(fontSize: 18, fontWeight: FontWeight.bold),
                    ),
                    SizedBox(height: 16),
                    _buildBandwidthChart(),
                  ],
                ),
              ),
            ),
          ] else ...[
            // No device selected state
            Container(
              height: 300,
              alignment: Alignment.center,
              child: Column(
                mainAxisAlignment: MainAxisAlignment.center,
                children: [
                  Icon(Icons.wifi, size: 48, color: Colors.grey.shade300),
                  SizedBox(height: 16),
                  Text(
                    'Select a device from the topology view',
                    style: TextStyle(color: Colors.grey.shade600),
                  ),
                ],
              ),
            ),
          ],
        ],
      ),
    );
  }

  Widget _buildDetailRow(String label, String value) {
    return Padding(
      padding: EdgeInsets.symmetric(vertical: 4),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          SizedBox(
            width: 100,
            child: Text(
              label,
              style: TextStyle(
                  color: Colors.grey.shade600, fontWeight: FontWeight.w500),
            ),
          ),
          Expanded(
            child: Text(
              value,
              style: TextStyle(
                fontFamily: label.contains('MAC:') || label.contains('IP:')
                    ? 'monospace'
                    : null,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildStatCard(String label, String value) {
    return Container(
      padding: EdgeInsets.all(8),
      decoration: BoxDecoration(
        color: Colors.grey.shade50,
        borderRadius: BorderRadius.circular(8),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            label,
            style: TextStyle(color: Colors.grey.shade500, fontSize: 12),
          ),
          SizedBox(height: 4),
          Text(
            value,
            style: TextStyle(fontWeight: FontWeight.bold, fontSize: 16),
          ),
        ],
      ),
    );
  }

  Widget _buildBandwidthChart() {
    // Filter history for selected node
    final nodeHistory = _bandwidthHistory
        .where((entry) => entry['mac'] == _selectedNode?['id'])
        .toList();

    if (nodeHistory.isEmpty) {
      return Container(
        height: 300,
        alignment: Alignment.center,
        child: Column(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            Icon(Icons.show_chart, size: 48, color: Colors.grey.shade300),
            SizedBox(height: 16),
            Text(
              'No bandwidth history available for this node yet.',
              style: TextStyle(color: Colors.grey.shade600),
            ),
            SizedBox(height: 8),
            Text(
              'Data will appear after a few refresh cycles.',
              style: TextStyle(color: Colors.grey.shade400, fontSize: 12),
            ),
          ],
        ),
      );
    }

    // Prepare data for FL Chart
    List<FlSpot> sentSpots = [];
    List<FlSpot> receivedSpots = [];

    for (int i = 0; i < nodeHistory.length; i++) {
      final sent = nodeHistory[i]['bytesSent'];
      final received = nodeHistory[i]['bytesReceived'];

      sentSpots.add(FlSpot(i.toDouble(), (sent is num ? sent : 0).toDouble()));
      receivedSpots.add(
          FlSpot(i.toDouble(), (received is num ? received : 0).toDouble()));
    }

    // Find max value for Y-axis
    double maxY = 1.0;
    for (var entry in nodeHistory) {
      final sent = entry['bytesSent'];
      final received = entry['bytesReceived'];

      maxY = math.max(
          maxY,
          math.max((sent is num ? sent : 0).toDouble(),
              (received is num ? received : 0).toDouble()));
    }

    return Container(
      height: 300,
      child: LineChart(
        LineChartData(
          gridData: FlGridData(
            show: true,
            drawVerticalLine: true,
            horizontalInterval: maxY / 5,
            getDrawingHorizontalLine: (value) {
              return FlLine(
                color: Colors.grey.shade200,
                strokeWidth: 1,
              );
            },
            getDrawingVerticalLine: (value) {
              return FlLine(
                color: Colors.grey.shade200,
                strokeWidth: 1,
              );
            },
          ),
          titlesData: FlTitlesData(
            bottomTitles: AxisTitles(
              sideTitles: SideTitles(
                showTitles: true,
                reservedSize: 22,
                getTitlesWidget: (double value, TitleMeta meta) {
                  final index = value.toInt();
                  if (index >= 0 &&
                      index < nodeHistory.length &&
                      index % 3 == 0) {
                    return Text(
                      nodeHistory[index]['time'] ?? '',
                      style: const TextStyle(
                        color: Color(0xff68737d),
                        fontWeight: FontWeight.bold,
                        fontSize: 10,
                      ),
                    );
                  }
                  return const Text('');
                },
                interval: 1,
              ),
            ),
            leftTitles: AxisTitles(
              sideTitles: SideTitles(
                showTitles: true,
                getTitlesWidget: (double value, TitleMeta meta) {
                  return Text(
                    _formatBytes(value.toInt(), 0),
                    style: const TextStyle(
                      color: Color(0xff67727d),
                      fontWeight: FontWeight.bold,
                      fontSize: 10,
                    ),
                  );
                },
                reservedSize: 50,
              ),
            ),
            rightTitles: AxisTitles(
              sideTitles: SideTitles(showTitles: false),
            ),
            topTitles: AxisTitles(
              sideTitles: SideTitles(showTitles: false),
            ),
          ),
          borderData: FlBorderData(
            show: true,
            border: Border.all(color: const Color(0xff37434d), width: 1),
          ),
          minX: 0,
          maxX: (nodeHistory.length - 1).toDouble(),
          minY: 0,
          maxY: maxY * 1.2,
          lineBarsData: [
            LineChartBarData(
              spots: sentSpots,
              isCurved: true,
              color: Colors.indigo,
              barWidth: 3,
              isStrokeCapRound: true,
              dotData: FlDotData(show: false),
              belowBarData: BarAreaData(show: false),
            ),
            LineChartBarData(
              spots: receivedSpots,
              isCurved: true,
              color: Colors.green,
              barWidth: 3,
              isStrokeCapRound: true,
              dotData: FlDotData(show: false),
              belowBarData: BarAreaData(show: false),
            ),
          ],
          lineTouchData: LineTouchData(
            touchTooltipData: LineTouchTooltipData(
              getTooltipItems: (List<LineBarSpot> touchedSpots) {
                return touchedSpots.map((spot) {
                  final String label = spot.barIndex == 0 ? 'Sent' : 'Received';
                  return LineTooltipItem(
                    '$label: ${_formatBytes(spot.y.toInt())}',
                    TextStyle(
                      color: spot.barIndex == 0 ? Colors.indigo : Colors.green,
                      fontWeight: FontWeight.bold,
                    ),
                  );
                }).toList();
              },
            ),
          ),
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        title: Row(
          children: [
            Icon(Icons.wifi),
            SizedBox(width: 8),
            Text('Network Topology Monitor'),
          ],
        ),
        bottom: TabBar(
          controller: _tabController,
          tabs: [
            Tab(text: 'Topology View'),
            Tab(text: 'Device Details'),
          ],
        ),
      ),
      body: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Padding(
            padding: EdgeInsets.all(16),
            child: Text(
              'Monitoring ${_topologyData['nodes'].length} devices and ${_topologyData['links'].length} connections',
              style: TextStyle(color: Colors.grey.shade600),
            ),
          ),
          Expanded(
            child: _isLoading
                ? Center(
                    child: SpinKitRing(
                      color: Colors.blue,
                      size: 50.0,
                    ),
                  )
                : TabBarView(
                    controller: _tabController,
                    children: [
                      // Topology View Tab
                      _buildTopologyView(),

                      // Device Details Tab
                      _buildDeviceDetailsView(),
                    ],
                  ),
          ),

          // Footer
          Padding(
            padding: EdgeInsets.all(8),
            child: Text(
              'Last updated: ${DateTime.now().toLocal().toString().substring(0, 19)}',
              style: TextStyle(color: Colors.grey.shade400, fontSize: 12),
              textAlign: TextAlign.right,
            ),
          ),
        ],
      ),
    );
  }
}
