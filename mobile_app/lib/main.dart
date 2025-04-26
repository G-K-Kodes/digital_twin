import 'package:flutter/material.dart';
import 'package:mobile_app/pages/network_topology.dart';

void main() {
  runApp(const MyApp());
}

class MyApp extends StatelessWidget {
  const MyApp({super.key});

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'Network Topology Monitor',
      theme: ThemeData(
        colorScheme: ColorScheme.fromSeed(seedColor: Colors.deepPurple),
        useMaterial3: true,
      ),
      home: NetworkTopologyPage(),
      debugShowCheckedModeBanner: false,
    );
  }
}

