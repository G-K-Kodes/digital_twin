import React from 'react';
import { Button } from '@/components/ui/button';
import { motion } from 'framer-motion';
import { ArrowRight } from 'lucide-react';
import { Link } from 'react-router-dom';

const HomePage = () => {
  return (
    <main className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 p-10">
      <section className="max-w-7xl mx-auto text-center">
        <motion.h1
          initial={{ opacity: 0, y: -50 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.8 }}
          className="text-5xl font-bold text-indigo-800 mb-6"
        >
          Digital Twin of Wireless Networks
        </motion.h1>

        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2, duration: 0.8 }}
          className="text-lg text-gray-700 max-w-3xl mx-auto mb-10"
        >
          Experience a cutting-edge simulation and monitoring system powered by real-time router analytics.
          Our platform predicts network flow behavior through live analysis of traffic data, utilizing
          machine learning models integrated into the router's digital twin.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4, duration: 0.8 }}
          className="bg-white shadow-xl rounded-2xl p-8 max-w-4xl mx-auto text-left mb-10"
        >
          <h2 className="text-2xl font-semibold text-indigo-700 mb-4">Network Flow Prediction</h2>
          <p className="text-gray-600 mb-4">
            Our router endpoint analyzes live packets to extract Netflow and Payload features, predicting whether traffic
            is benign or anomalous using HMM-based models. The system provides real-time insights to ensure network integrity
            and proactively alerts administrators of suspicious behavior.
          </p>

          <h2 className="text-2xl font-semibold text-indigo-700 mt-6 mb-4">Network Topology Overview</h2>
          <p className="text-gray-600">
            The digital twin captures the current state of the wireless network, visualizing connected devices,
            packet exchange, and signal strength. Topology updates dynamically to reflect real-time status, enabling
            better network awareness and performance tracking.
          </p>
        </motion.div>

        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.6, duration: 0.8 }}
          className="flex justify-center gap-6"
        >
          <Link to="/network">
            <Button className="text-lg px-6 py-3 rounded-2xl shadow-md bg-indigo-600 text-white hover:bg-indigo-700">
              Go to Network Dashboard <ArrowRight className="ml-2 w-5 h-5" />
            </Button>
          </Link>

          <Link to="/topology">
            <Button className="text-lg px-6 py-3 rounded-2xl shadow-md bg-white text-indigo-600 border border-indigo-300 hover:bg-indigo-50">
              View Network Topology <ArrowRight className="ml-2 w-5 h-5" />
            </Button>
          </Link>
        </motion.div>
      </section>
    </main>
  );
};

export default HomePage;