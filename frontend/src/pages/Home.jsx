import React from 'react';
import { Button } from '@/components/ui/button';
import { motion } from 'framer-motion';
import { ArrowRight, Network, Signal, BrainCircuit, Puzzle } from 'lucide-react';
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
          className="text-lg text-gray-700 max-w-3xl mx-auto mb-10 text-center"
        >
          Experience a cutting-edge simulation and monitoring system powered by real-time router analytics.
          Predict, visualize, and optimize wireless networks using a comprehensive digital twin platform
          embedded with AI-driven intelligence.
        </motion.p>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.4, duration: 0.8 }}
          className="grid grid-cols-1 md:grid-cols-2 gap-y-10 gap-x-8 max-w-6xl mx-auto mb-14"
        >
          {/* Card 1 */}
          <div className="bg-white shadow-xl rounded-2xl p-6 md:p-8 flex items-start gap-4">
            <Network className="text-indigo-600 w-8 h-8 mt-1" />
            <div>
              <h2 className="text-m font-semibold text-indigo-700 mb-2">Real-Time Flow Prediction</h2>
              <p className="text-gray-600 text-sm leading-relaxed">
                Live packet inspection using payload and Netflow features helps detect anomalies and security threats
                in real-time. Our system uses a Hidden Markov Model to classify traffic states.
              </p>
            </div>
          </div>

          {/* Card 2 */}
          <div className="bg-white shadow-xl rounded-2xl p-6 md:p-8 flex items-start gap-4">
            <Signal className="text-indigo-600 w-8 h-8 mt-1" />
            <div>
              <h2 className="text-m font-semibold text-indigo-700 mb-2">Dynamic Topology Mapping</h2>
              <p className="text-gray-600 text-sm leading-relaxed">
                Visualize wireless infrastructure in real time. Our platform updates device connectivity and signal
                strength dynamically, enhancing situational awareness.
              </p>
            </div>
          </div>

          {/* Card 3 */}
          <div className="bg-white shadow-xl rounded-2xl p-6 md:p-8 flex items-start gap-4">
            <BrainCircuit className="text-indigo-600 w-8 h-8 mt-1" />
            <div>
              <h2 className="text-m font-semibold text-indigo-700 mb-2">AI-Powered Insights</h2>
              <p className="text-gray-600 text-sm leading-relaxed">
                Machine learning models provide intelligent recommendations for traffic rerouting, anomaly detection,
                and wireless channel optimization.
              </p>
            </div>
          </div>

          {/* Card 4 */}
          <div className="bg-white shadow-xl rounded-2xl p-6 md:p-8 flex items-start gap-4">
            <Puzzle className="text-indigo-600 w-8 h-8 mt-1" />
            <div>
              <h2 className="text-m font-semibold text-indigo-700 mb-2">Seamless Integration</h2>
              <p className="text-gray-600 text-sm leading-relaxed">
                Easily connect with your existing network stack using robust APIs. Our architecture ensures compatibility
                and flexibility across hardware vendors.
              </p>
            </div>
          </div>
        </motion.div>

        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.6, duration: 0.8 }}
          className="flex justify-center gap-6 flex-wrap"
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

          <Link to="/docs">
            <Button className="text-lg px-6 py-3 rounded-2xl shadow-md bg-gray-100 text-indigo-700 hover:bg-gray-200">
              Platform Documentation <ArrowRight className="ml-2 w-5 h-5" />
            </Button>
          </Link>
        </motion.div>
      </section>
    </main>
  );
};

export default HomePage;
