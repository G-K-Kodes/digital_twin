import 'aframe';
import 'aframe-extras';
import React from 'react';
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom';

import Navbar from './components/Navbar';
import NetworkTopology from './pages/NetworkTopology';
import NetworkDashboard from './pages/NetworkDashboard';
import HomePage from './pages/Home';

const App = () => {
  return (
    <Router>
      <Navbar />
      <Routes>
        <Route path='/' element={<HomePage />} />
        <Route path='/topology' element={<NetworkTopology />} />
        <Route path='/network' element={<NetworkDashboard />} />
        <Route path='/simulations' element = {<div className='p-10 text-center'>Simulation feature Coming Soon</div>}/>
        <Route path='/contact' element={<div className='p-10 text-center'>Contact Page Coming Soon</div>} />
      </Routes>
    </Router>
  );
};

export default App;
