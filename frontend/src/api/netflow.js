// src/api/netflow.js
export const fetchNetflowPredictions = async () => {
    try {
      const response = await fetch('http://127.0.0.1:5000/predict/netflow', {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json'
        }
      });
  
      if (!response.ok) throw new Error("API call failed");
      const data = await response.json();
      return data;
    } catch (err) {
      console.error("Fetch error:", err);
      return null;
    }
  };
  