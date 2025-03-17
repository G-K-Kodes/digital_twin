import axios from 'axios';

const API_BASE_URL = 'http://127.0.0.1:5000'; // Change if your API is on a different port

export const fetchData = async () => {
    try {
        const response = await axios.get(`${API_BASE_URL}/network/topology`);
        return response.data;
    } catch (error) {
        console.error('Error fetching data:', error);
        throw error;
    }
};
