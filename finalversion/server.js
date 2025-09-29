// --- server.js (Requires Node.js and 'npm install express body-parser node-fetch') ---
const express = require('express');
const fetch = require('node-fetch');
const bodyParser = require('body-parser');

const app = express();
const port = 3000; // This is the port your frontend will talk to

app.use(bodyParser.json());

// Enable CORS so the browser (frontend) can talk to this server
app.use((req, res, next) => {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
});

// Endpoint to handle AI bot requests
app.post('/api/ollama', async (req, res) => {
    const { prompt } = req.body;
    const ollamaHost = 'http://localhost:11434'; // Default Ollama URL

    if (!prompt) {
        return res.status(400).json({ success: false, error: 'Prompt is required.' });
    }

    try {
        console.log(`Proxying request to Ollama: ${prompt.substring(0, 50)}...`);

        const ollamaResponse = await fetch(`${ollamaHost}/api/generate`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                model: 'llama2', // IMPORTANT: Change this to the model you have installed (e.g., 'mistral', 'phi')
                prompt: `You are a cybersecurity expert. Give a concise, professional answer to this question: ${prompt}`,
                stream: false
            })
        });

        if (!ollamaResponse.ok) {
            throw new Error(`Ollama API error: ${ollamaResponse.statusText}. Status: ${ollamaResponse.status}`);
        }

        const data = await ollamaResponse.json();
        
        // Ollama response text is in data.response
        const botResponse = data.response.trim();

        res.json({ success: true, response: `OLLAMA: ${botResponse}` });

    } catch (error) {
        console.error('Error communicating with Ollama:', error.message);
        res.status(500).json({ 
            success: false, 
            response: `AI: ERROR: Could not connect to Ollama. Please ensure your Ollama service is running on ${ollamaHost}, you have the model 'llama2' installed, and the Node.js proxy is running on port ${port}.`
        });
    }
});

app.listen(port, () => {
    console.log(`Ollama Proxy running at http://localhost:${port}`);
    console.log('*** START YOUR FRONTEND NOW ***');
});