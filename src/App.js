import { useState } from "react";
import "./App.css";

export default function PhishingDetector() {
  const [input, setInput] = useState("");
  const [result, setResult] = useState(null);

  const handlePredict = async () => {
    // Placeholder for ML model integration
    const response = await fetch("http://localhost:5000/predict", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ text: input })
    });
    const data = await response.json();
    setResult(data.prediction);
  };

  return (
    <div className="container">
      <nav className="navbar">
        <span className="nav-title">Phishing Detector</span>
      </nav>
      
      <h1 className="title">Phishing Website Detector</h1>
      
      <div className="main-content">
        <div className="input-container">
          <textarea
            className="input-box"
            placeholder="Paste website URL or content here..."
            value={input}
            onChange={(e) => setInput(e.target.value)}
            rows={4}
          ></textarea>
          <button className="predict-btn" onClick={handlePredict}>Predict</button>
        </div>
        <div className="result-container">
          {result !== null && (
            <div className="result-box">Result: {result}</div>
          )}
        </div>
      </div>
    </div>
  );
}


