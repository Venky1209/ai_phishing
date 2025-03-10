import { useState, useEffect } from "react";
import "./App.css";


export default function PhishingDetector() {
  const [urlInput, setUrlInput] = useState("");
  const [textInput, setTextInput] = useState("");
  const [urlResult, setUrlResult] = useState(null);
  const [textResult, setTextResult] = useState(null);
  const [loadingUrl, setLoadingUrl] = useState(false);
  const [loadingText, setLoadingText] = useState(false);
  const [activeSection, setActiveSection] = useState("both"); // "url", "text", or "both"
  const [shake, setShake] = useState(false);
  const [urlError, setUrlError] = useState("");
  const [textError, setTextError] = useState("");

  // Handle URL section focus
  const handleUrlFocus = () => {
    if (urlInput.trim() !== "") {
      setActiveSection("url");
    }
  };

  // Handle Text section focus
  const handleTextFocus = () => {
    if (textInput.trim() !== "") {
      setActiveSection("text");
    }
  };

  // Reset to both sections visible when inputs are cleared
  useEffect(() => {
    if (urlInput.trim() === "" && textInput.trim() === "") {
      setActiveSection("both");
    }
  }, [urlInput, textInput]);

  // Improved URL validation function
  const isValidUrl = (string) => {
    try {
      // Check if it has a valid URL format
      const url = new URL(string);
      return url.protocol === "http:" || url.protocol === "https:";
    } catch (_) {
      // Try adding http:// prefix and check again
      try {
        const url = new URL(`http://${string}`);
        return true;
      } catch {
        return false;
      }
    }
  };

  // Improved email content validation
  const looksLikeEmailContent = (text) => {
    // Check if text has multiple lines
    const lines = text.split('\n').filter(line => line.trim().length > 0);
    const hasMultipleLines = lines.length > 1;
    
    // Check for common email content patterns
    const emailPatterns = [
      /subject|dear|hello|hi|sincerely|regards|thank you/i,
      /we are writing to inform|we noticed|your account|recent activity/i,
      /please find attached|please review|please contact|please do not reply/i,
      /confidential|important|urgent|notification|alert/i,
      /customer service|support team|security team|account team/i
    ];
    
    const hasEmailPatterns = emailPatterns.some(pattern => pattern.test(text));
    
    // Check for greeting patterns (e.g., "Dear User," or "Hello,")
    const hasGreeting = /^(dear|hello|hi|greetings).{1,20}[,\.]/im.test(text);
    
    // If text is short, it's probably not an email
    if (text.length < 40 && !hasGreeting) {
      return false;
    }
    
    return hasMultipleLines || hasEmailPatterns || hasGreeting || text.length > 100;
  };

  // Improved URL check to avoid false positives
  const looksLikeUrl = (text) => {
    // If there are multiple lines or it's a long text, probably not a URL
    if (text.includes('\n') || text.length > 150) {
      return false;
    }
    
    // Basic URL patterns
    const urlPatterns = [
      /^https?:\/\//i,
      /^www\.[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}(:[0-9]{1,5})?(\/.*)?$/i,
      /^[a-z0-9]+([\-\.]{1}[a-z0-9]+)*\.[a-z]{2,}(:[0-9]{1,5})?(\/.*)?$/i
    ];
    
    // If text contains spaces or typical email content, it's not a URL
    if (text.includes(' ') && !text.startsWith('http')) {
      return false;
    }
    
    return urlPatterns.some(pattern => pattern.test(text.trim()));
  };

  // URL input change handler with validation
  const handleUrlInputChange = (e) => {
    const value = e.target.value;
    setUrlInput(value);
    
    // Clear error if input is empty
    if (!value.trim()) {
      setUrlError("");
      return;
    }
    
    // Check if the input looks like email content
    if (looksLikeEmailContent(value) && !looksLikeUrl(value)) {
      setUrlError("This looks like email content. Please use the Email Content box instead.");
    } else {
      setUrlError("");
    }
  };

  // Text input change handler with improved validation
  const handleTextInputChange = (e) => {
    const value = e.target.value;
    setTextInput(value);
    
    // Clear error if input is empty
    if (!value.trim()) {
      setTextError("");
      return;
    }
    
    // Check if input looks like a URL but not like email content
    if (looksLikeUrl(value) && !looksLikeEmailContent(value)) {
      setTextError("This looks like a URL. Please use the URL box instead.");
    } else {
      setTextError("");
    }
  };

  const handleUrlPredict = async () => {
    if (!urlInput.trim()) return;
    
    // Prepare URL for submission
    let urlToCheck = urlInput.trim();
    
    // Add http:// prefix if missing
    if (!urlToCheck.startsWith('http://') && !urlToCheck.startsWith('https://')) {
      urlToCheck = 'http://' + urlToCheck;
    }
    
    setLoadingUrl(true);
    setUrlResult(null);
    setShake(false);
    setUrlError("");
    
    try {
      const response = await fetch("http://localhost:5000/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: urlToCheck, type: "url" })
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
      
      const data = await response.json();
      console.log("URL prediction result:", data); // Debug log
      
      setUrlResult(data);
      
      // Check if it's a phishing URL and trigger shake animation
      if (data.prediction_label && data.prediction_label.toLowerCase() === "phishing") {
        setShake(true);
        setTimeout(() => setShake(false), 1000);
      }
    } catch (error) {
      console.error("URL prediction error:", error);
      setUrlResult({ 
        prediction_label: "Error", 
        prediction_score: 0,
        message: "Error connecting to server. Please try again."
      });
    }
    setLoadingUrl(false);
  };

  const handleTextPredict = async () => {
    if (!textInput.trim()) return;
    
    setLoadingText(true);
    setTextResult(null);
    setShake(false);
    setTextError("");
    
    try {
      const response = await fetch("http://localhost:5000/predict", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ text: textInput, type: "content" })
      });
      
      if (!response.ok) {
        throw new Error(`HTTP error! Status: ${response.status}`);
      }
      
      const data = await response.json();
      console.log("Text prediction result:", data); // Debug log
      
      setTextResult(data);
      
      // Check if it's phishing content and trigger shake animation
      if (data.prediction_label && data.prediction_label.toLowerCase() === "phishing") {
        setShake(true);
        setTimeout(() => setShake(false), 1000);
      }
    } catch (error) {
      console.error("Text prediction error:", error);
      setTextResult({
        prediction_label: "Error",
        prediction_score: 0,
        message: "Error connecting to server. Please try again."
      });
    }
    setLoadingText(false);
  };

  // Helper function to determine card classes based on active section
  const getCardClass = (section) => {
    let baseClass = "section card";
    
    if (activeSection === "both") {
      return baseClass;
    }
    
    if (activeSection === section) {
      return `${baseClass} card-expanded`;
    }
    
    return `${baseClass} card-minimized`;
  };

  return (
    <div className={`container ${shake ? 'shake' : ''}`}>
      <nav className="navbar">
        <span className="nav-title">Phishing Defender</span>
      </nav>
      
      <h1 className="title">Phishing Detection Tool</h1>
      <p className="subtitle">
        Protect yourself from phishing attempts. Enter a suspicious URL or paste email content 
        to analyze for potential threats.
      </p>
      
      
      <div className="sections">
        {/* URL Section */}
        <div className={getCardClass("url")}>
          <h2>Check a URL</h2>
          <input
            className="input-box"
            type="text"
            placeholder="Paste website URL here (e.g., example.com or https://example.com)..."
            value={urlInput}
            onChange={handleUrlInputChange}
            onFocus={handleUrlFocus}
            spellCheck="false"
          />
          {urlError && (
            <div className="error-message">{urlError}</div>
          )}
          <button 
            className={`predict-btn ${loadingUrl ? 'loading' : ''}`}
            onClick={handleUrlPredict} 
            disabled={loadingUrl || urlInput.trim() === "" || urlError !== ""}
          >
            {loadingUrl ? (
              <span className="loader"></span>
            ) : (
              "Analyze URL"
            )}
          </button>
          
          <div className="result-container">
            {urlResult && (
              <div className={`result-box ${urlResult.prediction_label && urlResult.prediction_label.toLowerCase() === "phishing" ? "phishing" : "safe"}`}>
                <div className="result-status">
                  {urlResult.prediction_label && urlResult.prediction_label.toLowerCase() === "phishing" ? "Not Safe - Phishing Detected" : "Safe"}
                </div>
                {/* Only show confidence score for phishing sites */}
                {urlResult.prediction_score !== undefined && 
                 urlResult.prediction_label && 
                 urlResult.prediction_label.toLowerCase() === "phishing" && (
                  <div className="score-info">
                    Confidence: {Math.round(urlResult.prediction_score)}%
                  </div>
                )}
              </div>
            )}
          </div>
        </div>

        {/* Text Section */}
        <div className={getCardClass("text")}>
          <h2>Check Email Content</h2>
          <textarea
            className="input-box"
            placeholder="Paste email content here (message body, subject, etc.)..."
            value={textInput}
            onChange={handleTextInputChange}
            onFocus={handleTextFocus}
            rows={4}
            spellCheck="false"
          ></textarea>
          {textError && (
            <div className="error-message">{textError}</div>
          )}
          <button 
            className={`predict-btn ${loadingText ? 'loading' : ''}`}
            onClick={handleTextPredict} 
            disabled={loadingText || textInput.trim() === "" || textError !== ""}
          >
            {loadingText ? (
              <span className="loader"></span>
            ) : (
              "Analyze Content"
            )}
          </button>
          
          <div className="result-container">
            {textResult && (
              <div className={`result-box ${textResult.prediction_label && textResult.prediction_label.toLowerCase() === "phishing" ? "phishing" : "safe"}`}>
                <div className="result-status">
                  {textResult.prediction_label && textResult.prediction_label.toLowerCase() === "phishing" ? "Not Safe - Phishing Detected" : "Safe"}
                </div>
                {/* Only show confidence score for phishing content */}
                {textResult.prediction_score !== undefined && 
                 textResult.prediction_label && 
                 textResult.prediction_label.toLowerCase() === "phishing" && (
                  <div className="score-info">
                    Confidence: {Math.round(textResult.prediction_score)}%
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      </div>
      
      <div className="footer">
        © {new Date().getFullYear()} Phishing Defender | AI-Powered Protection
      </div>
    </div>
  );
}