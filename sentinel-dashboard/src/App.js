import { useState } from "react";

function App() {
  const [url, setUrl] = useState("");
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const analyze = async () => {
    if (!url) {
      setError("Please enter a URL");
      return;
    }

    setLoading(true);
    setError(null);
    setData(null);

    try {
      const response = await fetch(`/analyze?url=${url}`);
      const result = await response.json();

      if (!response.ok) {
        throw new Error(result.error || "Something went wrong");
      }

      setData(result);
    } catch (err) {
      setError(err.message);
    }

    setLoading(false);
  };

  const getRiskColor = (level) => {
    if (level === "Low") return "green";
    if (level === "Medium") return "orange";
    if (level === "High") return "red";
    return "black";
  };

  return (
    <div
      style={{
        padding: "40px",
        fontFamily: "Arial",
        backgroundColor: "#f4f6f8",
        minHeight: "100vh",
      }}
    >
      <h1 style={{ marginBottom: "20px" }}>
        🛡 SentinelScrape Security Dashboard
      </h1>

      <div style={{ marginBottom: "20px" }}>
        <input
          type="text"
          placeholder="Enter URL (https://example.com)"
          value={url}
          onChange={(e) => setUrl(e.target.value)}
          style={{
            width: "350px",
            padding: "10px",
            borderRadius: "5px",
            border: "1px solid #ccc",
          }}
        />

        <button
          onClick={analyze}
          style={{
            marginLeft: "10px",
            padding: "10px 15px",
            borderRadius: "5px",
            border: "none",
            backgroundColor: "#007bff",
            color: "white",
            cursor: "pointer",
          }}
        >
          Analyze
        </button>
      </div>

      {loading && <p>🔍 Analyzing security risks...</p>}

      {error && (
        <p style={{ color: "red", fontWeight: "bold" }}>
          Error: {error}
        </p>
      )}

      {data && (
        <div
          style={{
            backgroundColor: "white",
            padding: "20px",
            borderRadius: "10px",
            boxShadow: "0 4px 10px rgba(0,0,0,0.1)",
          }}
        >
          <h2>Page Title: {data.title}</h2>

          <h3
            style={{
              color: getRiskColor(data.security_analysis.risk_level),
            }}
          >
            Risk Level: {data.security_analysis.risk_level}
          </h3>

          <h4>
            Risk Score: {data.security_analysis.risk_score}
          </h4>

          <hr />

          <p><strong>Forms Detected:</strong> {data.forms}</p>
          <p><strong>Total Links:</strong> {data.links.length}</p>
          <p><strong>Total Headings:</strong> {data.headings.length}</p>

          <hr />

          {data.security_analysis.inline_scripts && (
            <p>
              <strong>Inline Scripts:</strong>{" "}
              {data.security_analysis.inline_scripts}
            </p>
          )}

          {data.security_analysis.external_scripts_from_other_domains && (
            <div>
              <h3>⚠ Suspicious External Scripts</h3>
              <ul>
                {data.security_analysis.external_scripts_from_other_domains.map(
                  (script, index) => (
                    <li key={index}>{script}</li>
                  )
                )}
              </ul>
            </div>
          )}

          {data.security_analysis.suspicious_keywords && (
            <div>
              <h3>🚨 Suspicious Keywords Found</h3>
              <ul>
                {data.security_analysis.suspicious_keywords.map(
                  (keyword, index) => (
                    <li key={index}>{keyword}</li>
                  )
                )}
              </ul>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default App;