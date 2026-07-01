import base64
import os

# ----------------------------------------------------------------------
# Inline SVG avatar (base64) used if photo.jpg is missing.
# It's a simple person silhouette.
SVG_AVATAR = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">
  <circle cx="50" cy="35" r="25" fill="#b0bec5"/>
  <path d="M20,90 Q20,60 50,60 Q80,60 80,90 Z" fill="#b0bec5"/>
</svg>'''
SVG_BASE64 = base64.b64encode(SVG_AVATAR.encode()).decode()
PLACEHOLDER_IMG = f"data:image/svg+xml;base64,{SVG_BASE64}"

# Use the real photo if it exists
PHOTO_FILE = "photo.jpg"
if os.path.exists(PHOTO_FILE):
    with open(PHOTO_FILE, "rb") as f:
        img_data = base64.b64encode(f.read()).decode()
        # Assume jpeg; you may adjust mime type if png
        IMG_SRC = f"data:image/jpeg;base64,{img_data}"
else:
    IMG_SRC = PLACEHOLDER_IMG
    print(f"Warning: '{PHOTO_FILE}' not found. Using placeholder avatar.")

# ----------------------------------------------------------------------
HTML_TEMPLATE = f"""
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Deep Packet Inspection – Mohammed Waseem Siddique</title>
<style>
  body {{
    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    background: linear-gradient(135deg, #1e1e2f 0%, #2d2d44 100%);
    color: #e0e0e0;
    margin: 0;
    padding: 2rem;
  }}
  .container {{
    max-width: 960px;
    margin: auto;
    background: rgba(255,255,255,0.05);
    backdrop-filter: blur(10px);
    border-radius: 20px;
    padding: 2rem;
    box-shadow: 0 20px 40px rgba(0,0,0,0.5);
  }}
  .header {{
    display: flex;
    align-items: center;
    gap: 2rem;
    border-bottom: 2px solid #00bcd4;
    padding-bottom: 1.5rem;
  }}
  .photo img {{
    width: 120px;
    height: 120px;
    border-radius: 50%;
    object-fit: cover;
    border: 4px solid #00bcd4;
    box-shadow: 0 0 20px #00bcd4;
  }}
  .name-title h1 {{
    margin: 0;
    font-size: 2.5rem;
    color: #ffffff;
  }}
  .name-title h1 span {{
    color: #00bcd4;
  }}
  .name-title p {{
    margin: 0.5rem 0 0;
    font-size: 1.2rem;
    color: #b0bec5;
  }}
  .section {{
    margin: 2rem 0;
  }}
  .section h2 {{
    color: #00bcd4;
    border-left: 4px solid #00bcd4;
    padding-left: 1rem;
  }}
  .tech-list {{
    display: flex;
    flex-wrap: wrap;
    gap: 0.5rem;
    list-style: none;
    padding: 0;
  }}
  .tech-list li {{
    background: #00bcd422;
    border: 1px solid #00bcd4;
    padding: 0.4rem 1rem;
    border-radius: 20px;
    font-weight: bold;
  }}
  .pitch {{
    background: #00bcd411;
    padding: 1.5rem;
    border-radius: 12px;
    border: 1px solid #00bcd4;
    font-size: 1.2rem;
  }}
  .footer {{
    margin-top: 3rem;
    text-align: center;
    color: #888;
  }}
</style>
</head>
<body>
<div class="container">
  <div class="header">
    <div class="photo">
      <img src="{IMG_SRC}" alt="Mohammed Waseem Siddique">
    </div>
    <div class="name-title">
      <h1> <span>Mohammed Waseem Siddique</span></h1>
      <p>Computer Science Student and Cybersecurity Enthusiast</p>
    </div>
  </div>

  <div class="section">
    <h2>Project: Deep Packet Inspection Engine</h2>
    <p>
      A real‑time network traffic analyser capable of <strong>live packet capture</strong> and
      <strong>offline PCAP forensics</strong>. It identifies application‑layer protocols 
      (HTTP, DNS, TLS/SNI, SSH, FTP) and performs <strong>signature‑based threat detection</strong>
      to spot malware, reverse shells, SQLi, XSS, and other suspicious activity.
      All findings are logged to a structured CSV report.
    </p>
  </div>

  <div class="section">
    <h2>Key Features</h2>
    <ul>
      <li>Live sniffing on any interface or analysis of pre‑recorded PCAP files</li>
      <li>Deep protocol parsing – HTTP requests/responses, DNS queries, TLS SNI extraction</li>
      <li>Signature engine with 6+ threat signatures (RCE, injection, C2 patterns)</li>
      <li>Clean CSV logging with severity levels</li>
      <li>Modular, production‑ready OOP architecture</li>
      <li>Cross‑platform (Linux, Windows with Npcap)</li>
    </ul>
  </div>

  <div class="section">
    <h2>Technology Stack</h2>
    <ul class="tech-list">
      <li>Python 3</li><li>Scapy</li><li>PCAP Analysis</li>
      <li>Regex Signature Matching</li><li>CSV Reporting</li>
      <li>TCP/IP Stack</li>
    </ul>
  </div>

  <div class="section pitch">
    <strong>Developed by Mohammed Waseem Siddique – Open to impactful opportunities</strong><br>
    I am ready to invest my time and skills into more challenging projects and real‑world 
    opportunities in network security, backend engineering, and system design. 
    Let’s connect and build something that matters.
  </div>

  <div class="footer">
    © 2026 Mohammed Waseem Siddique | Deep Packet Inspection Project
  </div>
</div>
</body>
</html>
"""

with open("project_overview.html", "w", encoding="utf-8") as f:
    f.write(HTML_TEMPLATE)

print("✅ project_overview.html generated successfully!")
print("   Place your photo as 'photo.jpg' next to the script and re-run for personalisation.")
