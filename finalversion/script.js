// ====================================================================
// SCRIPT.JS - CYBERDEFENDER PRO AI DEMO (FINAL CODE WITH ALL FEATURES & FIXES)
// ====================================================================

/**
 * Helper function called by the HTML tool menu to pre-fill the query box 
 * and immediately send the query, triggering the simulation logic in sendQuery().
 * @param {string} query - The tool command to execute.
 */
function selectTool(query) {
    const queryInput = document.getElementById('ai-query');
    if (queryInput) {
        queryInput.value = query; // Pre-fill the input
        sendQuery();              // Call the existing sendQuery function
    }
}
// --------------------------------------------------------------------------

document.addEventListener('DOMContentLoaded', () => {
    const sendButton = document.querySelector('.send-btn');
    const queryInput = document.getElementById('ai-query');

    if (sendButton) {
        sendButton.addEventListener('click', sendQuery);
    }
    
    if (queryInput) {
        queryInput.addEventListener('keypress', handleKeyPress);
    }

    const chatArea = document.getElementById('chat-area');
    if (chatArea) {
        const welcomeMsg = document.createElement('p');
        welcomeMsg.className = 'bot-message';
        welcomeMsg.textContent = 'AI (Ollama): Welcome to CyberDefender Pro! Ask me to analyze a tool result or a general security question.';
        chatArea.appendChild(welcomeMsg);
        chatArea.scrollTop = chatArea.scrollHeight;
    }
    
    // ATTACH THEME TOGGLE LISTENER
    document.getElementById('theme-toggle').addEventListener('click', toggleTheme);

    // Initial listener setup is now handled within generateDemoVulnerabilities
    // We keep this DOMContentLoaded listener for the main setup.
});

function handleKeyPress(event) {
    if (event.key === 'Enter') {
        event.preventDefault(); 
        sendQuery();
    }
}

// ====================================================================
// THEME TOGGLE FUNCTION (FIXED)
// ====================================================================
function toggleTheme() {
    document.body.classList.toggle('light-theme');
    const toggleButton = document.getElementById('theme-toggle');
    const isLightTheme = document.body.classList.contains('light-theme');
    
    // Update the button icon and text based on the current state
    if (isLightTheme) {
        toggleButton.innerHTML = '<i class="fas fa-moon"></i> Toggle Dark';
    } else {
        toggleButton.innerHTML = '<i class="fas fa-cog"></i> Toggle Theme'; 
    }
}

// ====================================================================
// DYNAMIC VULNERABILITY GENERATION (NEW FUNCTION)
// ====================================================================
function generateDemoVulnerabilities(domainIp) {
    const listWrapper = document.getElementById('vulnerability-summary-list');
    
    // Clear the existing list content
    listWrapper.innerHTML = '';
    
    // Define base list of vulnerabilities
    const vulnerabilities = [
        { title: "SQL Injection", severity: "high", tool: "ZAP/Burp Suite" },
        { title: "Cross-Site Scripting (XSS)", severity: "medium", tool: "ZAP/Acunetix" },
        { title: "Default Admin Credentials", severity: "high", tool: "Hydra/Nessus" },
        { title: "Missing Security Headers", severity: "low", tool: "ZAP/Burp Suite" },
        { title: "Weak SSH Ciphers", severity: "high", tool: "Nmap/OpenVAS" },
        { title: "Unrestricted File Upload", severity: "medium", tool: "Burp Suite" },
        { title: "Outdated Apache Server", severity: "medium", tool: "Nikto/Nessus" },
        { title: "Open FTP Port (Anon)", severity: "high", tool: "Nmap/Nessus" }
    ];

    // Determine the number of vulnerabilities to show (simulating varying results)
    // The number of findings will be between 5 and 9 based on domainIp length
    const hash = domainIp.length % 5; 
    const numVulnerabilities = 5 + hash;

    let htmlContent = '';
    
    for (let i = 0; i < numVulnerabilities; i++) {
        // Cycle through the base list to generate unique-looking results
        const vuln = vulnerabilities[i % vulnerabilities.length];
        
        // Generate a mock CVE ID based on the iteration
        const mockCve = `CVE-2024-MOCK-${String(100 + i).padStart(3, '0')}`;
        
        // Use a variant of the domain for the site name for realism
        const siteName = domainIp.replace(/\./g, '_') + (i % 3 === 0 ? '/login' : '/api');

        htmlContent += `
            <div class="vulnerability-item">
                <div class="details">
                    <h3 class="vuln-link" data-id="${mockCve}" style="cursor: pointer;">${vuln.title}</h3>
                    <span class="severity ${vuln.severity}">${vuln.severity.charAt(0).toUpperCase() + vuln.severity.slice(1)}</span> Severity
                </div>
                <div class="info">
                    <span class="site">${siteName}</span>
                    <span class="time">${vuln.tool}</span>
                </div>
            </div>
        `;
    }

    listWrapper.innerHTML = htmlContent;

    // Re-attach the click listener for the detailed view on the newly created elements
    document.querySelectorAll('.vuln-link').forEach(link => {
        link.addEventListener('click', function() {
            showVulnerabilityDetails(this.dataset.id, this.textContent);
        });
    });
    
    // Update the total count in the header
    const totalFindingsElement = document.querySelector('.results-card h3');
    if (totalFindingsElement) {
        totalFindingsElement.textContent = `Detailed Findings (Total: ${numVulnerabilities} for ${domainIp})`;
    }
}

// ====================================================================
// SCAN & REPORT FUNCTIONS (UPDATED)
// ====================================================================

function startScan() {
    const domainIpInput = document.getElementById('domain-ip');
    const domainIp = domainIpInput.value.trim();

    if (!domainIp) {
        alert("Please enter a domain or IP to start the scan.");
        return;
    }
    
    const scanStatus = document.querySelector('.scan-status');
    const scanPercentage = document.getElementById('scan-percentage');
    const progressBar = document.getElementById('scan-progress');
    const reportActionsWrapper = document.getElementById('report-actions-wrapper');
    const reportDetails = document.getElementById('report-details');

    // Reset UI
    scanStatus.textContent = `Scanning ${domainIp}...`;
    reportActionsWrapper.classList.add('hidden');
    reportDetails.style.display = 'none';

    // Start simulation
    let percentage = 0;
    const interval = setInterval(() => {
        percentage += 5;
        scanPercentage.textContent = percentage;
        progressBar.style.width = `${percentage}%`;

        if (percentage >= 100) {
            clearInterval(interval);
            scanStatus.textContent = `Scan Complete: ${domainIp}`;
            
            // Show the report action buttons
            reportActionsWrapper.classList.remove('hidden'); 
            
            // *** CRITICAL CALL: Generate dynamic findings ***
            generateDemoVulnerabilities(domainIp);
            
            // Add to history (inserting at the top)
            const historyCard = document.querySelector('.history-card');
            const newHistoryItem = document.createElement('div');
            newHistoryItem.className = 'history-item';
            newHistoryItem.innerHTML = `
                <span>${domainIp}</span>
                <span>Scan Completed</span>
                <span class="time">${new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })}</span>
            `;
            const firstHistoryItem = historyCard.querySelector('.history-item');
            if (firstHistoryItem) {
                // Insert before the oldest history item
                historyCard.insertBefore(newHistoryItem, firstHistoryItem);
            } else {
                 historyCard.appendChild(newHistoryItem);
            }
            
            alert(`Scan complete for ${domainIp}. Report is ready.`);
        }
    }, 100);
}

// Download button shows email modal
function downloadReport() {
    document.getElementById('email-modal').classList.remove('hidden');
}

// FIX: Changed file type from .pdf to .txt for a successful simulation download
function confirmDownload() {
    const emailInput = document.getElementById('email-for-report');
    const email = emailInput.value.trim();
    const domain = document.getElementById('domain-ip').value.trim() || 'target';

    document.getElementById('email-modal').classList.add('hidden');

    if (email && email.includes('@')) {
        alert(`Downloading simulated report for ${domain}. A copy will also be emailed to: ${email}.`);
    } else {
        alert(`Downloading simulated report for ${domain}.`);
    }

    // SIMULATION FIX: Change type to text/plain and extension to .txt
    const blob = new Blob(["SIMULATED REPORT\n\nSecurity Scan Report for " + domain + 
        "\n\n--- Findings ---\n\nReport downloaded successfully. This is a text simulation of a PDF document for technical demonstration purposes."], 
        {type: "text/plain"});
    
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `CyberDefender_Report_${domain}.txt`; // <-- CHANGED TO .TXT

    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    
    // Clear the modal input after use
    emailInput.value = '';
}

function emailReport() {
    // This button will now also use the email modal for consistency
    document.getElementById('email-modal').classList.remove('hidden');
    
    alert("Please enter an email in the pop-up. (The 'Confirm Download' button will simulate the final action).");
}

function showVulnerabilityDetails(cveId, title) {
    const reportDetails = document.getElementById('report-details');
    reportDetails.style.display = 'block';
    
    let detailsContent = `
        <h3>Detailed Report: ${title} (${cveId})</h3>
        <p><strong>Severity:</strong> <span style="color: var(--color-high);">Critical</span></p>
        <p><strong>Affected URL/Parameter:</strong> <code>https://target.com/api/v1/data?id=123'</code></p>
        <p><strong>Description:</strong> This vulnerability allows an attacker to manipulate SQL queries by injecting malicious strings into the application's input fields. This can lead to unauthorized data access, modification, or destruction.</p>
        <p><strong>Remediation:</strong> Implement **Parameterized Queries** (Prepared Statements) for all database interactions. Validate and sanitize all user input before passing it to the database query.</p>
        <p><strong>Tools Used to Confirm:</strong> ZAP Active Scan, Burp Suite Intruder.</p>
    `;

    if (title.includes('XSS')) {
        detailsContent = `
            <h3>Detailed Report: ${title} (${cveId})</h3>
            <p><strong>Severity:</strong> <span style="color: var(--color-medium);">Medium</span></p>
            <p><strong>Affected URL/Parameter:</strong> <code>https://target.com/search?q=<script>alert(1)</script></code></p>
            <p><strong>Description:</strong> A reflected Cross-Site Scripting (XSS) vulnerability was found, allowing an attacker to inject client-side scripts into web pages viewed by other users.</p>
            <p><strong>Remediation:</strong> **HTML-encode** all user-supplied data before rendering it in the HTML page. Also, implement a strong **Content Security Policy (CSP)** header.</p>
            <p><strong>Tools Used to Confirm:</strong> ZAP Active Scan, Acunetix.</p>
        `;
    }
    reportDetails.innerHTML = detailsContent;
    reportDetails.scrollIntoView({ behavior: 'smooth' });
}


function showTechStackFinder() {
    document.getElementById('tech-stack-modal').classList.remove('hidden');
    document.getElementById('tech-stack-results').innerHTML = '<p>Results will appear here...</p>';
}

function closeModal(event, modalId) {
    // Only close if the background overlay was clicked OR if called without an event
    if (!event || (event && event.target.id === modalId)) {
        document.getElementById(modalId).classList.add('hidden');
    }
}

async function findTechStack() {
    const appName = document.getElementById('tech-stack-input').value.trim();
    const resultsArea = document.getElementById('tech-stack-results');

    if (!appName) {
        resultsArea.innerHTML = '<p style="color: var(--color-high);">Please enter a name or URL.</p>';
        return;
    }

    resultsArea.innerHTML = '<p>Searching popular technology databases...<i class="fas fa-spinner fa-spin"></i></p>';

    await new Promise(resolve => setTimeout(resolve, 1500)); 

    let stack = '';
    const nameLower = appName.toLowerCase();

    if (nameLower.includes('google') || nameLower.includes('youtube')) {
        stack = `
            <h4><i class="fab fa-google"></i> Google/YouTube Estimated Stack</h4>
            <p><strong>Frontend:</strong> Custom JavaScript, Polymer/LitElement, WebAssembly (WASM).</p>
            <p><strong>Backend:</strong> C++, Java, Python (internal), Go (new services).</p>
            <p><strong>Database:</strong> Bigtable, Spanner (Proprietary distributed systems).</p>
            <p><strong>Infrastructure:</strong> Google Cloud Platform (GCP) running on custom hardware/Borg.</p>
        `;
    } else if (nameLower.includes('amazon') || nameLower.includes('aws')) {
        stack = `
            <h4><i class="fab fa-amazon"></i> Amazon Estimated Stack</h4>
            <p><strong>Frontend:</strong> JavaScript, React/Next.js, Custom A-Z UI framework.</p>
            <p><strong>Backend:</strong> Java, C++, Go, Ruby on Rails (legacy/specific teams).</p>
            <p><strong>Database:</strong> DynamoDB, Aurora (PostgreSQL/MySQL), S3/Glacier.</p>
            <p><strong>Infrastructure:</strong> Amazon Web Services (AWS), custom kernel optimization.</p>
        `;
    } else if (nameLower.includes('microsoft') || nameLower.includes('azure')) {
        stack = `
            <h4><i class="fab fa-windows"></i> Microsoft/Azure Estimated Stack</h4>
            <p><strong>Frontend:</strong> TypeScript, React, Vue.js, ASP.NET (Blazor).</p>
            <p><strong>Backend:</strong> C#, .NET Core, PowerShell, Java.</p>
            <p><strong>Database:</strong> Azure SQL Database, Azure Cosmos DB, MS SQL Server.</p>
            <p><strong>Infrastructure:</strong> Azure Cloud, Windows Server, Linux (increasingly).</p>
        `;
    } else if (nameLower.includes('facebook') || nameLower.includes('meta')) {
        stack = `
            <h4><i class="fab fa-facebook"></i> Meta/Facebook Estimated Stack</h4>
            <p><strong>Frontend:</strong> React/React Native, GraphQL (Relay), Flow (Type Checker).</p>
            <p><strong>Backend:</strong> Hack (PHP variant), C++, Python.</p>
            <p><strong>Database:</strong> MyRocks, Memcached, ZippyDB.</p>
            <p><strong>Infrastructure:</strong> Custom Linux distribution, massive internal data centers.</p>
        `;
    } else if (nameLower.includes('openai') || nameLower.includes('chatgpt')) {
        stack = `
            <h4><i class="fas fa-robot"></i> OpenAI/ChatGPT Estimated Stack</h4>
            <p><strong>Frontend:</strong> React/Next.js, TypeScript.</p>
            <p><strong>Backend:</strong> Python, Go, Node.js.</p>
            <p><strong>Database:</strong> Various NoSQL/Vector Databases for large models (e.g., Pinecone/Weaviate).</p>
            <p><strong>Infrastructure:</strong> Microsoft Azure, large-scale GPU clusters.</p>
        `;
    } else {
        stack = `
            <h4><i class="fas fa-exclamation-circle"></i> Tech Stack Analysis Failed</h4>
            <p>The system was unable to identify a known stack for **${appName}**. </p>
            <p>Often, small or internal applications use generic combinations like:</p>
            <ul>
                <li><strong>LAMP:</strong> Linux, Apache, MySQL, PHP</li>
                <li><strong>MERN:</strong> MongoDB, Express, React, Node.js</li>
                <li><strong>Django/Python:</strong> Python backend with PostgreSQL.</li>
            </ul>
        `;
    }

    resultsArea.innerHTML = stack;
}


// ====================================================================
// CORE AI BOT LOGIC (Tool Simulation and NEW Features)
// ====================================================================

async function sendQuery() {
    const queryInput = document.getElementById('ai-query');
    const chatArea = document.getElementById('chat-area');
    const queryText = queryInput.value.trim();
    const queryLower = queryText.toLowerCase();

    if (queryText === "") { return; }

    const userMsg = document.createElement('p');
    userMsg.className = 'user-message'; 
    userMsg.textContent = queryText;
    chatArea.appendChild(userMsg);

    queryInput.value = ''; 
    
    const botMsg = document.createElement('p');
    botMsg.className = 'bot-message';
    botMsg.textContent = '...Thinking...';
    chatArea.appendChild(botMsg);
    chatArea.scrollTop = chatArea.scrollHeight;

    let response = null;
    let isToolResponse = false;
    
    // --- TOOL SIMULATION LOGIC ---

    // NMAP Logic 
    if (queryLower.includes('nmap') && (queryLower.includes('scan') || queryLower.includes('-sS'))) {
        isToolResponse = true;
        if (queryLower.includes('weeanovtainout.com')) {
            response = "AI: **Nmap Scan for WeeAnovtainout.com**: Port 80 (HTTP) Open, Port 443 (HTTPS) Open. *Critical Finding: Open port 80 detected, confirming an easy attack vector for vulnerability CVE-2023-MOCK-001 (SQL Injection).*";
        } else if (queryLower.includes('server-01.cloud')) {
            response = "AI: **Nmap Scan for server-01.cloud**: Port 22 (SSH) OPEN - Service Scan detected outdated SSH Ciphers (`3des-cbc`). This confirms vulnerability **CVE-2023-MOCK-006 (Weak SSH Ciphers)**.";
        } else {
            response = "AI: **Nmap SYN Scan (-sS) Simulation**: Target 192.168.1.1. Results: Port **22 (SSH) OPEN**, Port **80 (HTTP) OPEN**, Port **443 (HTTPS) OPEN**, Port 3389 (RDP) Filtered. This data is pulled directly from the scan output.";
        }
    } 
    
    // BURP SUITE / ZAP Logic
    else if (queryLower.includes('burp') || queryLower.includes('intercept') || queryLower.includes('zap')) {
        isToolResponse = true;
        if (queryLower.includes('aponvstept.com')) {
            response = "AI: **Burp Suite Active Scan for AponVStept.com**: Found a Reflected XSS vulnerability in the comment submission form parameter. Remediation: Apply **HTML-encoding** to user output to prevent **CVE-2023-MOCK-002**.";
        } else if (queryLower.includes('api.service/users/')) {
            response = "AI: **Burp Intruder for API.service/users/**: Successfully iterated User ID parameter from 123 to 124 without re-authentication. This confirms **CVE-2023-MOCK-004 (IDOR)**.";
        } else {
            response = "AI: **Burp Suite Proxy Simulation**: Intercepting request to `/login`. Found a security issue: Weak Cookie Attribute (**Missing Secure Flag**). Recommendation: Set the `Secure` and `HttpOnly` flags on all session cookies.";
        }
    }
    
    // KALI TOOL: JOHN THE RIPPER / HASHCAT 
    else if (queryLower.includes('john') || queryLower.includes('hashcat') || queryLower.includes('crack password') || queryLower.includes('ntlm') || queryLower.includes('hash')) {
        isToolResponse = true;
        if (queryLower.includes('bcrypt')) {
            response = "AI: **Hashcat Simulation**: Running a hybrid attack against **100,000 Bcrypt hashes** (mode 3200). *Result: **5** weak passwords cracked, including `admin:p@ssword1`. Recommendation: Migrate to Argon2 or Scrypt and enforce a password policy of 15+ characters.*";
        } else if (queryLower.includes('ntlm')) {
            response = "AI: **John the Ripper Simulation**: Running a rule-based attack on **NTLM hashes** from a Domain Controller dump. *Result: Successfully cracked **90%** of NTLM hashes in 3 minutes. Finding: Most users use dictionary words. Critical Action: Enable MFA and perform an immediate domain-wide password reset.*";
        } else {
            response = "AI: **Password Cracking Simulation (John/Hashcat)**: Analysis shows the majority of leaked hashes use the insecure **MD5** algorithm. *Critical Finding: Cracking 80% of the sample took less than 1 second. Recommendation: Salt and hash credentials using modern, slow algorithms like Scrypt or Argon2.*";
        }
    }
    
    // KALI TOOL: HYDRA / MEDUSA (Brute Force)
    else if (queryLower.includes('hydra') || queryLower.includes('medusa') || queryLower.includes('brute force') || queryLower.includes('credentials')) {
        isToolResponse = true;
        if (queryLower.includes('ssh') || queryLower.includes('server-20')) {
            response = "AI: **Hydra Brute Force Simulation (Target: SSH)**: Running a credential stuffing attack using a large list of common passwords against `server-20.internal`. *Result: Login successful using `root:summer2024`. This confirms vulnerability CVE-2023-MOCK-003 (Weak Default Credentials). Mitigation: Implement strong password policies and immediate account lockouts after 3 failed attempts.*";
        } else {
            response = "AI: **Hydra Brute Force Simulation**: Target generic login service. *Result: Login successful using a commonly used password list: `user:admin123`. Critical action: Enforce Multi-Factor Authentication (MFA) on all user accounts immediately.* ";
        }
    }
    
    // NEW FEATURE 1: KALI TOOL: AIRCRACK-NG / KISMET (Wireless Attacks)
    else if (queryLower.includes('aircrack') || queryLower.includes('wireless') || queryLower.includes('wpa') || queryLower.includes('kismet')) {
        isToolResponse = true;
        if (queryLower.includes('wpa2') || queryLower.includes('network')) {
            response = "AI: **Aircrack-ng Simulation (WPA2)**: Captured handshake for 'Guest_WiFi_HQ' and successfully cracked the password: **`Summer2025!`**. *Critical action: Change the WiFi password to a complex, non-dictionary phrase and enforce WPA3.*";
        } else if (queryLower.includes('rogue ap') || queryLower.includes('kismet')) {
            response = "AI: **Kismet Scan (Rogue AP)**: Detected a **Rogue Access Point** disguised as 'Corp_Internal_VPN' connected to the internal network. *Alert: This is a Man-in-the-Middle (MITM) threat. Action: Physically locate and disconnect the rogue device immediately.*";
        } else {
            response = "AI: **Wireless Attack Simulation**: Running a deauthentication attack to capture a WPA handshake. *Result: Handshake captured. Cracking attempts are underway using a dictionary attack. Mitigation: Segment your wireless network and monitor for deauth packets.*";
        }
    }
    
    // NEW FEATURE 2: KALI TOOL: GHIDRA / IDA PRO (Reverse Engineering / Code Analysis)
    else if (queryLower.includes('ghidra') || queryLower.includes('ida pro') || queryLower.includes('code analysis') || queryLower.includes('reverse engineering')) {
        isToolResponse = true;
        if (queryLower.includes('malware') || queryLower.includes('binary file')) {
            response = "AI: **Ghidra Reverse Engineering Simulation**: Analysis of `malware_injector.exe` revealed a hardcoded decryption key **`K3y-4utH-9876`** used for command-and-control (C2) communication. *Action: Use this key to monitor and disrupt C2 traffic.*";
        } else if (queryLower.includes('firmware')) {
            response = "AI: **IDA Pro Firmware Analysis**: Disassembly of router firmware `v1.2.3` shows an unpatched **Buffer Overflow** vulnerability (CVE-2023-MOCK-016) in the configuration parsing function. *Action: Immediately halt deployment of this firmware version and issue a patch.*";
        } else {
            response = "AI: **Code Analysis Simulation**: Decompiling a financial application DLL. *Result: Found poor exception handling that exposes stack trace information, increasing the risk of memory corruption exploits. Fix: Implement structured exception handling (SEH) and strip debug symbols.*";
        }
    }

    // WIRESHARK / TSHARK Logic
    else if (queryLower.includes('wireshark') || queryLower.includes('tshark') || queryLower.includes('packet capture')) {
        isToolResponse = true;
        response = "AI: **Wireshark Analysis Simulation**: Detected clear-text credentials being sent via FTP (Port 21) from 10.1.1.5. *Recommendation: Immediately disable FTP and migrate to SFTP/FTPS to prevent data leakage (MITM risk).*";
    }

    // METASPLOIT Logic
    else if (queryLower.includes('metasploit') || queryLower.includes('exploit') || queryLower.includes('shell')) {
        isToolResponse = true;
        response = "AI: **Metasploit Simulation**: Ran the `exploit/multi/handler` module against the target `192.168.1.10`. *Result: Successfully established a reverse shell (Meterpreter session 1 opened). Critical action required: Patch the service immediately!*";
    }
    
    // HONEYPOT / IDS / IPS Logic
    else if (queryLower.includes('honeypot') || queryLower.includes('ids alert') || queryLower.includes('ips block')) {
        isToolResponse = true;
        response = "AI: **IDS Alert Simulation**: An alert was generated on the login page by the **Snort Rule ID 1:2345** - `Attempted SQL Injection (UNION SELECT) detected from IP 10.0.0.5`. *Action taken: IPS has successfully blocked the source IP for 60 minutes.*";
    }

    // --- STATIC VULNERABILITY & GENERAL RULES (if no tool triggered) ---
    if (!isToolResponse) {
        if (queryLower.includes('xss')) {
            response = "AI: To fix XSS, ensure all user-provided input is properly **sanitized** or **escaped** before rendering it in the HTML page. Always validate input on the server side.";
        } else if (queryLower.includes('sql')) {
            response = "AI: The best defense against SQL Injection is using **Parameterized Queries** (Prepared Statements) in your backend code. This separates code from data.";
        } 
        // NEW FEATURE 3: PHISHING/SOCIAL ENGINEERING ADVICE
        else if (queryLower.includes('phishing') || queryLower.includes('social engineering') || queryLower.includes('spear phishing')) {
            response = "AI: **Social Engineering Defense**: The best defense against phishing is employee training. Implement mock phishing campaigns, enforce **MFA** on all services, and use domain monitoring tools to spot lookalike domains targeting your staff.";
        }
        else if (queryLower.includes('hello')) {
            response = "AI: Hello there! How can I assist you with CyberDefender Pro today?";
        } else {
            response = "AI: I'm not familiar with that tool or concept yet. Try asking me about 'SQL' fixes, 'XSS' protection, or simulate a tool like 'Nmap scan for server-01.cloud'.";
        }
    }


    // Replace the thinking message with the actual response
    const finalBotMsg = chatArea.lastElementChild;
    if (finalBotMsg && finalBotMsg.textContent === '...Thinking...') {
        finalBotMsg.textContent = response;
    } else {
        // Fallback in case the thinking message wasn't the last element
        const newBotMsg = document.createElement('p');
        newBotMsg.className = 'bot-message';
        newBotMsg.textContent = response;
        chatArea.appendChild(newBotMsg);
    }

    chatArea.scrollTop = chatArea.scrollHeight;
}