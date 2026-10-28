

    const socket = io.connect('http://' + document.domain + ':' + location.port);
    //var socket = io.connect("http://127.0.0.1:5000");



    socket.on("connect", () => {
        console.log("Connected to WebSocket server!");
    });

    socket.on("disconnect", () => {
        console.log("Disconnected from WebSocket server!");
    });

    function updateNetworkStatus(isConnected) {
        const statusElement = document.getElementById("networkStatus");
        statusElement.textContent = isConnected ? "Network: Connected" : "Network: Disconnected";
        statusElement.style.color = isConnected ? "green" : "red";
    }

    window.addEventListener("online", () => updateNetworkStatus(true));
    window.addEventListener("offline", () => updateNetworkStatus(false));
    updateNetworkStatus(navigator.onLine);
    
    // Toggle Capture Button
    const toggleCaptureButton = document.getElementById('toggleCapture');
    let capturing = false;
    
    toggleCaptureButton.addEventListener('click', function() {
        capturing = !capturing;
        toggleCaptureButton.classList.toggle('off');
        toggleCaptureButton.textContent = capturing ? 'Stop' : 'Start';
        const action = capturing ? 'start_capture' : 'stop_capture';
        socket.emit(action, { data: capturing });
    });

    // Traffic Trend Chart
    const trafficChart = new Chart(document.getElementById('trafficTrendChart').getContext('2d'), {
        type: 'line',
        data: { labels: [], datasets: [{ label: 'Traffic Volume', data: [], borderColor: 'blue' }] },
    });

    // Protocol Distribution Chart
    const protocolChart = new Chart(document.getElementById('protocolDistributionChart').getContext('2d'), {
        type: 'doughnut',
        data: { labels: [], datasets: [{ data: [], backgroundColor: [] }] },
    });

    
    function toggleTrafficBlocking() {
        const table = document.getElementById("trafficBlockingTable");
        table.style.display = table.style.display === "none" ? "table" : "none";
    }

    // Attack Type Chart
    //const attackChart = new Chart(document.getElementById('attackTypeChart').getContext('2d'), {
      //  type: 'bar',
        //data: { labels: [], datasets: [{ data: [], backgroundColor: [] }] },
    //});

     // Attack Types Chart
     const attackChart = new Chart(document.getElementById("attackTypeChart").getContext("2d"), {
        type: "bar",
        data: { labels: [], datasets: [{ label: "Number of Attacks", data: [], backgroundColor: [] }] },
        options: { responsive: true, maintainAspectRatio: true, scales: { y: { beginAtZero: true } } }
    });

    // Function to Update Attack Chart Dynamically
    function updateAttackChart(attackData) {
        attackChart.data.labels = attackData.labels;
        attackChart.data.datasets[0].data = attackData.data;
        attackChart.data.datasets[0].backgroundColor = attackData.colors;
        attackChart.update(); // Refresh Chart
    }

    // Function to update chart dynamically
    function updateAttackChart(attackData) {
        attackChart.data.labels = attackData.labels;
        attackChart.data.datasets[0].data = attackData.data;
        attackChart.data.datasets[0].backgroundColor = attackData.colors;
        attackChart.update();
    }

    // Attack Severity Chart
    const severityChart = new Chart(document.getElementById('attackSeverityChart').getContext('2d'), {
        type: "pie",
        data: { labels: ["Critical", "High", "Medium", "Low"], datasets: [{ data: [0, 0, 0, 0], backgroundColor: ["red", "orange", "yellow", "blue"] }] },
    });

    function updateSeverityChart(severity) {
        const severityMapping = { "Critical": 0, "High": 1, "Medium": 2, "Low": 3 };
        severityChart.data.datasets[0].data[severityMapping[severity]]++;
        severityChart.update();
    }
// Function to update Traffic Trend Chart every 5 minutes
function updateTrafficChart(trafficVolume) {
    const now = new Date();
    const timeLabel = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });

    // Add new data point every 5 minutes
    if (trafficChart.data.labels.length === 0 || new Date().getMinutes() % 5 === 0) {
        trafficChart.data.labels.push(timeLabel);
        trafficChart.data.datasets[0].data.push(trafficVolume);

        // Keep only last 12 data points (1-hour window)
        if (trafficChart.data.labels.length > 12) {
            trafficChart.data.labels.shift();
            trafficChart.data.datasets[0].data.shift();
        }

        trafficChart.update();
    }
}

    socket.on('update', function(data) {
        const newRow = `<tr><td>${new Date().toLocaleString()}</td><td>${data.source}</td><td>${data.destination}</td><td>${data.protocol}</td><td>${Math.floor(Math.random() * 1000)} KB</td><td>Normal</td></tr>`;
        document.getElementById('networkTrafficTable').innerHTML += newRow;
        
        trafficChart.data.labels.push(new Date().toLocaleTimeString());
        trafficChart.data.datasets[0].data.push(Math.floor(Math.random() * 1000));
        trafficChart.update();

        let protocolIndex = protocolChart.data.labels.indexOf(data.protocol);
        if (protocolIndex === -1) {
            protocolChart.data.labels.push(data.protocol);
            protocolChart.data.datasets[0].data.push(1);
            protocolChart.data.datasets[0].backgroundColor.push(`hsl(${Math.random() * 360}, 70%, 50%)`);
        } else {
            protocolChart.data.datasets[0].data[protocolIndex]++;
        }
        protocolChart.update();
    });

    const attackColors = { 
    "DDoS": "#FF5733", 
    "Malware": "#33FF57", 
    "Phishing": "#3357FF",
    "SQL Injection": "#FF33A8",
    "Brute Force": "#A833FF"
};

// Handle incoming attack alerts and update UI dynamically
socket.on("alert", function (data) {
    console.log("📢 Received attack alert:", data);

    // Append vulnerability alert to the frontend UI
    document.getElementById("vulnerabilityAlerts").innerHTML += 
        `<div class="alert-${data.severity.toLowerCase()}">
           <strong>${data.type}</strong> from IP: ${data.source_ip} - Severity: ${data.severity}-Time: ${data.Time}
        </div>`;

    let attackIndex = attackChart.data.labels.indexOf(data.type); // Check if attack type already exists

    if (attackIndex === -1) {
        // If new attack type, add it
        attackChart.data.labels.push(data.type);
        attackChart.data.datasets[0].data.push(1);
        
        // Assign a predefined color or generate a random one
        attackChart.data.datasets[0].backgroundColor.push(
            attackColors[data.type] || `hsl(${Math.random() * 360}, 70%, 50%)`
        ); 
    } else {
        // If attack type exists, increase count
        attackChart.data.datasets[0].data[attackIndex]++;
    }

    attackChart.update(); // Refresh the chart
    updateSeverityChart(data.severity); // Ensure severity chart updates
});


// Set to track permanently blocked IPs
let permanentlyBlockedIPs = new Set();

// Handle traffic blocking updates and dynamically update the Traffic Blocking table
socket.on('traffic_blocking_update', function(data) {
    console.log("🚦 Traffic Block received:", data);
    
    var table = document.getElementById("trafficBlockingTable").getElementsByTagName('tbody')[0];
    var newRow = table.insertRow();

    var timeCell = newRow.insertCell(0);
    var sourceIPCell = newRow.insertCell(1);
    var problemCell = newRow.insertCell(2);
    var severityCell = newRow.insertCell(3);
    var actionCell = newRow.insertCell(4);

    timeCell.innerHTML = data.Time;
    sourceIPCell.innerHTML = data.source_ip;
    problemCell.innerHTML = data.problem;
    severityCell.innerHTML = data.severity;

    // ✅ Create "Permanent Block" button only if the IP is not already blocked
    if (!permanentlyBlockedIPs.has(data.source_ip)) {
        let permBlockBtn = document.createElement("button");
        permBlockBtn.innerHTML = "Permanent Block";
        permBlockBtn.classList.add("btn", "btn-danger");

        permBlockBtn.onclick = function() {
            permanentlyBlockIP(data.source_ip);
            permanentlyBlockedIPs.add(data.source_ip); // Add to Set
            permBlockBtn.remove();  // Remove button, not the row
        };

        actionCell.appendChild(permBlockBtn);
    }
});

// Update Blocked IPs dynamically
socket.on("update_blocked_ips", function(data) {
    console.log("Received Blocked Traffic Data:", data);
    if (!data) {
        console.error("No blocked traffic data received!");
        return;
    }

    updateBlockedTraffic(data.temporary, data.permanent);
});

// Function to update blocked traffic tables dynamically
function updateBlockedTraffic(temporary, permanent) {
    let tempTable = document.getElementById("temporary-block-table");
    let permTable = document.getElementById("permanent-block-table");

    // Clear tables before updating
    tempTable.innerHTML = "";
    permTable.innerHTML = "";

    temporary.forEach(ip => {
        let row = `<tr><td>${ip}</td><td>Temporary</td></tr>`;
        tempTable.innerHTML += row;
    });

    permanent.forEach(ip => {
        let row = `<tr><td>${ip}</td><td>Permanent</td></tr>`;
        permTable.innerHTML += row;
        permanentlyBlockedIPs.add(ip); // ✅ Ensure Set is updated
    });
}

// Emit event for permanent block
document.getElementById("permanentBlockBtn").addEventListener("click", function () {
    let ipToBlock = getSelectedIP();  // Ensure this function exists!
    if (ipToBlock) {
        socket.emit("permanent_block", { ip: ipToBlock });
    } else {
        console.warn("No IP selected for blocking.");
    }
});

// Receive updates on traffic blocking and update UI
socket.on("update_traffic_blocking", function (data) {
    console.log("Received blocking update:", data);
    addBlockedIPToTable(data.ip, data.status);
});

// Function to send permanent block request
// Function to send permanent block request
function permanentlyBlockIP(ip, attackType) {  // Ensure attackType is passed
    fetch('/permanent_block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip, final_attack_type: attackType })  // Use attackType correctly
    })
    .then(response => response.json())
    .then(data => console.log("Permanent Block Response:", data))
    .catch(error => console.error('Error:', error));
}

// Ensure the permanent block button uses the correct function
document.querySelectorAll('.perm-block-btn').forEach(button => {
    button.addEventListener('click', function() {
        let ip = this.getAttribute('data-ip');
        let attackType = "Unknown"; // You need to fetch the actual attack type dynamically if available
        permanentlyBlockIP(ip, attackType);
    });
});


// Show traffic blocking section on header click
document.getElementById("trafficBlockingHeader").addEventListener("click", function(event) {
    event.preventDefault();
    document.getElementById("trafficBlockingSection").style.display = "block";
});


// Update Blocked Traffic Sections
function updateBlockedTraffic(temporary, permanent) {
    updateBlockedIPs("temporary", temporary);
    updateBlockedIPs("permanent", permanent);
}

// Populate Blocked IP Tables
function updateBlockedIPs(type, ips) {
    const tableBody = document.getElementById(`${type}BlockedTable`);

    if (!tableBody) {
        console.error(`Table for ${type} not found!`);
        return;
    }

    tableBody.innerHTML = ''; // Clear table before updating

    if (!ips || ips.length === 0) {
        tableBody.innerHTML = '<tr><td colspan="4" class="text-center">No data available</td></tr>';
        return;
    }

    ips.forEach(ipData => {
        let row = document.createElement('tr');

        if (type === "temporary") {
            row.innerHTML = `
                <td>${ipData.time}</td>
                <td>${ipData.ip}</td>
                <td>${ipData.reason || 'N/A'}</td>
                <td>${ipData.count || 1}</td>
                
            `;
        } else if (type === "permanent") {
            row.innerHTML = `
                <td>${ipData.time}</td>
                <td>${ipData.ip}</td>
                <td>${ipData.reason || 'N/A'}</td>
                <td>${ipData.count || 3}</td>
                
            `;
        }
        tableBody.appendChild(row);
    });

    attachEventListeners();
}

// Attach Event Listeners for Buttons
function attachEventListeners() {
    document.querySelectorAll('.block-btn').forEach(button => {
        button.addEventListener('click', function() {
            let ip = this.getAttribute('data-ip');
            blockTemporaryIP(ip, "Reblocked");
        });
    });

    document.querySelectorAll('.unblock-btn').forEach(button => {
        button.addEventListener('click', function() {
            let ip = this.getAttribute('data-ip');
            let type = this.getAttribute('data-type');
            unblockIP(ip, type);
        });
    });
}

// Temporary Block Function
function blockTemporaryIP(ip, attackType) {
    fetch('/temporary_block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip, final_attack_type: attackType })
    })
    .then(response => response.json())
    .then(data => {
        console.log(data);
    })
    .catch(error => console.error('Error:', error));
}

// Permanent Block Function
function permanentlyBlockIP(ip, attackType) {
    fetch('/permanent_block', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ip: ip, final_attack_type: attackType })
    })
    .then(response => response.json())
    .then(data => {
        console.log("Permanent Block Response:", data);
    })
    .catch(error => console.error('Error:', error));
}

// Unblock Function
function unblockIP(ip, type) {
    fetch('/unblock_ip', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ip: ip, type: type })  
})
.then(response => response.json())  
.then(data => {
    if (data.status === "success") {
        alert(data.message);
        socket.emit("fetch_updated_blocked_ips");
    } else {
        alert("Error: " + (data.message || "Unknown error occurred"));
    }
})
.catch(error => {
    console.error('Fetch Error:', error);
    alert("Network Error: Unable to reach the server");
});
}

// WebSocket Event Listeners
if (typeof socket !== 'undefined') {
    socket.on("update_blocked_ips", function(data) {
        console.log("Received Blocked Traffic Data:", data);
        if (!data) {
            console.error("No blocked traffic data received!");
            return;
        }

        updateBlockedIPs("temporary", data.temporary);
        updateBlockedIPs("permanent", data.permanent);
    });
} else {
    console.error("WebSocket 'socket' is not defined!");
}




