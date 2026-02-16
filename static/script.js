function analyzeURL() {
    let url = document.getElementById("urlInput").value;

    if (!url) {
        alert("Please enter a URL");
        return;
    }

    document.getElementById("loader").style.display = "block";
    document.getElementById("resultCard").style.display = "none";
    document.getElementById("analyzeBtn").disabled = true;

    fetch("/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url })
    })
        .then(response => response.json())
        .then(data => {

            document.getElementById("loader").style.display = "none";
            document.getElementById("resultCard").style.display = "block";
            document.getElementById("analyzeBtn").disabled = false;

            let badgeClass = "";
            let fillClass = "";

            if (data.level === "Low Risk") {
                badgeClass = "low";
                fillClass = "low-fill";
            } else if (data.level === "Suspicious") {
                badgeClass = "medium";
                fillClass = "medium-fill";
            } else {
                badgeClass = "high";
                fillClass = "high-fill";
            }

            let riskLevel = document.getElementById("riskLevel");
            riskLevel.className = "risk-badge " + badgeClass;
            riskLevel.innerText = data.level;

            document.getElementById("riskScore").innerText =
                "Risk Score: " + data.risk + "/100";

            let progress = document.getElementById("progressFill");
            progress.className = "progress-fill " + fillClass;
            progress.style.width = data.risk + "%";

            let container = document.getElementById("detailsContainer");
            container.innerHTML = "";

            data.details.forEach(item => {

                let card = document.createElement("div");
                card.classList.add("detail-card");

                let icon = document.createElement("span");
                icon.classList.add("icon");

                if (item.includes("❌")) {
                    card.classList.add("danger");
                    icon.innerText = "❌";
                }
                else if (item.includes("⚠")) {
                    card.classList.add("warning");
                    icon.innerText = "⚠";
                }
                else if (item.includes("ℹ")) {
                    card.classList.add("info");
                    icon.innerText = "ℹ";
                }
                else {
                    card.classList.add("success");
                    icon.innerText = "✔";
                }

                let text = document.createElement("span");
                text.innerText = item.replace(/[❌⚠ℹ✔]/g, "").trim();

                card.appendChild(icon);
                card.appendChild(text);
                container.appendChild(card);
            });

        });
}
