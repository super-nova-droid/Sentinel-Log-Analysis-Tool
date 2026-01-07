## Running the App

Choose one of the following options:

1. Quick (open file)
   - Open `index.html` directly in your browser (double-click or right-click → Open with).

2. Recommended (local static server)
   - Using Python (works if Python is installed):
     - cd into the project folder
     - `python -m http.server 8000`
     - Open `http://localhost:8000` in your browser

   - Using Node (if Node/npm available):
     - `npx http-server -p 8000`
     - Open `http://localhost:8000`

3. Using VS Code
   - Install the **Live Server** extension and click **Go Live**.

Test:
- Click **Load Sample Logs**, then **Scan for Threats**. Threat items should appear and **Threats Found** will update.

Note: The `index.html` file now loads `logscript.js` (was `script.js`).

A sample screenshot has been created at `screenshot.png`.

New features added:
- **Severity filter** (All / Critical / High / Medium / Low)
- **Dedupe** option to skip duplicate detections
- **Export CSV** of detected threats
- **Clear** results button

Test: open the page, click **Load Sample Logs**, then **Scan for Threats** and try the filter, dedupe and export options.