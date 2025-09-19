from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import HTMLResponse, FileResponse
from pydantic import BaseModel
from typing import Optional, List, Dict, Any
import logging
import os
from .autodast import AutoDast


logger = logging.getLogger(__name__)

app = FastAPI(
    title="AutoDast API",
    description="Web Application Security Monitoring with OWASP ZAP",
    version="1.0.0"
)

# Global AutoDast instance
autodast: Optional[AutoDast] = None


class ScanRequest(BaseModel):
    target_name: str
    scan_policy: Optional[str] = None


class TargetRequest(BaseModel):
    name: str
    url: str
    scan_policy: Optional[str] = "default"


@app.on_event("startup")
async def startup_event():
    """Initialize AutoDast on startup."""
    global autodast
    try:
        autodast = AutoDast()
        autodast.start()
        logger.info("AutoDast API started successfully")
    except Exception as e:
        logger.error(f"Failed to start AutoDast: {e}")


@app.on_event("shutdown")
async def shutdown_event():
    """Stop AutoDast on shutdown."""
    if autodast:
        autodast.stop()
        logger.info("AutoDast API stopped")


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    """Main dashboard page."""
    if not autodast:
        raise HTTPException(status_code=503, detail="AutoDast not initialized")

    status = autodast.get_system_status()
    targets_status = autodast.get_target_status()

    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>AutoDast Dashboard</title>
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }}
            .container {{ max-width: 1200px; margin: 0 auto; }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                      color: white; padding: 30px; border-radius: 8px; text-align: center; margin-bottom: 30px; }}
            .status-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
                           gap: 20px; margin-bottom: 30px; }}
            .card {{ background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
            .status-good {{ border-left: 4px solid #28a745; }}
            .status-warning {{ border-left: 4px solid #ffc107; }}
            .status-error {{ border-left: 4px solid #dc3545; }}
            .btn {{ background: #667eea; color: white; padding: 10px 20px; border: none;
                   border-radius: 4px; cursor: pointer; text-decoration: none; display: inline-block; }}
            .btn:hover {{ background: #5a6fd8; }}
            .btn-danger {{ background: #dc3545; }}
            .btn-danger:hover {{ background: #c82333; }}
            .actions {{ margin: 20px 0; }}
            .actions button {{ margin-right: 10px; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🔍 AutoDast Security Monitor</h1>
                <p>Web Application Security Monitoring with OWASP ZAP</p>
            </div>

            <div class="status-grid">
                <div class="card {'status-good' if status['running'] else 'status-error'}">
                    <h3>System Status</h3>
                    <p><strong>Status:</strong> {'Running' if status['running'] else 'Stopped'}</p>
                    <p><strong>ZAP Available:</strong> {'Yes' if status['zap_available'] else 'No'}</p>
                    <p><strong>Targets:</strong> {status['targets_count']}</p>
                </div>

                <div class="card {'status-good' if status['scheduler_status']['is_running'] else 'status-error'}">
                    <h3>Scheduler</h3>
                    <p><strong>Status:</strong> {'Running' if status['scheduler_status']['is_running'] else 'Stopped'}</p>
                    <p><strong>Scheduled Targets:</strong> {status['scheduler_status']['scheduled_targets']}</p>
                    <p><strong>Manual Scan:</strong> {'In Progress' if status['scheduler_status'].get('manual_scan_in_progress') else 'Idle'}</p>
                </div>

                <div class="card {'status-good' if status['webhook_configured'] else 'status-warning'}">
                    <h3>Notifications</h3>
                    <p><strong>Google Chat:</strong> {'Configured' if status['webhook_configured'] else 'Not Configured'}</p>
                </div>
            </div>

            <div class="card">
                <h3>Quick Actions</h3>
                <div class="actions">
                    <button class="btn" onclick="refreshPage()">🔄 Refresh</button>
                    <button class="btn" onclick="testWebhook()">🧪 Test Webhook</button>
                    <button class="btn" onclick="showScanForm()">🚀 Manual Scan</button>
                    <a href="/api/docs" class="btn">📖 API Docs</a>
                </div>
            </div>

            <div class="card">
                <h3>API Endpoints</h3>
                <ul>
                    <li><strong>GET /status</strong> - System status</li>
                    <li><strong>POST /scan</strong> - Execute manual scan</li>
                    <li><strong>GET /history</strong> - Scan history</li>
                    <li><strong>GET /reports</strong> - Available reports</li>
                    <li><strong>POST /targets</strong> - Add new target</li>
                </ul>
            </div>
        </div>

        <script>
            function refreshPage() {{ location.reload(); }}

            function testWebhook() {{
                fetch('/webhook/test', {{method: 'POST'}})
                    .then(response => response.json())
                    .then(data => alert(data.success ? 'Webhook test successful!' : 'Webhook test failed!'));
            }}

            function showScanForm() {{
                const target = prompt('Enter target name:');
                if (target) {{
                    fetch('/scan', {{
                        method: 'POST',
                        headers: {{'Content-Type': 'application/json'}},
                        body: JSON.stringify({{target_name: target}})
                    }})
                    .then(response => response.json())
                    .then(data => alert(data.success ? 'Scan started!' : 'Scan failed: ' + data.error));
                }}
            }}
        </script>
    </body>
    </html>
    """
    return html_content


@app.get("/status")
async def get_status():
    """Get system status."""
    if not autodast:
        raise HTTPException(status_code=503, detail="AutoDast not initialized")

    return {
        "system": autodast.get_system_status(),
        "targets": autodast.get_target_status()
    }


@app.post("/scan")
async def execute_scan(scan_request: ScanRequest, background_tasks: BackgroundTasks):
    """Execute a manual scan."""
    if not autodast:
        raise HTTPException(status_code=503, detail="AutoDast not initialized")

    try:
        # Execute scan in background
        def run_scan():
            autodast.execute_manual_scan(
                scan_request.target_name,
                scan_request.scan_policy
            )

        background_tasks.add_task(run_scan)

        return {
            "success": True,
            "message": f"Manual scan started for {scan_request.target_name}",
            "target": scan_request.target_name
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@app.get("/history")
async def get_scan_history(target_name: Optional[str] = None, limit: int = 10):
    """Get scan history."""
    if not autodast:
        raise HTTPException(status_code=503, detail="AutoDast not initialized")

    history = autodast.get_scan_history(target_name, limit)
    return {
        "target": target_name,
        "history": history
    }


@app.get("/reports")
async def get_reports(target_name: Optional[str] = None):
    """Get available reports."""
    if not autodast:
        raise HTTPException(status_code=503, detail="AutoDast not initialized")

    reports = autodast.report_generator.get_report_files(target_name)
    return {
        "target": target_name,
        "reports": reports
    }


@app.get("/reports/{filename}")
async def download_report(filename: str):
    """Download a specific report file."""
    if not autodast:
        raise HTTPException(status_code=503, detail="AutoDast not initialized")

    filepath = os.path.join(autodast.config.reports.output_dir, filename)

    if not os.path.exists(filepath):
        raise HTTPException(status_code=404, detail="Report not found")

    return FileResponse(filepath, filename=filename)


@app.post("/targets")
async def add_target(target_request: TargetRequest):
    """Add a new target for monitoring."""
    if not autodast:
        raise HTTPException(status_code=503, detail="AutoDast not initialized")

    try:
        autodast.add_target(
            target_request.name,
            target_request.url,
            target_request.scan_policy
        )

        return {
            "success": True,
            "message": f"Target {target_request.name} added successfully"
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@app.delete("/targets/{target_name}")
async def remove_target(target_name: str):
    """Remove a target from monitoring."""
    if not autodast:
        raise HTTPException(status_code=503, detail="AutoDast not initialized")

    try:
        autodast.remove_target(target_name)

        return {
            "success": True,
            "message": f"Target {target_name} removed successfully"
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


@app.post("/webhook/test")
async def test_webhook():
    """Test Google Chat webhook."""
    if not autodast:
        raise HTTPException(status_code=503, detail="AutoDast not initialized")

    success = autodast.test_google_chat_webhook()

    return {
        "success": success,
        "message": "Webhook test successful" if success else "Webhook test failed"
    }


@app.post("/cleanup")
async def cleanup_data(days_to_keep: int = 30):
    """Clean up old scan data."""
    if not autodast:
        raise HTTPException(status_code=503, detail="AutoDast not initialized")

    try:
        autodast.cleanup_old_data(days_to_keep)

        return {
            "success": True,
            "message": f"Cleaned up data older than {days_to_keep} days"
        }

    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }