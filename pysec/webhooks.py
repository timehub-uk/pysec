"""
Notification Webhooks - Send alerts to Slack, Teams, Discord, etc.
"""

import json
import subprocess
from typing import Optional
from pathlib import Path


def send_slack(webhook_url: str, message: str, severity: str = "info") -> bool:
    """Send notification to Slack"""
    if not webhook_url:
        return False
    
    color_map = {
        "critical": "#ff0000",
        "high": "#ff6600",
        "medium": "#ffcc00",
        "low": "#00cc00",
        "info": "#0066cc"
    }
    
    payload = {
        "attachments": [{
            "color": color_map.get(severity, "#0066cc"),
            "text": message,
            "footer": "pysec Security Scanner",
            "ts": int(__import__("time").time())
        }]
    }
    
    result = subprocess.run(
        ["curl", "-s", "-X", "POST", "-H", "Content-Type: application/json",
         "-d", json.dumps(payload), webhook_url],
        capture_output=True
    )
    
    return result.returncode == 0


def send_teams(webhook_url: str, message: str, title: str = "Security Alert") -> bool:
    """Send notification to Microsoft Teams"""
    if not webhook_url:
        return False
    
    payload = {
        "@type": "MessageCard",
        "@context": "http://schema.org/extensions",
        "themeColor": "ff0000",
        "summary": title,
        "sections": [{
            "activityTitle": title,
            "facts": [{"name": "Message", "value": message}],
            "markdown": True
        }]
    }
    
    result = subprocess.run(
        ["curl", "-s", "-X", "POST", "-H", "Content-Type: application/json",
         "-d", json.dumps(payload), webhook_url],
        capture_output=True
    )
    
    return result.returncode == 0


def send_discord(webhook_url: str, message: str, severity: str = "info") -> bool:
    """Send notification to Discord"""
    if not webhook_url:
        return False
    
    color_map = {
        "critical": 16711680,
        "high": 16744448,
        "medium": 16776960,
        "low": 65280,
        "info": 255
    }
    
    payload = {
        "embeds": [{
            "title": "🔒 Security Alert",
            "description": message,
            "color": color_map.get(severity, 255)
        }]
    }
    
    result = subprocess.run(
        ["curl", "-s", "-X", "POST", "-H", "Content-Type: application/json",
         "-d", json.dumps(payload), webhook_url],
        capture_output=True
    )
    
    return result.returncode == 0


def send_webhook(webhook_url: str, message: str, platform: str = "slack", **kwargs) -> bool:
    """Generic webhook sender"""
    
    if not webhook_url:
        return False
    
    platform = platform.lower()
    
    if "slack" in platform or platform == "web":
        return send_slack(webhook_url, message, kwargs.get("severity", "info"))
    elif "teams" in platform or "microsoft" in platform:
        return send_teams(webhook_url, message, kwargs.get("title", "Security Alert"))
    elif "discord" in platform:
        return send_discord(webhook_url, message, kwargs.get("severity", "info"))
    else:
        return False


def notify_from_results(results: list[dict], webhook_url: str, platform: str = "slack") -> bool:
    """Send notification based on scan results"""
    
    if not results:
        return False
    
    summary = {
        "critical": len([r for r in results if r.get("severity") == "critical"]),
        "high": len([r for r in results if r.get("severity") == "high"]),
        "medium": len([r for r in results if r.get("severity") == "medium"]),
        "low": len([r for r in results if r.get("severity") == "low"])
    }
    
    total = sum(summary.values())
    
    if total == 0:
        message = "✅ No security issues found"
        severity = "info"
    elif summary["critical"] > 0 or summary["high"] > 0:
        message = f"⚠️ Found {total} security issues: {summary['critical']} critical, {summary['high']} high"
        severity = "high"
    else:
        message = f"ℹ️ Found {total} security issues: {summary['medium']} medium, {summary['low']} low"
        severity = "medium"
    
    return send_webhook(webhook_url, message, platform, severity=severity)