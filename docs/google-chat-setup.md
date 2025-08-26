# Google Chat Integration Setup

This guide explains how to set up Google Chat webhook integration for DAST monitoring alerts.

## 📋 Prerequisites

- Google Workspace account with admin privileges
- Access to Google Chat API
- A Google Chat space where you want to receive alerts

## 🔧 Setting Up Google Chat Webhooks

### Step 1: Create a Google Chat App

1. Go to [Google Chat API Console](https://console.cloud.google.com/apis/api/chat.googleapis.com)
2. Enable the Google Chat API for your project
3. Go to [Google Cloud Console - Credentials](https://console.cloud.google.com/apis/credentials)
4. Create credentials (API Key or Service Account)

### Step 2: Create a Chat Space

1. Open Google Chat in your browser
2. Create a new space or use an existing one
3. Add the bot/app to the space

### Step 3: Generate Webhook URL

#### Method A: Using Google Apps Script

1. Go to [Google Apps Script](https://script.google.com)
2. Create a new project
3. Replace the default code with:

```javascript
function doPost(e) {
  const data = JSON.parse(e.postData.contents);
  
  // Your space ID - get this from Google Chat URL
  const spaceId = 'YOUR_SPACE_ID';
  const chatApi = 'https://chat.googleapis.com/v1/';
  
  // Send message to Google Chat
  const message = {
    text: data.text || 'DAST Alert',
    cards: data.cards || []
  };
  
  const response = UrlFetchApp.fetch(
    `${chatApi}spaces/${spaceId}/messages`,
    {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${getAccessToken()}`,
        'Content-Type': 'application/json'
      },
      payload: JSON.stringify(message)
    }
  );
  
  return ContentService.createTextOutput('Success');
}

function getAccessToken() {
  return ScriptApp.getOAuthToken();
}
```

4. Deploy as a web app
5. Copy the generated URL - this is your webhook URL

#### Method B: Direct Chat API (Recommended)

1. Get your Space ID:
   - Open the Google Chat space in your browser
   - Look at the URL: `https://chat.google.com/room/SPACE_ID`
   - Copy the `SPACE_ID` part

2. Create API credentials:
   - Go to [Google Cloud Console](https://console.cloud.google.com)
   - Create a Service Account
   - Download the JSON key file
   - Enable Google Chat API

3. Your webhook URL format will be:
   ```
   https://chat.googleapis.com/v1/spaces/SPACE_ID/messages?key=API_KEY&token=TOKEN
   ```

### Step 4: Configure DAST Monitor

1. Update your `.env` file:
   ```bash
   GOOGLE_CHAT_WEBHOOK_URL=https://chat.googleapis.com/v1/spaces/YOUR_SPACE_ID/messages?key=YOUR_API_KEY&token=YOUR_TOKEN
   ```

2. Update `config/dast_config.yaml`:
   ```yaml
   notifications:
     google_chat:
       enabled: true
       webhook_url: "${GOOGLE_CHAT_WEBHOOK_URL}"
       space_name: "Security Monitoring"
       severity_threshold: "medium"
       message_style: "card"
       thread_alerts: true
   ```

## 🧪 Testing the Integration

### Test with Python Script

Create a test script to verify your webhook:

```python
import requests
import json

webhook_url = "YOUR_GOOGLE_CHAT_WEBHOOK_URL"

# Simple text message
simple_message = {
    "text": "🧪 **Test Message**\n\nThis is a test from DAST Monitor!"
}

# Card message
card_message = {
    "text": "DAST Monitor Test",
    "cards": [
        {
            "header": {
                "title": "🛡️ DAST Security Test",
                "subtitle": "Integration Test",
                "imageUrl": "https://owasp.org/assets/images/logo.png"
            },
            "sections": [
                {
                    "widgets": [
                        {
                            "keyValue": {
                                "topLabel": "Status",
                                "content": "✅ Integration Working",
                                "icon": "STAR"
                            }
                        },
                        {
                            "keyValue": {
                                "topLabel": "Test Type",
                                "content": "Google Chat Webhook",
                                "icon": "DESCRIPTION"
                            }
                        }
                    ]
                }
            ]
        }
    ]
}

# Send simple message
response = requests.post(webhook_url, json=simple_message)
print(f"Simple message status: {response.status_code}")

# Send card message
response = requests.post(webhook_url, json=card_message)
print(f"Card message status: {response.status_code}")
```

### Test with DAST Monitor

```bash
# Test the integration directly
python -c "
import asyncio
import sys
sys.path.append('app/integrations')
from google_chat_integration import GoogleChatIntegration

config = {
    'enabled': True,
    'webhook_url': 'YOUR_WEBHOOK_URL',
    'message_style': 'card'
}

async def test():
    integration = GoogleChatIntegration(config)
    result = await integration.send_test_message()
    print('✅ Success!' if result else '❌ Failed!')

asyncio.run(test())
"
```

## 🎨 Message Formatting Options

### Simple Text Messages

```yaml
google_chat:
  message_style: "simple"
```

- Clean, plain text format
- Fast and lightweight
- Good for high-volume alerts

### Rich Card Messages (Recommended)

```yaml
google_chat:
  message_style: "card"
```

- Rich formatting with headers and sections
- Color-coded severity levels
- Interactive elements
- Better visual organization

## ⚙️ Configuration Options

| Option | Description | Default | Values |
|--------|-------------|---------|--------|
| `enabled` | Enable/disable Google Chat | `false` | `true`/`false` |
| `webhook_url` | Google Chat webhook URL | - | URL string |
| `space_name` | Display name for the space | `"Security Monitoring"` | String |
| `bot_name` | Bot display name | `"DAST Monitor"` | String |
| `severity_threshold` | Minimum severity to send | `"medium"` | `info`/`low`/`medium`/`high`/`critical` |
| `message_style` | Message format style | `"card"` | `simple`/`card`/`rich` |
| `thread_alerts` | Group related alerts | `true` | `true`/`false` |
| `include_remediation` | Include fix suggestions | `true` | `true`/`false` |
| `max_card_fields` | Max fields in cards | `10` | Number |

## 🔒 Security Considerations

### API Key Security
- Store API keys in environment variables
- Use service accounts with minimal permissions
- Rotate keys regularly
- Monitor API usage

### Access Control
- Limit space membership
- Use private spaces for sensitive alerts
- Consider encryption for sensitive data

### Rate Limiting
- Google Chat has API rate limits
- Monitor usage to avoid throttling
- Implement retry logic with backoff

## 🚨 Alert Types

The integration sends different types of alerts:

### Scan Completion Alerts
- Triggered after each DAST scan
- Includes vulnerability counts by severity
- Shows scan duration and status
- Links to full reports

### High-Severity Alerts
- Immediate notifications for critical findings
- Red color coding for urgency
- Detailed vulnerability information
- Remediation suggestions

### Subdomain Discovery Alerts
- New subdomains discovered
- Attack surface expansion notifications
- Domain monitoring updates

### System Alerts
- Scan failures and errors
- System health issues
- Configuration problems

## 📊 Example Alert Messages

### Critical Vulnerability Alert
```
🔴 DAST Scan Completed
Target: api.example.com
🚨 Critical Issues Found!
• High: 3 vulnerabilities
• Medium: 5 vulnerabilities
• Total: 12 alerts
⏱️ Duration: 45 minutes
📄 Full Report Available
```

### Subdomain Discovery
```
🔍 New Subdomains Discovered
Domain: example.com
📊 New: 5 subdomains
📈 Total: 23 subdomains
🆕 Latest: api-v2.example.com, staging.example.com
```

## 🔧 Troubleshooting

### Common Issues

**Webhook not receiving messages:**
- Verify the webhook URL is correct
- Check API key permissions
- Ensure the bot is added to the space
- Test with a simple curl command

**Authentication errors:**
- Verify service account credentials
- Check API key validity
- Ensure proper scopes are enabled

**Message formatting issues:**
- Validate JSON payload structure
- Check card format compliance
- Test with simple messages first

**Rate limiting:**
- Monitor API quotas
- Implement exponential backoff
- Consider message batching

### Debug Commands

```bash
# Test webhook connectivity
curl -X POST "$GOOGLE_CHAT_WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{"text": "Test message"}'

# Check API quotas
gcloud auth activate-service-account --key-file=service-account.json
gcloud services list --enabled | grep chat

# Validate webhook URL format
echo $GOOGLE_CHAT_WEBHOOK_URL | grep -E "chat.googleapis.com.*spaces.*messages"
```

## 🔄 Migration from Other Platforms

### From Slack
- Similar webhook concept
- Card format translates well
- Thread support available
- Maintain same alerting logic

### From Microsoft Teams
- Cards supported in both platforms
- Action buttons work similarly
- Connector setup differs

## 📚 Additional Resources

- [Google Chat API Documentation](https://developers.google.com/chat)
- [Card Message Format](https://developers.google.com/chat/api/guides/message-formats/cards)
- [Webhooks Guide](https://developers.google.com/chat/how-tos/webhooks)
- [Authentication Guide](https://cloud.google.com/docs/authentication)

## 🆘 Support

If you encounter issues:
1. Check the troubleshooting section above
2. Review Google Chat API documentation
3. Validate your webhook configuration
4. Test with simple messages first
5. Check application logs for error details

---

**Ready to receive security alerts directly in Google Chat!** 🛡️📱