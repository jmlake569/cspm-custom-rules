# Trend Vision One Custom Rules Management

A Python script to manage custom conformity rules in Trend Vision One for security compliance automation.

## 🚀 Quick Start

### Prerequisites
- Python 3.7+
- Trend Vision One API token with appropriate permissions
- Required packages: `requests` (install with `pip install requests`)

### Installation
```bash
git clone <your-repo>
cd custom-checks
pip install requests
```

## 🔧 Main Tool: `custom_rules.py`

The primary tool for managing custom conformity rules in Trend Vision One. Creates automated compliance rules that can monitor and validate security configurations.

### Key Features
- ✅ List existing custom rules
- ✅ Create new custom rules from templates or JSON files
- ✅ Built-in IAM access key rotation rule (180-day compliance)
- ✅ Get details of specific rules
- ✅ Delete custom rules
- ✅ Full API error handling and validation

### Basic Usage

**List all existing custom rules:**
```bash
python custom_rules.py --api-key YOUR_API_KEY --list
```

**Create a 180-day IAM key rotation rule:**
```bash
python custom_rules.py --api-key YOUR_API_KEY --create --sample
```

**Create rule from JSON file:**
```bash
python custom_rules.py --api-key YOUR_API_KEY --create --rule-file iam_key_rotation_180_days.json
```

**Get details of a specific rule:**
```bash
python custom_rules.py --api-key YOUR_API_KEY --get RULE_ID
```

**Delete a rule:**
```bash
python custom_rules.py --api-key YOUR_API_KEY --delete RULE_ID
```

### Sample Rule: IAM Key Rotation (180 Days)

The built-in sample creates a rule that ensures AWS IAM access keys are rotated every 180 days:

- **Service:** IAM  
- **Resource Type:** iam-user
- **Severity:** HIGH
- **Check:** Active access keys older than 180 days
- **Provider:** AWS
- **Categories:** security

**Example output:**
```
📝 Creating sample IAM access key rotation rule for 180 days...
Creating custom rule at: https://api.xdr.trendmicro.com/beta/c1/conformity/custom-rules
Response Status: 201
✅ Custom rule created successfully!
✅ Created custom rule with ID: iam-access-key-rotation-180-days-abc123
```

### Custom Rule JSON Format

Create your own rules using this structure (see `iam_key_rotation_180_days.json` for example):

```json
{
  "name": "My Custom Rule",
  "slug": "my-custom-rule-slug",
  "description": "Description of what this rule checks",
  "remediationNotes": "Steps to fix violations...",
  "service": "IAM",
  "resourceType": "iam-user",
  "categories": ["security"],
  "severity": "HIGH",
  "provider": "aws",
  "enabled": true,
  "attributes": [
    {
      "name": "attributeName",
      "path": "data.SomeField",
      "required": true
    }
  ],
  "rules": [
    {
      "conditions": {
        "any": [
          {
            "fact": "attributeName",
            "operator": "someOperator",
            "value": "expectedValue"
          }
        ]
      },
      "event": {
        "type": "Violation description"
      }
    }
  ]
}
```



## 🔒 Security Best Practices

### 1. API Key Management
**❌ DON'T:**
```bash
# Don't hardcode in scripts
API_KEY = "your-token-here"
```

**✅ DO:**
```bash
# Use environment variables
export VISION_ONE_API_KEY="your-token-here"
python custom_rules.py --api-key "$VISION_ONE_API_KEY" --list

# Or store securely
echo "your-api-token" > ~/.vision_one_api_key
chmod 600 ~/.vision_one_api_key
python custom_rules.py --api-key "$(cat ~/.vision_one_api_key)" --list
```

### 2. API Token Requirements
Your Trend Vision One API token needs:
- ✅ Read access to Cloud Posture accounts
- ✅ Write access to custom conformity rules  
- ✅ Appropriate region/tenant permissions

## 🔧 Common Workflows

### 1. Initial Setup and Exploration
```bash
# See what custom rules already exist
python custom_rules.py --api-key "$VISION_ONE_API_KEY" --list
```

### 2. Create IAM Security Rules
```bash
# Create 180-day key rotation rule
python custom_rules.py --api-key "$VISION_ONE_API_KEY" --create --sample

# Check it was created
python custom_rules.py --api-key "$VISION_ONE_API_KEY" --list
```

### 3. Custom Rule Development
```bash
# Create rule from your JSON file
python custom_rules.py --api-key "$VISION_ONE_API_KEY" --create --rule-file my_custom_rule.json

# Get details to verify
python custom_rules.py --api-key "$VISION_ONE_API_KEY" --get RULE_ID
```

### 4. Rule Management
```bash
# List all rules
python custom_rules.py --api-key "$VISION_ONE_API_KEY" --list

# Delete outdated rule
python custom_rules.py --api-key "$VISION_ONE_API_KEY" --delete OLD_RULE_ID
```

## ❗ Troubleshooting

### Common Issues

**401 Unauthorized:**
- ✅ Check your API token is valid
- ✅ Verify token has conformity rule permissions
- ✅ Confirm API endpoint is correct

**403 Access Denied:**
- ✅ Token may lack custom rule creation permissions
- ✅ Check if conformity feature is enabled in your account
- ✅ Verify you're using Vision One API (not Cloud One)

**404 Not Found:**
- ✅ Confirm the custom rules API endpoint is available
- ✅ Check if rule ID exists when fetching/deleting

**422 Validation Error:**
- ✅ Review JSON structure against expected format
- ✅ Check required fields are present
- ✅ Validate operators and conditions syntax

### Debug Steps
```bash
# Check existing rules (tests API connectivity)
python custom_rules.py --api-key "$VISION_ONE_API_KEY" --list

# Try creating a simple rule
python custom_rules.py --api-key "$VISION_ONE_API_KEY" --create --sample
```

## 📚 Understanding Custom Rules

### Rule Logic
Custom conformity rules use a fact-based evaluation system:

- **Facts:** Data extracted from cloud resources using `attributes`
- **Conditions:** Logic that evaluates facts using operators  
- **Events:** What gets triggered when conditions are met

### Supported Operators
- `equal` - Exact match
- `arrayContains` - Array contains specific elements
- `daysSince` - Date comparison for time-based rules
- `pattern` - Regex pattern matching
- And more based on API documentation

### Rule Categories
- `security` - Security compliance rules
- `cost-optimization` - Cost management rules  
- `reliability` - Reliability and availability
- `performance-efficiency` - Performance optimization
- `operational-excellence` - Operational best practices

## 🤝 Contributing

Feel free to submit issues and enhancement requests! When contributing:

1. Test API connectivity with the `--list` command first
2. Validate JSON rule definitions before submitting
3. Include example use cases for new rule types

## 📄 License

[Add your license information here]

---

**Need help?** Check the `--help` flag on any script or review the Trend Vision One API documentation.
