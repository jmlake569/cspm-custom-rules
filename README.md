# Trend Vision One Custom Rules Management

A Python toolkit for managing custom conformity rules in Trend Vision One for security compliance automation. Includes rule creation, management, and testing capabilities.

## 🚀 Quick Start

### Prerequisites
- Python 3.7+
- Trend Vision One API token with appropriate permissions
- Required packages: `requests` (install with `pip install requests`)

### Installation
```bash
git clone <your-repo>
cd cspm-custom-rules
pip install requests
```

## 🔧 Tools Overview

### 1. `custom_rules.py` - Rule Management
The primary tool for managing custom conformity rules in Trend Vision One. Creates automated compliance rules that can monitor and validate security configurations.

### 2. `dry_run_rules.py` - Rule Testing
Test custom rules against existing resource data without waiting for the Conformity Bot to complete. Perfect for validating rule logic before deployment.

## 📋 Main Tool: `custom_rules.py`

### Key Features
- ✅ List existing custom rules
- ✅ Create new custom rules from templates or JSON files
- ✅ Built-in IAM access key rotation rule (180-day compliance)
- ✅ Get details of specific rules
- ✅ Delete custom rules (single, bulk, or pattern-based)
- ✅ Force delete options (skip confirmation)
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

**Delete all rules:**
```bash
python custom_rules.py --api-key YOUR_API_KEY --delete-all
```

**Delete rules matching a pattern:**
```bash
python custom_rules.py --api-key YOUR_API_KEY --delete-pattern "iam"
```

**Force delete (skip confirmation):**
```bash
python custom_rules.py --api-key YOUR_API_KEY --delete-all --force
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

### Enhanced Deletion Features

The script now supports advanced deletion capabilities:

**Delete all rules:**
```bash
python custom_rules.py --api-key YOUR_API_KEY --delete-all
```

**Delete rules matching a pattern:**
```bash
# Delete all rules with "iam" in the name or ID
python custom_rules.py --api-key YOUR_API_KEY --delete-pattern "iam"

# Delete all rules with "test" in the name or ID
python custom_rules.py --api-key YOUR_API_KEY --delete-pattern "test"
```

**Force delete (skip confirmation):**
```bash
python custom_rules.py --api-key YOUR_API_KEY --delete-all --force
```

**Example bulk deletion output:**
```
🗑️  Deleting all custom rules...
🗑️  About to delete 3 custom rules:
  - iam-access-key-rotation-180-days-abc123
  - test-rule-456
  - production-security-rule-789

Are you sure? This cannot be undone. (y/N): y

🗑️  Deleting rule: iam-access-key-rotation-180-days-abc123
Response Status: 204
✅ Custom rule deleted successfully!

🗑️  Deleting rule: test-rule-456
Response Status: 204
✅ Custom rule deleted successfully!

🗑️  Deleting rule: production-security-rule-789
Response Status: 204
✅ Custom rule deleted successfully!

📊 Deletion Summary:
  ✅ Successfully deleted: 3
  ❌ Failed to delete: 0
```

## 🧪 Testing Tool: `dry_run_rules.py`

### Key Features
- ✅ Test rules against existing account data
- ✅ Validate rule logic before deployment
- ✅ Test rules from JSON files or existing rule IDs
- ✅ Get detailed results with resource data
- ✅ No waiting for Conformity Bot completion

### Basic Usage

**Test a rule from JSON file:**
```bash
python dry_run_rules.py --api-key YOUR_API_KEY --rule-file iam_key_rotation_180_days.json --account-id ACCOUNT_ID
```

**Test an existing rule by ID:**
```bash
python dry_run_rules.py --api-key YOUR_API_KEY --rule-id RULE_ID --account-id ACCOUNT_ID
```

**Test with resource data returned:**
```bash
python dry_run_rules.py --api-key YOUR_API_KEY --rule-file rule.json --account-id ACCOUNT_ID --resource-data
```

### Example Output
```
🔍 Performing dry run of rule from file: iam_key_rotation_180_days.json
Performing dry run at: https://api.xdr.trendmicro.com/beta/c1/conformity/custom-rules/run
Account ID: 123456789012
Resource data requested: False
Response Status: 200
✅ Dry run completed successfully!

================================================================================
DRY RUN RESULTS
================================================================================
Rule Name: IAM Access Key Rotation (180 Days)
Service: IAM
Resource Type: iam-user
Severity: HIGH
Provider: aws

Results Summary:
  Total Resources Checked: 5
  Passed: 3
  Failed: 2
  Errors: 0

Individual Results:
Resource ID                                        Status     Message                        
-------------------------------------------------- ---------- ------------------------------
user/john.doe                                      FAILED     Access key older than 180 days
user/jane.smith                                    PASSED     All access keys compliant
```

### Environment Variable Support
The dry run script supports environment variables for API keys:
```bash
# Using TMV1_TOKEN
export TMV1_TOKEN="your-api-key"
python dry_run_rules.py --rule-file rule.json --account-id ACCOUNT_ID

# Using VISION_ONE_API_KEY
export VISION_ONE_API_KEY="your-api-key"
python dry_run_rules.py --rule-file rule.json --account-id ACCOUNT_ID
```

## 📄 Custom Rule JSON Format

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

### 2. Create and Test IAM Security Rules
```bash
# Create 180-day key rotation rule
python custom_rules.py --api-key "$VISION_ONE_API_KEY" --create --sample

# Test the rule against your account
python dry_run_rules.py --api-key "$VISION_ONE_API_KEY" --rule-file iam_key_rotation_180_days.json --account-id YOUR_ACCOUNT_ID

# Check it was created
python custom_rules.py --api-key "$VISION_ONE_API_KEY" --list
```

### 3. Custom Rule Development Workflow
```bash
# 1. Create your rule JSON file
# 2. Test it with dry run
python dry_run_rules.py --api-key "$VISION_ONE_API_KEY" --rule-file my_custom_rule.json --account-id ACCOUNT_ID

# 3. If test passes, create the rule
python custom_rules.py --api-key "$VISION_ONE_API_KEY" --create --rule-file my_custom_rule.json

# 4. Get details to verify
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

# Test the sample rule
python dry_run_rules.py --api-key "$VISION_ONE_API_KEY" --rule-file iam_key_rotation_180_days.json --account-id YOUR_ACCOUNT_ID
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
2. Use dry run to validate rule logic before creating
3. Validate JSON rule definitions before submitting
4. Include example use cases for new rule types

## 📄 License

[Add your license information here]

---

**Need help?** Check the `--help` flag on any script or review the Trend Vision One API documentation.
