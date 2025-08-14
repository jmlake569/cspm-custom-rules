
import argparse
import json
import os
import requests
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

class ConformityCustomRulesManager:
    def __init__(self, api_key: str):
        """
        Initialize the Conformity Custom Rules Manager.
        
        Args:
            api_key: Trend Vision One API key (Bearer token)
        """
        self.api_key = api_key
        
        # Trend Vision One API base URL and path (matching get_accounts.py pattern)
        self.url_base = "https://api.xdr.trendmicro.com"
        self.url_path = "/beta/c1/conformity/custom-rules"
        self.headers = {
            "Authorization": "Bearer " + self.api_key,
            "Content-Type": "application/vnd.api+json"
        }

    def list_custom_rules(self) -> Optional[List[Dict[str, Any]]]:
        """
        List all custom rules in the Conformity account.
        
        Returns:
            List of custom rules or None if failed
        """
        url = self.url_base + self.url_path
        
        try:
            print(f"Fetching custom rules from: {url}")
            response = requests.get(url, headers=self.headers)
            
            print(f"Response Status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', [])
            elif response.status_code == 401:
                print("❌ Authentication failed. Check your API key.")
                return None
            elif response.status_code == 403:
                print("❌ Access denied. Check your permissions for custom rules.")
                return None
            else:
                print(f"❌ Failed to fetch custom rules: {response.status_code}")
                print(f"Response: {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error: {e}")
            return None

    def get_custom_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        Get details of a specific custom rule.
        
        Args:
            rule_id: The ID of the custom rule
            
        Returns:
            Custom rule details or None if failed
        """
        url = f"{self.url_base}{self.url_path}/{rule_id}"
        
        try:
            print(f"Fetching custom rule {rule_id} from: {url}")
            response = requests.get(url, headers=self.headers)
            
            print(f"Response Status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data')
            elif response.status_code == 404:
                print(f"❌ Custom rule {rule_id} not found.")
                return None
            elif response.status_code == 401:
                print("❌ Authentication failed. Check your API key.")
                return None
            elif response.status_code == 403:
                print("❌ Access denied. Check your permissions for custom rules.")
                return None
            else:
                print(f"❌ Failed to fetch custom rule: {response.status_code}")
                print(f"Response: {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error: {e}")
            return None

    def create_custom_rule(self, rule_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Create a new custom rule.
        
        Args:
            rule_data: The rule definition following Conformity API schema
            
        Returns:
            Created rule details or None if failed
        """
        url = self.url_base + self.url_path
        
        try:
            print(f"Creating custom rule at: {url}")
            # Use json parameter to let requests handle the JSON properly
            print(f"Request headers: {self.headers}")
            print(f"Request body: {json.dumps(rule_data, indent=2)}")
            response = requests.post(url, headers=self.headers, json=rule_data)
            
            print(f"Response Status: {response.status_code}")
            
            if response.status_code == 201:
                data = response.json()
                print("✅ Custom rule created successfully!")
                return data.get('data')
            elif response.status_code == 400:
                print("❌ Bad request. Check your rule definition.")
                print(f"Response: {response.text}")
                return None
            elif response.status_code == 401:
                print("❌ Authentication failed. Check your API key.")
                return None
            elif response.status_code == 403:
                print("❌ Access denied. Check your permissions for creating custom rules.")
                return None
            elif response.status_code == 422:
                print("❌ Validation error. Check your rule definition.")
                print(f"Response: {response.text}")
                return None
            else:
                print(f"❌ Failed to create custom rule: {response.status_code}")
                print(f"Response: {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error: {e}")
            return None

    def delete_custom_rule(self, rule_id: str) -> bool:
        """
        Delete a custom rule.
        
        Args:
            rule_id: The ID of the custom rule to delete
            
        Returns:
            True if successful, False otherwise
        """
        url = f"{self.url_base}{self.url_path}/{rule_id}"
        
        try:
            print(f"Deleting custom rule {rule_id} from: {url}")
            response = requests.delete(url, headers=self.headers)
            
            print(f"Response Status: {response.status_code}")
            
            if response.status_code == 204:
                print("✅ Custom rule deleted successfully!")
                return True
            elif response.status_code == 404:
                print(f"❌ Custom rule {rule_id} not found.")
                return False
            elif response.status_code == 401:
                print("❌ Authentication failed. Check your API key.")
                return False
            elif response.status_code == 403:
                print("❌ Access denied. Check your permissions for deleting custom rules.")
                return False
            else:
                print(f"❌ Failed to delete custom rule: {response.status_code}")
                print(f"Response: {response.text}")
                return False
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error: {e}")
            return False

    def delete_multiple_rules(self, rule_ids: List[str], force: bool = False) -> Dict[str, bool]:
        """
        Delete multiple custom rules.
        
        Args:
            rule_ids: List of rule IDs to delete
            force: Skip confirmation prompt
            
        Returns:
            Dictionary mapping rule IDs to success status
        """
        results = {}
        
        if not force:
            print(f"🗑️  About to delete {len(rule_ids)} custom rules:")
            for rule_id in rule_ids:
                print(f"  - {rule_id}")
            
            confirm = input(f"\nAre you sure? This cannot be undone. (y/N): ")
            if confirm.lower() != 'y':
                print("❌ Bulk deletion cancelled.")
                return results
        
        for rule_id in rule_ids:
            print(f"\n🗑️  Deleting rule: {rule_id}")
            results[rule_id] = self.delete_custom_rule(rule_id)
        
        return results

    def delete_rules_by_pattern(self, pattern: str, force: bool = False) -> Dict[str, bool]:
        """
        Delete custom rules that match a pattern in their name or ID.
        
        Args:
            pattern: Pattern to match (case-insensitive)
            force: Skip confirmation prompt
            
        Returns:
            Dictionary mapping rule IDs to success status
        """
        # First, get all rules
        rules = self.list_custom_rules()
        if not rules:
            print("No rules found to match against.")
            return {}
        
        # Find matching rules
        matching_rules = []
        for rule in rules:
            rule_id = rule.get('id', '')
            attributes = rule.get('attributes', {})
            name = attributes.get('name', '')
            
            if pattern.lower() in rule_id.lower() or pattern.lower() in name.lower():
                matching_rules.append(rule)
        
        if not matching_rules:
            print(f"No rules found matching pattern: {pattern}")
            return {}
        
        print(f"Found {len(matching_rules)} rules matching pattern '{pattern}':")
        for rule in matching_rules:
            rule_id = rule.get('id', '')
            attributes = rule.get('attributes', {})
            name = attributes.get('name', '')
            print(f"  - {rule_id}: {name}")
        
        rule_ids = [rule.get('id') for rule in matching_rules]
        return self.delete_multiple_rules(rule_ids, force)

    def delete_all_rules(self, force: bool = False) -> Dict[str, bool]:
        """
        Delete all custom rules.
        
        Args:
            force: Skip confirmation prompt
            
        Returns:
            Dictionary mapping rule IDs to success status
        """
        rules = self.list_custom_rules()
        if not rules:
            print("No custom rules found to delete.")
            return {}
        
        rule_ids = [rule.get('id') for rule in rules]
        return self.delete_multiple_rules(rule_ids, force)

def format_rules_table(rules: List[Dict[str, Any]]) -> None:
    """
    Format and display custom rules in a table.
    
    Args:
        rules: List of custom rule data
    """
    if not rules:
        print("No custom rules found.")
        return
    
    print(f"\n{'ID':<30} {'Name':<40} {'Service':<15} {'Status':<10} {'Created':<20}")
    print("-" * 125)
    
    for rule in rules:
        rule_id = rule.get('id', 'N/A')[:28]
        attributes = rule.get('attributes', {})
        name = attributes.get('name', 'N/A')[:38]
        service = attributes.get('service', 'N/A')[:13]
        enabled = "Enabled" if attributes.get('enabled', False) else "Disabled"
        created = attributes.get('created-date', 'N/A')[:18]
        
        print(f"{rule_id:<30} {name:<40} {service:<15} {enabled:<10} {created:<20}")

def create_sample_rule() -> Dict[str, Any]:
    """
    Create a sample IAM access key rotation rule for 180 days.
    
    Returns:
        Sample rule definition
    """
    return {
        "name": "IAM Access Key Rotation - 180 Days",
        "slug": "iam-access-key-rotation-180-days",
        "description": "Ensure IAM access keys are rotated every 180 days to maintain security best practices",
        "remediationNotes": "If this rule is violated, please follow these steps: 1. Go to AWS IAM console 2. Navigate to Users and select the affected user 3. In the Security credentials tab, create a new access key 4. Update your applications/services to use the new access key 5. Test that everything works with the new key 6. Delete the old access key once confirmed working",
        "service": "IAM",
        "resourceType": "iam-user",
        "categories": ["security"],
        "severity": "HIGH",
        "provider": "aws",
        "enabled": True,
        "attributes": [
            {
                "name": "userName",
                "path": "data.UserName",
                "required": True
            },
            {
                "name": "accessKeyAge",
                "path": "data.AccessKeyMetadata[0].CreateDate",
                "required": True
            },
            {
                "name": "accessKeyStatus",
                "path": "data.AccessKeyMetadata[0].Status",
                "required": True
            }
        ],
        "rules": [
            {
                "conditions": {
                    "all": [
                        {
                            "fact": "accessKeyStatus",
                            "operator": "equal",
                            "value": "Active"
                        },
                        {
                            "fact": "accessKeyAge",
                            "operator": "daysSince",
                            "value": 180
                        }
                    ]
                },
                "event": {
                    "type": "IAM access key is older than 180 days"
                }
            }
        ]
    }

def main():
    parser = argparse.ArgumentParser(
        description="Manage Trend Vision One Conformity custom rules",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  List all custom rules:
    python custom_rules.py --api-key YOUR_KEY --list
    # Or with environment variable:
    export TMV1_TOKEN="your-token"
    python custom_rules.py --list

  Get specific rule details:
    python custom_rules.py --api-key YOUR_KEY --get RULE_ID
    # Or with environment variable:
    python custom_rules.py --get RULE_ID

  Create rule from file:
    python custom_rules.py --api-key YOUR_KEY --create --rule-file rule.json
    # Or with environment variable:
    python custom_rules.py --create --rule-file rule.json

  Create sample IAM key rotation rule (180 days):
    python custom_rules.py --api-key YOUR_KEY --create --sample
    # Or with environment variable:
    python custom_rules.py --create --sample

  Delete a rule:
    python custom_rules.py --api-key YOUR_KEY --delete RULE_ID
    # Or with environment variable:
    python custom_rules.py --delete RULE_ID

  Delete all rules:
    python custom_rules.py --api-key YOUR_KEY --delete-all
    # Force delete without confirmation:
    python custom_rules.py --api-key YOUR_KEY --delete-all --force

  Delete rules matching pattern:
    python custom_rules.py --api-key YOUR_KEY --delete-pattern "iam"
    # Force delete without confirmation:
    python custom_rules.py --api-key YOUR_KEY --delete-pattern "test" --force

Security Note:
  Consider using environment variables for API keys:
  export TMV1_TOKEN="your-api-key"
  python custom_rules.py --list
  
  Or use VISION_ONE_API_KEY:
  export VISION_ONE_API_KEY="your-api-key"
  python custom_rules.py --list
        """
    )
    
    parser.add_argument("--api-key", help="Trend Vision One API key (Bearer token). Can also be set via TMV1_TOKEN or VISION_ONE_API_KEY environment variables.")
    
    # Action arguments
    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument("--list", action="store_true", help="List all custom rules")
    action_group.add_argument("--get", metavar="RULE_ID", help="Get details of a specific rule")
    action_group.add_argument("--create", action="store_true", help="Create a new custom rule")
    action_group.add_argument("--delete", metavar="RULE_ID", help="Delete a custom rule")
    action_group.add_argument("--delete-all", action="store_true", help="Delete all custom rules")
    action_group.add_argument("--delete-pattern", metavar="PATTERN", help="Delete custom rules matching pattern in name or ID")
    
    # Create options
    parser.add_argument("--rule-file", help="JSON file containing rule definition (for --create)")
    parser.add_argument("--sample", action="store_true", help="Create sample IAM key rotation rule for 180 days (for --create)")
    parser.add_argument("--force", action="store_true", help="Skip confirmation prompts for deletions")
    
    args = parser.parse_args()
    
    # Get API key from command line argument or environment variables
    api_key = args.api_key
    if not api_key:
        # Try environment variables in order of preference
        api_key = os.environ.get('TMV1_TOKEN') or os.environ.get('VISION_ONE_API_KEY')
        if not api_key:
            print("❌ API key is required. Provide it via --api-key argument or set TMV1_TOKEN or VISION_ONE_API_KEY environment variable.")
            sys.exit(1)
    
    # Initialize manager
    manager = ConformityCustomRulesManager(api_key)
    
    try:
        if args.list:
            print("🔍 Fetching custom rules...")
            rules = manager.list_custom_rules()
            if rules is not None:
                format_rules_table(rules)
                print(f"\nTotal custom rules: {len(rules)}")
            
        elif args.get:
            print(f"🔍 Fetching custom rule: {args.get}")
            rule = manager.get_custom_rule(args.get)
            if rule:
                print("\n" + "="*60)
                print(json.dumps(rule, indent=2))
                
        elif args.create:
            if args.sample:
                print("📝 Creating sample IAM access key rotation rule for 180 days...")
                rule_data = create_sample_rule()
            elif args.rule_file:
                try:
                    with open(args.rule_file, 'r') as f:
                        rule_data = json.load(f)
                    print(f"📝 Creating custom rule from {args.rule_file}...")
                    print(f"📋 Rule data preview: {json.dumps(rule_data, indent=2)[:500]}...")
                except FileNotFoundError:
                    print(f"❌ Rule file not found: {args.rule_file}")
                    sys.exit(1)
                except json.JSONDecodeError as e:
                    print(f"❌ Invalid JSON in rule file: {e}")
                    sys.exit(1)
            else:
                print("❌ For --create, specify either --rule-file or --sample")
                sys.exit(1)
            
            result = manager.create_custom_rule(rule_data)
            if result:
                print(f"✅ Created custom rule with ID: {result.get('id')}")
                
        elif args.delete:
            print(f"🗑️  Deleting custom rule: {args.delete}")
            if not args.force:
                confirm = input("Are you sure? This cannot be undone. (y/N): ")
                if confirm.lower() != 'y':
                    print("❌ Deletion cancelled.")
                    sys.exit(0)
            
            success = manager.delete_custom_rule(args.delete)
            if not success:
                sys.exit(1)
                
        elif args.delete_all:
            print("🗑️  Deleting all custom rules...")
            results = manager.delete_all_rules(args.force)
            
            if results:
                print(f"\n📊 Deletion Summary:")
                successful = sum(1 for success in results.values() if success)
                failed = len(results) - successful
                print(f"  ✅ Successfully deleted: {successful}")
                print(f"  ❌ Failed to delete: {failed}")
                
                if failed > 0:
                    print(f"\nFailed deletions:")
                    for rule_id, success in results.items():
                        if not success:
                            print(f"  - {rule_id}")
                    sys.exit(1)
            else:
                print("No rules were deleted.")
                
        elif args.delete_pattern:
            print(f"🗑️  Deleting custom rules matching pattern: {args.delete_pattern}")
            results = manager.delete_rules_by_pattern(args.delete_pattern, args.force)
            
            if results:
                print(f"\n📊 Deletion Summary:")
                successful = sum(1 for success in results.values() if success)
                failed = len(results) - successful
                print(f"  ✅ Successfully deleted: {successful}")
                print(f"  ❌ Failed to delete: {failed}")
                
                if failed > 0:
                    print(f"\nFailed deletions:")
                    for rule_id, success in results.items():
                        if not success:
                            print(f"  - {rule_id}")
                    sys.exit(1)
            else:
                print("No rules were deleted.")
                
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 