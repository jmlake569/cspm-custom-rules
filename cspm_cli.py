#!/usr/bin/env python3
"""
Trend Vision One CSPM (Cloud Security Posture Management) CLI Tool

A unified command-line interface for managing Conformity custom rules and performing dry runs.

This tool combines the functionality of custom rules management and dry run testing
into a single, easy-to-use CLI interface.

Usage:
    # List all custom rules
    python cspm_cli.py rules list
    
    # Create a sample rule
    python cspm_cli.py rules create --sample
    
    # Create rule from file
    python cspm_cli.py rules create --file rule.json
    
    # Get rule details
    python cspm_cli.py rules get RULE_ID
    
    # Delete a rule
    python cspm_cli.py rules delete RULE_ID
    
    # Delete all rules
    python cspm_cli.py rules delete-all --force
    
    # List accounts
    python cspm_cli.py accounts list
    
    # Dry run a rule
    python cspm_cli.py dry-run --file rule.json --account ACCOUNT_ID
    
    # Dry run existing rule
    python cspm_cli.py dry-run --rule-id RULE_ID --account ACCOUNT_ID
"""

import argparse
import json
import os
import requests
import sys
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any

class CSPMCLI:
    def __init__(self, api_key: str):
        """
        Initialize the CSPM CLI tool.
        
        Args:
            api_key: Trend Vision One API key (Bearer token)
        """
        self.api_key = api_key
        
        # Trend Vision One API base URL
        self.url_base = "https://api.xdr.trendmicro.com"
        self.headers = {
            "Authorization": "Bearer " + self.api_key,
            "Content-Type": "application/vnd.api+json"
        }

    # ============================================================================
    # CUSTOM RULES MANAGEMENT
    # ============================================================================

    def list_custom_rules(self) -> Optional[List[Dict[str, Any]]]:
        """List all custom rules in the Conformity account."""
        url = f"{self.url_base}/beta/c1/conformity/custom-rules"
        
        try:
            print(f"🔍 Fetching custom rules from: {url}")
            response = requests.get(url, headers=self.headers)
            
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
        """Get details of a specific custom rule."""
        url = f"{self.url_base}/beta/c1/conformity/custom-rules/{rule_id}"
        
        try:
            print(f"🔍 Fetching custom rule {rule_id}")
            response = requests.get(url, headers=self.headers)
            
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
        """Create a new custom rule."""
        url = f"{self.url_base}/beta/c1/conformity/custom-rules"
        
        try:
            print(f"📝 Creating custom rule...")
            response = requests.post(url, headers=self.headers, json=rule_data)
            
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
        """Delete a custom rule."""
        url = f"{self.url_base}/beta/c1/conformity/custom-rules/{rule_id}"
        
        try:
            print(f"🗑️  Deleting custom rule {rule_id}...")
            response = requests.delete(url, headers=self.headers)
            
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
        """Delete multiple custom rules."""
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
        """Delete custom rules that match a pattern in their name or ID."""
        rules = self.list_custom_rules()
        if not rules:
            print("No rules found to match against.")
            return {}
        
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
        """Delete all custom rules."""
        rules = self.list_custom_rules()
        if not rules:
            print("No custom rules found to delete.")
            return {}
        
        rule_ids = [rule.get('id') for rule in rules]
        return self.delete_multiple_rules(rule_ids, force)

    # ============================================================================
    # ACCOUNT MANAGEMENT
    # ============================================================================

    def list_accounts(self) -> Optional[List[Dict[str, Any]]]:
        """List all Cloud Posture accounts."""
        url = f"{self.url_base}/beta/cloudPosture/accounts"
        
        try:
            print(f"🔍 Fetching Cloud Posture accounts...")
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                
                # Try different possible data structures
                accounts = data.get('data', [])
                if not accounts:
                    accounts = data.get('accounts', [])
                if not accounts:
                    accounts = data.get('items', [])
                if not accounts:
                    accounts = data if isinstance(data, list) else []
                
                return accounts
            elif response.status_code == 401:
                print("❌ Authentication failed. Check your API key.")
                return None
            elif response.status_code == 403:
                print("❌ Access denied. Check your permissions for Cloud Posture accounts.")
                return None
            else:
                print(f"❌ Failed to fetch accounts: {response.status_code}")
                print(f"Response: {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error: {e}")
            return None

    # ============================================================================
    # DRY RUN FUNCTIONALITY
    # ============================================================================

    def dry_run_rule_from_file(self, rule_file: str, account_id: str, resource_data: bool = False) -> Optional[Dict[str, Any]]:
        """Perform a dry run of a custom rule from a JSON file."""
        try:
            with open(rule_file, 'r') as f:
                rule_data = json.load(f)
            
            return self._perform_dry_run(rule_data, account_id, resource_data)
            
        except FileNotFoundError:
            print(f"❌ Rule file not found: {rule_file}")
            return None
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON in rule file: {e}")
            return None

    def dry_run_existing_rule(self, rule_id: str, account_id: str, resource_data: bool = False) -> Optional[Dict[str, Any]]:
        """Perform a dry run of an existing custom rule by ID."""
        rule_data = self._get_existing_rule(rule_id)
        if not rule_data:
            return None
        
        return self._perform_dry_run(rule_data, account_id, resource_data)

    def _get_existing_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """Get an existing custom rule by ID."""
        url = f"{self.url_base}/beta/c1/conformity/custom-rules/{rule_id}"
        
        try:
            print(f"🔍 Fetching existing rule {rule_id}...")
            response = requests.get(url, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                return data.get('data', {}).get('attributes', {}).get('configuration')
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

    def _perform_dry_run(self, rule_data: Dict[str, Any], account_id: str, resource_data: bool = False) -> Optional[Dict[str, Any]]:
        """Perform the actual dry run request."""
        url = f"{self.url_base}/beta/c1/conformity/custom-rules/run"
        
        # Build query parameters
        params = {
            "accountId": account_id
        }
        
        if resource_data:
            params["resourceData"] = "true"
        
        # Prepare the request body
        request_body = {
            "configuration": rule_data
        }
        
        try:
            print(f"🧪 Performing dry run...")
            print(f"Account ID: {account_id}")
            print(f"Resource data requested: {resource_data}")
            
            response = requests.post(url, headers=self.headers, params=params, json=request_body)
            
            if response.status_code == 200:
                data = response.json()
                print("✅ Dry run completed successfully!")
                return data
            elif response.status_code == 400:
                print("❌ Bad request. Check your rule definition and account ID.")
                print(f"Response: {response.text}")
                return None
            elif response.status_code == 401:
                print("❌ Authentication failed. Check your API key.")
                return None
            elif response.status_code == 403:
                print("❌ Access denied. Check your permissions for dry run operations.")
                return None
            elif response.status_code == 422:
                print("❌ Validation error. Check your rule definition.")
                print(f"Response: {response.text}")
                return None
            else:
                print(f"❌ Failed to perform dry run: {response.status_code}")
                print(f"Response: {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            print(f"❌ Network error: {e}")
            return None

    # ============================================================================
    # UTILITY FUNCTIONS
    # ============================================================================



def format_rules_table(rules: List[Dict[str, Any]]) -> None:
    """Format and display custom rules in a table."""
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

def format_accounts_table(accounts: List[Dict[str, Any]]) -> None:
    """Format and display accounts in a table."""
    if not accounts:
        print("No accounts found.")
        return
    
    print(f"\n{'Account ID':<40} {'Name':<30} {'Type':<15} {'Status':<15} {'Provider':<10}")
    print("-" * 110)
    
    for account in accounts:
        account_id = account.get('id', 'N/A')
        
        attributes = account.get('attributes', {})
        if not attributes:
            name = account.get('name', 'N/A')
            account_type = account.get('type', 'N/A')
            status = account.get('status', 'N/A')
            provider = account.get('provider', 'N/A')
        else:
            name = attributes.get('name', 'N/A')
            account_type = attributes.get('type', 'N/A')
            status = attributes.get('status', 'N/A')
            provider = attributes.get('provider', 'N/A')
        
        name = name[:28] if name != 'N/A' else 'N/A'
        account_type = account_type[:13] if account_type != 'N/A' else 'N/A'
        status = status[:13] if status != 'N/A' else 'N/A'
        provider = provider[:8] if provider != 'N/A' else 'N/A'
        
        print(f"{account_id:<40} {name:<30} {account_type:<15} {status:<15} {provider:<10}")

def format_dry_run_results(results: Dict[str, Any]) -> None:
    """Format and display dry run results in a readable format."""
    print("\n" + "="*80)
    print("DRY RUN RESULTS")
    print("="*80)
    
    if 'data' in results:
        data = results['data']
        print(f"Rule Name: {data.get('attributes', {}).get('name', 'N/A')}")
        print(f"Service: {data.get('attributes', {}).get('service', 'N/A')}")
        print(f"Resource Type: {data.get('attributes', {}).get('resourceType', 'N/A')}")
        print(f"Severity: {data.get('attributes', {}).get('severity', 'N/A')}")
        print(f"Provider: {data.get('attributes', {}).get('provider', 'N/A')}")
        
        results_summary = data.get('results', {})
        print(f"\nResults Summary:")
        print(f"  Total Resources Checked: {results_summary.get('totalResources', 0)}")
        print(f"  Passed: {results_summary.get('passed', 0)}")
        print(f"  Failed: {results_summary.get('failed', 0)}")
        print(f"  Errors: {results_summary.get('errors', 0)}")
        
        individual_results = results_summary.get('results', [])
        if individual_results:
            print(f"\nIndividual Results:")
            print(f"{'Resource ID':<50} {'Status':<10} {'Message':<30}")
            print("-" * 90)
            
            for result in individual_results:
                resource_id = result.get('resourceId', 'N/A')[:48]
                status = result.get('status', 'N/A')
                message = result.get('message', 'N/A')[:28]
                print(f"{resource_id:<50} {status:<10} {message:<30}")
    
    if 'resourceData' in results:
        print(f"\nResource Data:")
        print(json.dumps(results['resourceData'], indent=2))
    
    print(f"\nFull Response:")
    print(json.dumps(results, indent=2))

def main():
    parser = argparse.ArgumentParser(
        description="Trend Vision One CSPM CLI Tool - Manage custom rules and perform dry runs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # List all custom rules
  python cspm_cli.py rules list
  
  # Create rule from file
  python cspm_cli.py rules create --file rule.json
  
  # Get rule details
  python cspm_cli.py rules get RULE_ID
  
  # Delete a rule
  python cspm_cli.py rules delete RULE_ID
  
  # Delete all rules (with confirmation)
  python cspm_cli.py rules delete-all
  
  # Delete all rules (force, no confirmation)
  python cspm_cli.py rules delete-all --force
  
  # List accounts
  python cspm_cli.py accounts list
  
  # Dry run a rule from file
  python cspm_cli.py dry-run --file rule.json --account ACCOUNT_ID
  
  # Dry run existing rule
  python cspm_cli.py dry-run --rule-id RULE_ID --account ACCOUNT_ID
  
  # Dry run with resource data
  python cspm_cli.py dry-run --file rule.json --account ACCOUNT_ID --resource-data

Environment Variables:
  You can set your API key using environment variables:
  export TMV1_TOKEN="your-api-key"
  export VISION_ONE_API_KEY="your-api-key"
        """
    )
    
    # Global arguments
    parser.add_argument("--api-key", help="Trend Vision One API key (Bearer token)")
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Rules subcommand
    rules_parser = subparsers.add_parser('rules', help='Manage custom rules')
    rules_subparsers = rules_parser.add_subparsers(dest='rules_action', help='Rules actions')
    
    # Rules list
    rules_subparsers.add_parser('list', help='List all custom rules')
    
    # Rules get
    rules_get_parser = rules_subparsers.add_parser('get', help='Get rule details')
    rules_get_parser.add_argument('rule_id', help='Rule ID to get')
    
    # Rules create
    rules_create_parser = rules_subparsers.add_parser('create', help='Create a new rule')
    rules_create_parser.add_argument('--file', required=True, help='JSON file containing rule definition')
    
    # Rules delete
    rules_delete_parser = rules_subparsers.add_parser('delete', help='Delete a rule')
    rules_delete_parser.add_argument('rule_id', help='Rule ID to delete')
    rules_delete_parser.add_argument('--force', action='store_true', help='Skip confirmation')
    
    # Rules delete-all
    rules_delete_all_parser = rules_subparsers.add_parser('delete-all', help='Delete all rules')
    rules_delete_all_parser.add_argument('--force', action='store_true', help='Skip confirmation')
    
    # Rules delete-pattern
    rules_delete_pattern_parser = rules_subparsers.add_parser('delete-pattern', help='Delete rules matching pattern')
    rules_delete_pattern_parser.add_argument('pattern', help='Pattern to match in rule name or ID')
    rules_delete_pattern_parser.add_argument('--force', action='store_true', help='Skip confirmation')
    
    # Accounts subcommand
    accounts_parser = subparsers.add_parser('accounts', help='Manage accounts')
    accounts_subparsers = accounts_parser.add_subparsers(dest='accounts_action', help='Accounts actions')
    accounts_subparsers.add_parser('list', help='List all Cloud Posture accounts')
    
    # Dry run subcommand
    dry_run_parser = subparsers.add_parser('dry-run', help='Perform dry run of a rule')
    dry_run_group = dry_run_parser.add_mutually_exclusive_group(required=True)
    dry_run_group.add_argument('--file', help='JSON file containing rule definition')
    dry_run_group.add_argument('--rule-id', help='ID of existing rule to test')
    dry_run_parser.add_argument('--account', required=True, help='Account ID to test against')
    dry_run_parser.add_argument('--resource-data', action='store_true', help='Return resource data in response')
    
    args = parser.parse_args()
    
    # Get API key
    api_key = args.api_key
    if not api_key:
        api_key = os.environ.get('TMV1_TOKEN') or os.environ.get('VISION_ONE_API_KEY')
        if not api_key:
            print("❌ API key is required. Provide it via --api-key argument or set TMV1_TOKEN or VISION_ONE_API_KEY environment variable.")
            sys.exit(1)
    
    # Initialize CLI
    cli = CSPMCLI(api_key)
    
    try:
        if args.command == 'rules':
            if args.rules_action == 'list':
                rules = cli.list_custom_rules()
                if rules is not None:
                    format_rules_table(rules)
                    print(f"\nTotal custom rules: {len(rules)}")
                    
            elif args.rules_action == 'get':
                rule = cli.get_custom_rule(args.rule_id)
                if rule:
                    print("\n" + "="*60)
                    print(json.dumps(rule, indent=2))
                    
            elif args.rules_action == 'create':
                try:
                    with open(args.file, 'r') as f:
                        rule_data = json.load(f)
                    print(f"📝 Creating custom rule from {args.file}...")
                except FileNotFoundError:
                    print(f"❌ Rule file not found: {args.file}")
                    sys.exit(1)
                except json.JSONDecodeError as e:
                    print(f"❌ Invalid JSON in rule file: {e}")
                    sys.exit(1)
                
                result = cli.create_custom_rule(rule_data)
                if result:
                    print(f"✅ Created custom rule with ID: {result.get('id')}")
                    
            elif args.rules_action == 'delete':
                if not args.force:
                    confirm = input(f"Are you sure you want to delete rule {args.rule_id}? (y/N): ")
                    if confirm.lower() != 'y':
                        print("❌ Deletion cancelled.")
                        sys.exit(0)
                
                success = cli.delete_custom_rule(args.rule_id)
                if not success:
                    sys.exit(1)
                    
            elif args.rules_action == 'delete-all':
                results = cli.delete_all_rules(args.force)
                
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
                    
            elif args.rules_action == 'delete-pattern':
                results = cli.delete_rules_by_pattern(args.pattern, args.force)
                
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
                    
        elif args.command == 'accounts':
            if args.accounts_action == 'list':
                accounts = cli.list_accounts()
                if accounts is not None:
                    format_accounts_table(accounts)
                    print(f"\nTotal accounts: {len(accounts)}")
                else:
                    print("❌ Failed to fetch accounts.")
                    sys.exit(1)
                    
        elif args.command == 'dry-run':
            if args.file:
                print(f"🧪 Performing dry run of rule from file: {args.file}")
                results = cli.dry_run_rule_from_file(args.file, args.account, args.resource_data)
            else:
                print(f"🧪 Performing dry run of existing rule: {args.rule_id}")
                results = cli.dry_run_existing_rule(args.rule_id, args.account, args.resource_data)
            
            if results:
                format_dry_run_results(results)
            else:
                print("❌ Dry run failed.")
                sys.exit(1)
                
        else:
            parser.print_help()
            
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
