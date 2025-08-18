#!/usr/bin/env python3
"""
Trend Vision One Conformity Custom Rules Dry Run Tester

This script performs dry runs of custom rules to test their logic against existing resource data
without having to wait for the Conformity Bot to complete.

Based on Trend Micro Cloud One Conformity Custom Rules documentation:
https://docs.trendmicro.com/en-us/documentation/article/trend-micro-cloud-one-conformity-getstartcustomrules

Usage:
    python dry_run_rules.py --api-key YOUR_API_KEY --rule-file rule.json --account-id ACCOUNT_ID
    python dry_run_rules.py --api-key YOUR_API_KEY --rule-id RULE_ID --account-id ACCOUNT_ID
    python dry_run_rules.py --api-key YOUR_API_KEY --rule-file rule.json --account-id ACCOUNT_ID --resource-data
    python dry_run_rules.py --api-key YOUR_API_KEY --list-accounts
"""

import argparse
import json
import os
import requests
import sys
from typing import Dict, List, Optional, Any

class ConformityDryRunTester:
    def __init__(self, api_key: str):
        """
        Initialize the Conformity Dry Run Tester.
        
        Args:
            api_key: Trend Vision One API key (Bearer token)
        """
        self.api_key = api_key
        
        # Trend Vision One API base URL and path
        self.url_base = "https://api.xdr.trendmicro.com"
        self.url_path = "/beta/c1/conformity/custom-rules/run"
        self.headers = {
            "Authorization": "Bearer " + self.api_key,
            "Content-Type": "application/vnd.api+json"
        }

    def list_accounts(self) -> Optional[List[Dict[str, Any]]]:
        """
        List all Cloud Posture accounts.
        
        Returns:
            List of accounts or None if failed
        """
        url = f"{self.url_base}/beta/cloudPosture/accounts"
        
        try:
            print(f"Fetching accounts from: {url}")
            response = requests.get(url, headers=self.headers)
            
            print(f"Response Status: {response.status_code}")
            
            if response.status_code == 200:
                data = response.json()
                print(f"Raw response: {json.dumps(data, indent=2)}")
                
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

    def dry_run_rule_from_file(self, rule_file: str, account_id: str, resource_data: bool = False) -> Optional[Dict[str, Any]]:
        """
        Perform a dry run of a custom rule from a JSON file.
        
        Args:
            rule_file: Path to the JSON file containing the rule definition
            account_id: The account ID to test against
            resource_data: Whether to return resource data in the response
            
        Returns:
            Dry run results or None if failed
        """
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
        """
        Perform a dry run of an existing custom rule by ID.
        
        Args:
            rule_id: The ID of the existing custom rule
            account_id: The account ID to test against
            resource_data: Whether to return resource data in the response
            
        Returns:
            Dry run results or None if failed
        """
        # First, get the existing rule
        rule_data = self._get_existing_rule(rule_id)
        if not rule_data:
            return None
        
        return self._perform_dry_run(rule_data, account_id, resource_data)

    def _get_existing_rule(self, rule_id: str) -> Optional[Dict[str, Any]]:
        """
        Get an existing custom rule by ID.
        
        Args:
            rule_id: The ID of the custom rule
            
        Returns:
            Rule data or None if failed
        """
        url = f"{self.url_base}/beta/c1/conformity/custom-rules/{rule_id}"
        
        try:
            print(f"Fetching existing rule {rule_id} from: {url}")
            response = requests.get(url, headers=self.headers)
            
            print(f"Response Status: {response.status_code}")
            
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
        """
        Perform the actual dry run request.
        
        Args:
            rule_data: The rule configuration data
            account_id: The account ID to test against
            resource_data: Whether to return resource data in the response
            
        Returns:
            Dry run results or None if failed
        """
        url = self.url_base + self.url_path
        
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
            print(f"Performing dry run at: {url}")
            print(f"Account ID: {account_id}")
            print(f"Resource data requested: {resource_data}")
            print(f"Request parameters: {params}")
            print(f"Request body: {json.dumps(request_body, indent=2)}")
            
            response = requests.post(url, headers=self.headers, params=params, json=request_body)
            
            print(f"Response Status: {response.status_code}")
            
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

def format_accounts_table(accounts: List[Dict[str, Any]]) -> None:
    """
    Format and display accounts in a table.
    
    Args:
        accounts: List of account data
    """
    if not accounts:
        print("No accounts found.")
        return
    
    print(f"\n{'Account ID':<15} {'Name':<30} {'Type':<15} {'Status':<15} {'Provider':<10}")
    print("-" * 85)
    
    for account in accounts:
        account_id = account.get('id', 'N/A')[:13]
        attributes = account.get('attributes', {})
        name = attributes.get('name', 'N/A')[:28]
        account_type = attributes.get('type', 'N/A')[:13]
        status = attributes.get('status', 'N/A')[:13]
        provider = attributes.get('provider', 'N/A')[:8]
        
        print(f"{account_id:<15} {name:<30} {account_type:<15} {status:<15} {provider:<10}")

def format_dry_run_results(results: Dict[str, Any]) -> None:
    """
    Format and display dry run results in a readable format.
    
    Args:
        results: The dry run results from the API
    """
    print("\n" + "="*80)
    print("DRY RUN RESULTS")
    print("="*80)
    
    # Display basic results
    if 'data' in results:
        data = results['data']
        print(f"Rule Name: {data.get('attributes', {}).get('name', 'N/A')}")
        print(f"Service: {data.get('attributes', {}).get('service', 'N/A')}")
        print(f"Resource Type: {data.get('attributes', {}).get('resourceType', 'N/A')}")
        print(f"Severity: {data.get('attributes', {}).get('severity', 'N/A')}")
        print(f"Provider: {data.get('attributes', {}).get('provider', 'N/A')}")
        
        # Display results summary
        results_summary = data.get('results', {})
        print(f"\nResults Summary:")
        print(f"  Total Resources Checked: {results_summary.get('totalResources', 0)}")
        print(f"  Passed: {results_summary.get('passed', 0)}")
        print(f"  Failed: {results_summary.get('failed', 0)}")
        print(f"  Errors: {results_summary.get('errors', 0)}")
        
        # Display individual results
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
    
    # Display resource data if present
    if 'resourceData' in results:
        print(f"\nResource Data:")
        print(json.dumps(results['resourceData'], indent=2))
    
    # Display full response if requested
    print(f"\nFull Response:")
    print(json.dumps(results, indent=2))

def main():
    parser = argparse.ArgumentParser(
        description="Perform dry runs of Trend Vision One Conformity custom rules and manage accounts",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  List all accounts:
    python dry_run_rules.py --api-key YOUR_KEY --list-accounts
    # Or with environment variable:
    export TMV1_TOKEN="your-token"
    python dry_run_rules.py --list-accounts

  Dry run a rule from file:
    python dry_run_rules.py --api-key YOUR_KEY --rule-file rule.json --account-id ACCOUNT_ID
    # Or with environment variable:
    export TMV1_TOKEN="your-token"
    python dry_run_rules.py --rule-file rule.json --account-id ACCOUNT_ID

  Dry run an existing rule by ID:
    python dry_run_rules.py --api-key YOUR_KEY --rule-id RULE_ID --account-id ACCOUNT_ID
    # Or with environment variable:
    python dry_run_rules.py --rule-id RULE_ID --account-id ACCOUNT_ID

  Dry run with resource data returned:
    python dry_run_rules.py --api-key YOUR_KEY --rule-file rule.json --account-id ACCOUNT_ID --resource-data

Security Note:
  Consider using environment variables for API keys:
  export TMV1_TOKEN="your-api-key"
  python dry_run_rules.py --list-accounts
  
  Or use VISION_ONE_API_KEY:
  export VISION_ONE_API_KEY="your-api-key"
  python dry_run_rules.py --list-accounts
        """
    )
    
    parser.add_argument("--api-key", help="Trend Vision One API key (Bearer token). Can also be set via TMV1_TOKEN or VISION_ONE_API_KEY environment variables.")
    parser.add_argument("--list-accounts", action="store_true", help="List all Cloud Posture accounts")
    parser.add_argument("--rule-file", help="JSON file containing rule definition")
    parser.add_argument("--rule-id", help="ID of an existing custom rule to test")
    parser.add_argument("--account-id", help="Account ID to test the rule against")
    parser.add_argument("--resource-data", action="store_true", help="Return resource data in the response")
    
    args = parser.parse_args()
    
    # Get API key from command line argument or environment variables
    api_key = args.api_key
    if not api_key:
        # Try environment variables in order of preference
        api_key = os.environ.get('TMV1_TOKEN') or os.environ.get('VISION_ONE_API_KEY')
        if not api_key:
            print("❌ API key is required. Provide it via --api-key argument or set TMV1_TOKEN or VISION_ONE_API_KEY environment variable.")
            sys.exit(1)
    
    # Initialize tester
    tester = ConformityDryRunTester(api_key)
    
    try:
        if args.list_accounts:
            print("🔍 Fetching Cloud Posture accounts...")
            accounts = tester.list_accounts()
            if accounts is not None:
                format_accounts_table(accounts)
                print(f"\nTotal accounts: {len(accounts)}")
            else:
                print("❌ Failed to fetch accounts.")
                sys.exit(1)
        else:
            # Dry run mode - validate required arguments
            if not args.rule_file and not args.rule_id:
                print("❌ Either --rule-file or --rule-id must be specified for dry run mode.")
                sys.exit(1)
            
            if args.rule_file and args.rule_id:
                print("❌ Only one of --rule-file or --rule-id should be specified.")
                sys.exit(1)
            
            if not args.account_id:
                print("❌ --account-id is required for dry run mode.")
                sys.exit(1)
            
            # Perform dry run
            if args.rule_file:
                print(f"🔍 Performing dry run of rule from file: {args.rule_file}")
                results = tester.dry_run_rule_from_file(args.rule_file, args.account_id, args.resource_data)
            else:
                print(f"🔍 Performing dry run of existing rule: {args.rule_id}")
                results = tester.dry_run_existing_rule(args.rule_id, args.account_id, args.resource_data)
            
            if results:
                format_dry_run_results(results)
            else:
                print("❌ Dry run failed.")
                sys.exit(1)
            
    except KeyboardInterrupt:
        print("\n❌ Operation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
