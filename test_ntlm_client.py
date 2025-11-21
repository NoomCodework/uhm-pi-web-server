"""
Test client for NTLM FastAPI server
User: NoomCodework
Date: 2025-10-28 11:51:11
"""

import requests
from requests_ntlm import HttpNtlmAuth
import json

BASE_URL = "http://localhost:8000"

# Test credentials
USERNAME = "noom"
PASSWORD = "password123"
DOMAIN = "CODEWORK"

def print_response(title: str, response: requests.Response):
    """Pretty print response"""
    print(f"\n{'='*70}")
    print(f"  {title}")
    print(f"{'='*70}")
    print(f"Status: {response.status_code}")
    try:
        print(f"Response:\n{json.dumps(response.json(), indent=2)}")
    except:
        print(f"Response: {response.text}")

def main():
    print("="*70)
    print("  FastAPI NTLM Client Test")
    print("  User: NoomCodework")
    print("  Date: 2025-10-28 11:51:11")
    print("="*70)
    
    # Create session with NTLM authentication
    session = requests.Session()
    session.auth = HttpNtlmAuth(f'{DOMAIN}\\{USERNAME}', PASSWORD)
    print(session)
    
    try:
        # # Test 1: Health check (no auth)
        # print("\n[Test 1] Health Check (No Authentication)")
        # response = requests.get(f"{BASE_URL}/health")
        # print_response("Health Check", response)
        
        # Test 2: Get current user
        print("\n[Test 2] Get Current User (NTLM Auth)")
        response = session.get(f"{BASE_URL}/api/me")
        print_response("Current User", response)
        
        # # Test 3: Get all items
        # print("\n[Test 3] Get All Items")
        # response = session.get(f"{BASE_URL}/api/items")
        # print_response("Get Items", response)
        
        # # Test 4: Get specific item
        # print("\n[Test 4] Get Specific Item (ID: 1)")
        # response = session.get(f"{BASE_URL}/api/items/1")
        # print_response("Get Item 1", response)
        
        # Test 5: Create new item
        # print("\n[Test 5] Create New Item")
        # new_item = {
        #     "name": "NTLM Test Item",
        #     "description": "Created via NTLM authentication",
        #     "price": 199.99
        # }
        # response = session.post(f"{BASE_URL}/api/items", json=new_item)
        # print_response("Create Item", response)
        
        # # Test 6: Update item
        # print("\n[Test 6] Update Item (ID: 1)")
        # updated_item = {
        #     "name": "Updated NTLM Item",
        #     "description": "Updated via NTLM",
        #     "price": 299.99
        # }
        # response = session.put(f"{BASE_URL}/api/items/1", json=updated_item)
        # print_response("Update Item", response)
        
        # # Test 7: Delete item
        # print("\n[Test 7] Delete Item (ID: 1)")
        # response = session.delete(f"{BASE_URL}/api/items/1")
        # print_response("Delete Item", response)
        
        # # Test 8: List users
        # print("\n[Test 8] List All Users")
        # response = session.get(f"{BASE_URL}/api/users")
        # print_response("List Users", response)
        
        # # Test 9: Unauthorized access
        # print("\n[Test 9] Unauthorized Access (No Auth)")
        # response = requests.get(f"{BASE_URL}/api/items")
        # print_response("Unauthorized Request", response)
        
        print("\n" + "="*70)
        print("  ✅ All Tests Completed!")
        print("="*70)
        
    except requests.exceptions.ConnectionError:
        print("\n❌ Connection Error: Could not connect to server")
        print("   Make sure the server is running on", BASE_URL)
    except Exception as e:
        print(f"\n❌ Error: {e}")

if __name__ == "__main__":
    main()