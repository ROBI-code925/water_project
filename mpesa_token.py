import requests
from requests.auth import HTTPBasicAuth

# Replace these with your Daraja API credentials
consumer_key = "FYpyFv1kyC2FeXY6U90GZdsi7TCkbWwzE0U7HzAxIzC14dJj"
consumer_secret = "1UceoPA2dPG9gvOr2scA5683opsxHK6eQJpRRfelMwYhy1Fcf5tzoVRHoGc5uf2Q"

def get_mpesa_access_token():
    url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
    response = requests.get(url, auth=HTTPBasicAuth(consumer_key, consumer_secret))
    
    if response.status_code == 200:
        return response.json().get("access_token")
    else:
        return None  # Handle errors

# Test the function
print(get_mpesa_access_token())
