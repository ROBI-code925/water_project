import requests
import base64
import datetime
from requests.auth import HTTPBasicAuth

# Your Safaricom API credentials
business_short_code = "174379"  # Use your M-Pesa paybill or till number
lipa_na_mpesa_passkey = "YOUR_PASSKEY_HERE"  # Get this from Daraja Portal
phone_number = "254769537113"  # Replace with the customer's phone number
amount = 1  # Amount to pay
callback_url = "https://yourwebsite.com/callback"  # Replace with your callback URL

# Get the access token
consumer_key = "FYpyFv1kyC2FeXY6U90GZdsi7TCkbWwzE0U7HzAxIzC14dJj"
consumer_secret = "1UceoPA2dPG9gvOr2scA5683opsxHK6eQJpRRfelMwYhy1Fcf5tzoVRHoGc5uf2Q"
token_url = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"

response = requests.get(token_url, auth=HTTPBasicAuth(consumer_key, consumer_secret))
access_token = response.json()["zBtWNaOmgYYEnO9MkZ6Vi3RQMPsl"]

# Generate timestamp
timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")

# Encode passkey to get password
data_to_encode = business_short_code + lipa_na_mpesa_passkey + timestamp
password = base64.b64encode(data_to_encode.encode()).decode("utf-8")

# API URL for STK Push
stk_push_url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"

headers = {
    "Authorization": f"Bearer {access_token}",
    "Content-Type": "application/json",
}

payload = {
    "BusinessShortCode": business_short_code,
    "Password": password,
    "Timestamp": timestamp,
    "TransactionType": "CustomerPayBillOnline",
    "Amount": amount,
    "PartyA": phone_number,
    "PartyB": business_short_code,
    "PhoneNumber": phone_number,
    "CallBackURL": callback_url,
    "AccountReference": "WaterBilling",
    "TransactionDesc": "Payment for water consumption",
}

# Send request
response = requests.post(stk_push_url, json=payload, headers=headers)

print(response.json())  # Print response
