import requests

# SenderApp API URL
sender_url = "http://127.0.0.1:8000/api/send_message/"

# Message Data
message_data = {
    "sender_username": "test_user",  # Ensure this user exists in the SenderApp database
    "recipient_username": "receiver_user",
    "priority": "high",
    "message_content": "Hello, this is the third test from SenderApp to ReceiverApp."
}

try:
    # Make the POST request to send the message
    response = requests.post(sender_url, json=message_data)  # Use `json` for structured payload

    # Check the response
    if response.status_code == 201:
        print("Message sent successfully!")
        print("Response:", response.json())
    else:
        print(f"Failed to send message. Status Code: {response.status_code}")
        print("Raw Response:", response.text)  # Print raw response content

except requests.RequestException as e:
    print(f"An error occurred: {e}")
