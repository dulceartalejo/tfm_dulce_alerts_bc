import json
from kafka import KafkaConsumer
import ecdsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.hashes import SHA256
import requests
import datetime

PRIVATE_KEY_FOLDER = "/secure_path/keys/"
PUBLIC_KEY = "/secure_path/keys/public_key.pem"
PRIVATE_KEY = "/secure_path/keys/private_key.pem"

def get_private_key_by_source(source, algorithm):
    # Look for the private key that matches the source and signing mechanism
    private_key_base = "private_key.pem"

    if algorithm == "ecdsa":
        key_file = source + "_ecdsa_" + private_key_base
    elif algorithm == "rsa":
        key_file = source + "_rsa_" + private_key_base
    else:
        print("There has beee an error when generating the key file name.")

    private_key_path = PRIVATE_KEY_FOLDER + key_file
    with open(private_key_path, "r") as key_file:
        private_key = key_file.read()
    return private_key

    raise ValueError(f"Private key for source '{source}' not found.")

def sign_alert(alert, private_key, algorithm):
    if algorithm == "ecdsa":
        # In this example, we'll use ECDSA for signing
        sk = ecdsa.SigningKey.from_pem(private_key)
        signature = sk.sign(json.dumps(alert).encode())
        return signature
    elif algorithm == "rsa":
        # RSA used for signing
        private_key_bytes = private_key.encode()
        private_key_obj = serialization.load_pem_private_key(
            private_key_bytes, password=None, backend=default_backend())

        signature = private_key_obj.sign(json.dumps(alert).encode(), padding.PKCS1v15(), SHA256())
        return signature
    else:
        # Raise error
        raise ValueError(f"Signing mechanism '{algorithm}' not implemented, try with a different one.")

def upload_to_blockchain(alert, signature):
    # Convert signed alert to JSON strings
    signed_alert_json = json.dumps(signature)

    # Define the Sawtooth REST API URL
    sawtooth_api_url = "http://localhost:8008/batches"

    # Define the payload for the transaction
    payload = {
        "data": [alert, signed_alert_json],
    }

    # Define the transaction header
    transaction_header = {
        "family_name": "tfm_dulce",
        "family_version": "1.0",
        "inputs": ["imput_address"],
        "outputs": ["output_address"],
        # Other required fields can be added for the transaction header
    }

    # Serialize the transaction header for signing
    serialized_header = json.dumps(transaction_header, sort_keys=True).encode()

    # Sign the serialized header using your signer's private key
    private_key_obj = serialization.load_pem_private_key(
        PRIVATE_KEY.encode(), password=None, backend=default_backend()
    )
    transaction_header_signature = private_key_obj.sign(serialized_header, padding.PKCS1v15(), SHA256())


    # Create the transaction
    transaction = {
        "header": transaction_header,
        "payload": payload,
        "header_signature": transaction_header_signature.hex()
    }

    # Define the batch header
    batch_header = {
        "signer_public_key": PUBLIC_KEY,
        "transaction_ids": [transaction["header_signature"]]
    }

    # Create the batch
    batch = {
        "header": batch_header,
        "transactions": [transaction]
    }

    # Send the batch to the Sawtooth REST API
    try:
        response = requests.post(sawtooth_api_url, json=batch)
        response.raise_for_status()
        block_id = response.json()["link"]
        return block_id
    except requests.exceptions.RequestException as e:
        print(f"Error sending batch to the Sawtooth REST API: {e}")
        return None


def main():
    # Used Kafka topic and bootstrap server for our configuration, Visual Studio Code used for the tests
    consumer = KafkaConsumer("quickstart-events", bootstrap_servers="your_ip:9092", client_id="vscode1")

    while True:
        for message in consumer:
            print(message)
            try:
                alert = json.loads(message.value)
                print(alert)
                tags = alert.get("tags")
                source = tags.get("source")
                algorithm = tags.get("alg")
                if source and algorithm:
                    private_key = get_private_key_by_source(source, algorithm)
                    signature = sign_alert(alert, private_key, algorithm)
                    print(signature)

                    # Uploading both the original alert and the signed one
                    block_id = upload_to_blockchain(alert, signature)
                    print(f"Upload Time: {datetime.datetime.now()}")
                    print(f"Your alert has been successfully added to the blockchain, its ID is: {block_id}")
                else:
                    print("Alert does not contain the 'source' or 'alg' field. Skipping...")
            except Exception as e:
               print(f"Error processing the message: {e}")

if __name__ == "__main__":
    main()
