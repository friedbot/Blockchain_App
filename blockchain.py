import datetime
import hashlib
import json
import threading
import time
import os
import firebase_admin
from firebase_admin import credentials, firestore

BLOCKCHAIN_FILE = 'blockchain.json'  # Local backup file (optional)


class Blockchain:
    def __init__(self):
        self.initialize_firebase()  # Initialize Firebase first
        self.chain = self.load_chain()  # Load blockchain from local file (optional)
        self.transactions = []
        self.wallets = self.load_wallets()
        self.users = self.load_users()
        self.allowed_denominations = [1, 2, 5, 10, 50, 100, 200, 500]

        if not self.chain:
            self.create_block(proof=1, previous_hash='0')

        # Start the validity check in a separate thread
        self.start_validity_check()

    def initialize_firebase(self):
        cred = credentials.Certificate(
            'blockchainapp-e45d8-firebase-adminsdk-jfmvu-58c2068b24.json')  # Your Firebase Admin SDK key
        firebase_admin.initialize_app(cred)
        self.db = firestore.client()  # Initialize Firestore client

    def save_wallets(self):
        # Save all wallets to Firestore
        for username, wallet_data in self.wallets.items():
            # Convert all fields to strings
            wallet_data_stringified = {
                'balance': str(wallet_data['balance']),  # Save balance as string for Firestore
                'password': wallet_data['password'],  # Assuming password remains hashed
                'denominations': {str(amount): list(map(str, serials)) for amount, serials in
                                  wallet_data['denominations'].items()},
                'is_suspended': str(wallet_data.get('is_suspended', "False"))  # Ensure is_suspended is a string
            }

            try:
                doc_ref = self.db.collection('wallets').document(username)
                doc_ref.set(wallet_data_stringified)  # Synchronous write
                print(f"Wallet for {username} updated successfully in Firestore.")
            except Exception as e:
                print(f"Failed to update wallet for {username} in Firestore: {e}")

    def load_wallets(self):
        wallets = {}
        try:
            wallets_ref = self.db.collection('wallets')
            for doc in wallets_ref.stream():
                wallet_data = doc.to_dict()
                # Convert balance to float when loading
                wallet_data['balance'] = float(wallet_data['balance'])
                wallets[doc.id] = wallet_data
            print("Wallets loaded successfully.")
        except Exception as e:
            print(f"Failed to load wallets: {e}")
        return wallets

    def create_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.datetime.now()),
            'proof': proof,
            'previous_hash': previous_hash,
            'transactions': self.transactions
        }
        block['hash'] = self.hash(block)
        self.transactions = []
        self.chain.append(block)
        self.save_chain()
        return block

    def get_previous_block(self):
        if len(self.chain) == 0:
            raise IndexError("Blockchain is empty, no previous block found.")
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while not check_proof:
            hash_operation = hashlib.sha256(
                str(new_proof ** 2 - previous_proof ** 2).encode()
            ).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    def hash(self, block):
        block_copy = block.copy()
        block_copy.pop('hash', None)
        encoded_block = json.dumps(block_copy, sort_keys=True).encode()
        return hashlib.sha256(encoded_block).hexdigest()

    def is_chain_valid(self, chain):
        if not chain:
            return True  # An empty chain is considered valid

        previous_block = chain[0]
        block_index = 1
        while block_index < len(chain):
            block = chain[block_index]
            if block['previous_hash'] != self.hash(previous_block):
                return False
            previous_proof = previous_block['proof']
            proof = block['proof']
            hash_operation = hashlib.sha256(
                str(proof ** 2 - previous_proof ** 2).encode()
            ).hexdigest()
            if hash_operation[:4] != '0000':
                return False
            previous_block = block
            block_index += 1
        return True

    def add_transaction_and_create_block(self, sender, password, receiver, amount):
        optimized_amount = self.optimize_amount(amount)

        if sender not in self.wallets:
            return "Sender wallet does not exist", 400
        if receiver not in self.wallets:
            return "Receiver wallet does not exist", 400

        if not self.verify_password(sender, password):
            return "Incorrect password", 400

        # Ensure balance comparison is done as float
        if float(self.wallets[sender]['balance']) < optimized_amount:
            return "Sender does not have enough funds", 400

        if self.wallets[sender].get('is_suspended') is "True":
            return "Sender's wallet is suspended", 400

        transaction = {
            'sender': sender,
            'receiver': receiver,
            'amount': str(optimized_amount),  # Convert to string for storage
            'status': 'success'
        }

        self.transactions.append(transaction)
        self.transfer_funds(sender, receiver, optimized_amount)

        previous_block = self.get_previous_block()
        previous_proof = previous_block['proof']
        proof = self.proof_of_work(previous_proof)
        previous_hash = self.hash(previous_block)
        block = self.create_block(proof, previous_hash)
        return block

    def optimize_amount(self, amount):
        denominations = sorted(self.allowed_denominations, reverse=True)
        result = 0
        for denom in denominations:
            while amount >= denom:
                result += denom
                amount -= denom
        return result

    def transfer_funds(self, sender, receiver, amount):
        self.wallets[sender]['balance'] -= amount
        self.wallets[receiver]['balance'] += amount
        self.save_wallets()

    def create_wallet(self, address, password):
        if address in self.wallets:
            raise ValueError("Wallet already exists")
        self.wallets[address] = {
            'balance': 0.0,  # Ensure balance is a float
            'password': self.hash_password(password),
            'denominations': {},
            'is_suspended': False
        }
        self.save_wallets()
        return self.wallets[address]['balance']

    def get_balance(self, address):
        if address in self.wallets:
            return self.wallets[address]['balance']
        else:
            raise ValueError("Wallet does not exist")

    def add_funds(self, address, amount, serial):
        if address not in self.wallets:
            raise ValueError("Wallet does not exist")

        if amount not in self.allowed_denominations:
            raise ValueError("Amount must be in allowed denominations")

        # Check for duplicate serial numbers
        for wallet in self.wallets.values():
            if serial in [s for serials in wallet['denominations'].values() for s in serials]:
                self.transactions.append({
                    'sender': 'Admin',
                    'receiver': address,
                    'amount': str(amount),
                    'serial_number': str(serial),
                    'status': 'failed',
                    'reason': 'Duplicate serial number'
                })
                return "Duplicate serial number", 400

        # Update wallet and balance
        self.wallets[address]['denominations'].setdefault(amount, []).append(str(serial))

        # Ensure the balance is treated as a float before updating
        current_balance = self.wallets[address]['balance']
        self.wallets[address]['balance'] = float(current_balance) + float(amount)

        # Save the new balance as a string for Firestore
        self.wallets[address]['balance'] = str(self.wallets[address]['balance'])

        transaction = {
            'sender': 'Admin',
            'receiver': address,
            'amount': str(amount),
            'serial_number': str(serial),
            'status': 'success'
        }
        self.transactions.append(transaction)

        previous_block = self.get_previous_block()
        proof = self.proof_of_work(previous_block['proof'])
        previous_hash = self.hash(previous_block)
        block = self.create_block(proof, previous_hash)

        self.save_wallets()  # Save wallets to Firestore immediately after funds are added
        return block

    def suspend_wallet(self, address):
        if address in self.wallets:
            self.wallets[address]['is_suspended'] = "True"
            self.save_wallets()
        else:
            raise ValueError("Wallet does not exist")

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def verify_password(self, username, password):
        hashed_password = self.wallets.get(username, {}).get('password')
        return hashed_password == self.hash_password(password)

    def save_users(self):
        # Save all users to Firestore
        for username, user_data in self.users.items():
            try:
                doc_ref = self.db.collection('users').document(username)
                doc_ref.set(user_data)  # Assuming user_data is already a dictionary with the required fields
                print(f"User {username} updated successfully in Firestore.")
            except Exception as e:
                print(f"Failed to update user {username} in Firestore: {e}")

    def load_users(self):
        # Load users from Firestore
        users = {}
        try:
            users_ref = self.db.collection('users')
            for doc in users_ref.stream():
                user_data = doc.to_dict()
                users[doc.id] = user_data
            print("Users loaded successfully.")
        except Exception as e:
            print(f"Failed to load users: {e}")
        return users

    def load_chain(self):
        # Load blockchain from local file (optional)
        if os.path.exists(BLOCKCHAIN_FILE):
            with open(BLOCKCHAIN_FILE, 'r') as file:
                return json.load(file)
        return []

    def save_chain(self):
        # Save blockchain to local file (optional)
        with open(BLOCKCHAIN_FILE, 'w') as file:
            json.dump(self.chain, file)

    def start_validity_check(self):
        # Start a separate thread to check validity
        validity_thread = threading.Thread(target=self.check_validity, daemon=True)
        validity_thread.start()

    def check_validity(self):
        while True:
            time.sleep(60)  # Check every 60 seconds
            if not self.is_chain_valid(self.chain):
                print("Blockchain is invalid!")
            else:
                print("Blockchain is valid.")

    def list_serial_numbers(self, address):
        if address not in self.wallets:
            raise ValueError("Wallet does not exist")

        denominations = self.wallets[address]['denominations']
        serial_numbers = {amount: serials for amount, serials in denominations.items()}
        return serial_numbers
# Example usage
