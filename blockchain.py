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
        self.chain = self.load_chain()  # Load blockchain from Firestore
        self.transactions = []
        self.wallets = self.load_wallets()  # Load wallets from Firestore
        self.users = self.load_users()  # Load user data from Firestore
        self.allowed_denominations = [1, 2, 5, 10, 50, 100, 200, 500]

        # Load the local copy of the blockchain (if it exists)
        self.local_chain = self.load_local_chain()  # Local blockchain copy

        if not self.chain:
            self.create_block(proof=1, previous_hash='0')  # Genesis block

        # Start threads for cloud synchronization and validity checks
        threading.Thread(target=self.sync_with_cloud, daemon=True).start()
        self.start_validity_check()  # Start validity check thread

    def initialize_firebase(self):
        cred = credentials.Certificate(
            'blockchainapp-e45d8-firebase-adminsdk-jfmvu-07e2e93a32.json')  # Firebase Admin SDK key
        firebase_admin.initialize_app(cred)
        self.db = firestore.client()  # Firestore client

    def save_local_chain(self):
        """ Save the blockchain to a local JSON file """
        try:
            with open(BLOCKCHAIN_FILE, 'w') as file:
                json.dump(self.chain, file, indent=4)
                print("Local blockchain copy saved.")
        except Exception as e:
            print(f"Failed to save local blockchain: {e}")

    def load_local_chain(self):
        """ Load the blockchain from the local JSON file """
        if os.path.exists(BLOCKCHAIN_FILE):
            try:
                with open(BLOCKCHAIN_FILE, 'r') as file:
                    chain = json.load(file)
                    print("Local blockchain copy loaded.")
                    return chain
            except Exception as e:
                print(f"Failed to load local blockchain: {e}")
        return []

    def update_local_copy(self, block):
        """ Update the local blockchain copy after a new block is created """
        self.local_chain.append(block)
        self.save_local_chain()  # Update the local file

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

        # Save the block in Firestore
        self.save_block_to_firestore(block)

        # Update the local copy
        self.update_local_copy(block)

        return block

    def save_block_to_firestore(self, block):
        try:
            doc_ref = self.db.collection('blockchain').document(str(block['index']))
            doc_ref.set(block)
            print(f"Block {block['index']} saved to Firestore.")
        except Exception as e:
            print(f"Failed to save block {block['index']} to Firestore: {e}")

    def load_chain(self):
        try:
            chain = []
            blockchain_ref = self.db.collection('blockchain')
            docs = blockchain_ref.stream()
            for doc in docs:
                chain.append(doc.to_dict())
            chain = sorted(chain, key=lambda x: x['index'])  # Ensure blocks are in order
            print("Blockchain loaded from Firestore.")
            return chain
        except Exception as e:
            print(f"Failed to load blockchain from Firestore: {e}")
        return []

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

        if float(self.wallets[sender]['balance']) < optimized_amount:
            return "Sender does not have enough funds", 400

        if self.wallets[sender].get('is_suspended') == "True":
            return "Sender's wallet is suspended", 400

        transaction = {
            'sender': sender,
            'receiver': receiver,
            'amount': str(optimized_amount),
            'status': 'success'
        }

        self.transactions.append(transaction)
        self.transfer_funds(sender, receiver, optimized_amount)

        previous_block = self.get_previous_block()
        proof = self.proof_of_work(previous_block['proof'])
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
            'balance': 0.0,
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

    def list_serial_numbers(self, address):
        if address not in self.wallets:
            raise ValueError("Wallet does not exist")

        denominations = self.wallets[address]['denominations']
        serial_numbers = {amount: serials for amount, serials in denominations.items()}
        return serial_numbers

    def add_funds(self, address, amount, serial):
        if address not in self.wallets:
            raise ValueError("Wallet does not exist")

        if amount not in self.allowed_denominations:
            raise ValueError("Amount must be in allowed denominations")

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

        self.wallets[address]['denominations'].setdefault(amount, []).append(str(serial))
        self.wallets[address]['balance'] = float(self.wallets[address]['balance']) + float(amount)
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

        self.save_wallets()
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

    def save_wallets(self):
        for username, wallet_data in self.wallets.items():
            wallet_data_stringified = {
                'balance': str(wallet_data['balance']),
                'password': wallet_data['password'],
                'denominations': {str(amount): list(map(str, serials)) for amount, serials in
                                  wallet_data['denominations'].items()},
                'is_suspended': str(wallet_data.get('is_suspended', "False"))
            }
            try:
                doc_ref = self.db.collection('wallets').document(username)
                doc_ref.set(wallet_data_stringified)
                print(f"Wallet for {username} updated successfully in Firestore.")
            except Exception as e:
                print(f"Failed to update wallet for {username} in Firestore: {e}")

    def load_wallets(self):
        wallets = {}
        try:
            wallets_ref = self.db.collection('wallets')
            for doc in wallets_ref.stream():
                wallet_data = doc.to_dict()
                wallet_data['balance'] = float(wallet_data['balance'])  # Convert balance to float
                wallets[doc.id] = wallet_data
            print("Wallets loaded successfully.")
        except Exception as e:
            print(f"Failed to load wallets: {e}")
        return wallets

    def load_users(self):
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

    def save_users(self):
        """ Save user data to Firestore """
        for username, user_data in self.users.items():
            try:
                doc_ref = self.db.collection('users').document(username)
                doc_ref.set(user_data)  # Save the entire user data
                print(f"User data for {username} saved successfully in Firestore.")
            except Exception as e:
                print(f"Failed to save user data for {username}: {e}")

    def sync_with_cloud(self):
        while True:
            time.sleep(60)  # Sync every 60 seconds
            self.save_wallets()
            self.save_users()
            self.chain = self.load_chain()
            self.local_chain = self.load_local_chain()
            print("Data synced with Firestore and local backup updated.")

    def start_validity_check(self):
        def check_validity():
            while True:
                time.sleep(600)  # Validate every 10 minutes
                is_valid = self.is_chain_valid(self.chain)
                print("Blockchain validity:", is_valid)

        threading.Thread(target=check_validity, daemon=True).start()

