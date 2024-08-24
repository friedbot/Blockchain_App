import datetime
import hashlib
import json
import threading
import time

BLOCKCHAIN_FILE = 'blockchain.json'
WALLETS_FILE = 'wallets.json'
USERS_FILE = 'users.json'

class Blockchain:
    def __init__(self):
        self.chain = self.load_chain()
        self.transactions = []
        self.wallets = self.load_wallets()
        self.users = self.load_users()
        self.allowed_denominations = [1, 2, 5, 10, 50, 100, 200, 500]

        if not self.chain:
            self.create_block(proof=1, previous_hash='0')

        # Start the validity check in a separate thread
        self.start_validity_check()

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

        if self.wallets[sender]['balance'] < optimized_amount:
            return "Sender does not have enough funds", 400

        if self.wallets[sender].get('is_suspended', False):
            return "Sender's wallet is suspended", 400

        transaction = {
            'sender': sender,
            'receiver': receiver,
            'amount': optimized_amount,
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
            'balance': 0,
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
        if address in self.wallets:
            if amount not in self.allowed_denominations:
                raise ValueError("Amount must be in allowed denominations")

            for wallet in self.wallets.values():
                if serial in [s for serials in wallet['denominations'].values() for s in serials]:
                    self.transactions.append({
                        'sender': 'Admin',
                        'receiver': address,
                        'amount': amount,
                        'serial_number': serial,
                        'status': 'failed',
                        'reason': 'Duplicate serial number'
                    })
                    self.save_chain()
                    return "Duplicate serial number", 400

            if amount not in self.wallets[address]['denominations']:
                self.wallets[address]['denominations'][amount] = []
            self.wallets[address]['denominations'][amount].append(serial)
            self.wallets[address]['balance'] += amount

            transaction = {
                'sender': 'Admin',
                'receiver': address,
                'amount': amount,
                'serial_number': serial,
                'status': 'success'
            }
            self.transactions.append(transaction)

            previous_block = self.get_previous_block()
            previous_proof = previous_block['proof']
            proof = self.proof_of_work(previous_proof)
            previous_hash = self.hash(previous_block)
            block = self.create_block(proof, previous_hash)
            self.save_wallets()
            return block

        else:
            raise ValueError("Wallet does not exist")

    def suspend_wallet(self, address):
        if address in self.wallets:
            self.wallets[address]['is_suspended'] = True
            self.save_wallets()
        else:
            raise ValueError("Wallet does not exist")

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def verify_password(self, username, password):
        hashed_password = self.hash_password(password)
        return self.users.get(username) == hashed_password

    def save_chain(self):
        with open(BLOCKCHAIN_FILE, 'w') as file:
            json.dump(self.chain, file, indent=4)

    def load_chain(self):
        try:
            with open(BLOCKCHAIN_FILE, 'r') as file:
                return json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            return []

    def save_wallets(self):
        with open(WALLETS_FILE, 'w') as file:
            json.dump(self.wallets, file, indent=4)

    def load_wallets(self):
        try:
            with open(WALLETS_FILE, 'r') as file:
                return json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def save_users(self):
        with open(USERS_FILE, 'w') as file:
            json.dump(self.users, file, indent=4)

    def load_users(self):
        try:
            with open(USERS_FILE, 'r') as file:
                return json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def start_validity_check(self):
        def check_validity_periodically():
            while True:
                if not self.is_chain_valid(self.chain):
                    print("Blockchain is not valid! Restoring from backup...")
                    self.restore_from_backup()
                else:
                    print("Blockchain is valid.")
                time.sleep(60)  # Check every 60 seconds

        # Start the thread
        threading.Thread(target=check_validity_periodically, daemon=True).start()

    def restore_from_backup(self):
        backup_file = 'blockchain_backup.json'
        if os.path.exists(backup_file):
            with open(backup_file, 'r') as file:
                self.chain = json.load(file)
            self.save_chain()
            print("Blockchain restored from backup.")
        else:
            print("Backup file does not exist.")
