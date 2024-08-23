import datetime
import hashlib
import json
from flask import Flask, jsonify, request, render_template, redirect, url_for

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

BLOCKCHAIN_FILE = 'blockchain.json'
WALLETS_FILE = 'wallets.json'

class Blockchain:
    def __init__(self):
        self.chain = self.load_chain()
        self.transactions = []
        self.wallets = self.load_wallets()  # Load wallets from JSON file
        self.allowed_denominations = [1, 2, 5, 10, 50, 100, 200, 500]

        # Check if the blockchain is empty and create a genesis block if necessary
        if not self.chain:
            self.create_block(proof=1, previous_hash='0')

    def create_block(self, proof, previous_hash):
        block = {
            'index': len(self.chain) + 1,
            'timestamp': str(datetime.datetime.now()),
            'proof': proof,
            'previous_hash': previous_hash,
            'transactions': self.transactions
        }
        block['hash'] = self.hash(block)  # Compute the hash of the block
        self.transactions = []
        self.chain.append(block)
        self.save_chain()  # Save the blockchain to the JSON file
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

        # Check if both sender and receiver wallets exist
        if sender not in self.wallets:
            return "Sender wallet does not exist", 400
        if receiver not in self.wallets:
            return "Receiver wallet does not exist", 400

        # Verify the password
        if not self.verify_password(sender, password):
            return "Incorrect password", 400

        # Check if the sender has enough balance
        if self.wallets[sender]['balance'] < optimized_amount:
            return "Sender does not have enough funds", 400

        # Check if the sender's wallet is suspended
        if self.wallets[sender].get('is_suspended', False):
            return "Sender's wallet is suspended", 400

        transaction = {
            'sender': sender,
            'receiver': receiver,
            'amount': optimized_amount,
            'status': 'success'  # Default status
        }

        # Add transaction to the list
        self.transactions.append(transaction)

        # Perform fund transfer if the transaction is valid
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
        # Update the wallet balances
        self.wallets[sender]['balance'] -= amount
        self.wallets[receiver]['balance'] += amount
        self.save_wallets()  # Save the updated wallets data

    def create_wallet(self, address, password):
        if address in self.wallets:
            raise ValueError("Wallet already exists")
        self.wallets[address] = {
            'balance': 0,
            'password': self.hash_password(password),
            'denominations': {},  # To store denominations with their serial numbers
            'is_suspended': False  # Initial state of the wallet
        }
        self.save_wallets()  # Save the new wallet
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

            # Check for serial number duplication
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
                    self.save_chain()  # Save the transaction to the blockchain
                    return "Duplicate serial number", 400

            # Add funds and serial number to the wallet
            if amount not in self.wallets[address]['denominations']:
                self.wallets[address]['denominations'][amount] = []
            self.wallets[address]['denominations'][amount].append(serial)
            self.wallets[address]['balance'] += amount

            # Record the transaction as successful
            transaction = {
                'sender': 'Admin',
                'receiver': address,
                'amount': amount,
                'serial_number': serial,
                'status': 'success'
            }
            self.transactions.append(transaction)

            # Add the transaction to the blockchain by creating a new block
            previous_block = self.get_previous_block()
            previous_proof = previous_block['proof']
            proof = self.proof_of_work(previous_proof)
            previous_hash = self.hash(previous_block)
            block = self.create_block(proof, previous_hash)
            self.save_wallets()  # Save the updated wallet data
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

    def verify_password(self, address, password):
        hashed_password = self.hash_password(password)
        return self.wallets[address]['password'] == hashed_password


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

blockchain = Blockchain()

@app.route('/')
def index():
    return render_template('index.html', denominations=blockchain.allowed_denominations)

@app.route('/get_chain', methods=['GET'])
def get_chain():
    chain = blockchain.chain
    return render_template('chain.html', chain=chain)

@app.route('/is_valid', methods=['GET'])
def is_valid():
    is_valid = blockchain.is_chain_valid(blockchain.chain)
    message = 'All Good' if is_valid else 'Not a valid blockchain'
    return render_template('is_valid.html', message=message)

@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    sender = request.form['sender']
    password = request.form['password']
    receiver = request.form['receiver']
    amount = float(request.form['amount'])

    response = blockchain.add_transaction_and_create_block(sender, password, receiver, amount)
    if isinstance(response, tuple) and response[1] == 400:
        return response[0], 400  # Return the error message if there's an issue

    return redirect(url_for('get_chain'))

@app.route('/create_wallet', methods=['POST'])
def create_wallet():
    address = request.form['address']
    password = request.form['password']
    try:
        balance = blockchain.create_wallet(address, password)
    except ValueError as e:
        return str(e), 400
    return redirect(url_for('get_chain'))

@app.route('/get_balance/<address>', methods=['GET'])
def get_balance(address):
    try:
        balance = blockchain.get_balance(address)
        return jsonify({'balance': balance}), 200
    except ValueError as e:
        return str(e), 400

@app.route('/add_funds', methods=['POST'])
def add_funds():
    address = request.form['address']
    amount = float(request.form['amount'])
    serial = request.form['serial']
    try:
        block = blockchain.add_funds(address, amount, serial)
    except ValueError as e:
        return str(e), 400
    return redirect(url_for('get_chain'))

@app.route('/suspend_wallet', methods=['POST'])
def suspend_wallet():
    address = request.form['address']
    try:
        blockchain.suspend_wallet(address)
    except ValueError as e:
        return str(e), 400
    return redirect(url_for('get_chain'))

if __name__ == '__main__':
    app.run(debug=True)
