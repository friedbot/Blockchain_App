import datetime
import hashlib
import json
from flask import Flask, jsonify, request, render_template, redirect, url_for
from uuid import uuid4
import random

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

class Blockchain:
    def __init__(self):
        self.chain = []
        self.transactions = []
        self.wallets = {}  # Dictionary to store wallet addresses and balances
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
        return block

    def get_previous_block(self):
        return self.chain[-1]

    def proof_of_work(self, previous_proof):
        new_proof = 1
        check_proof = False
        while not check_proof:
            hash_operation = hashlib.sha256(str(new_proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] == '0000':
                check_proof = True
            else:
                new_proof += 1
        return new_proof

    def hash(self, block):
        # Exclude 'hash' key from block while hashing
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
            hash_operation = hashlib.sha256(str(proof**2 - previous_proof**2).encode()).hexdigest()
            if hash_operation[:4] != '0000':
                return False
            previous_block = block
            block_index += 1
        return True

    def generate_serial_number(self):
        return str(uuid4())

    def add_transaction_and_create_block(self, sender, receiver, amount, is_freeze=False):
        # Check if both sender and receiver wallets exist
        if sender not in self.wallets:
            raise ValueError("Sender wallet does not exist")
        if receiver not in self.wallets:
            raise ValueError("Receiver wallet does not exist")

        # Check if the sender has enough balance
        if self.wallets[sender] < amount:
            raise ValueError("Sender does not have enough funds")

        # Update the wallet balances
        self.wallets[sender] -= amount
        self.wallets[receiver] += amount

        serial_number = self.generate_serial_number()
        transaction = {
            'serial_number': serial_number,
            'sender': sender,
            'receiver': receiver,
            'amount': amount,
            'is_freeze': is_freeze
        }
        self.transactions.append(transaction)
        previous_block = self.get_previous_block()
        previous_proof = previous_block['proof']
        proof = self.proof_of_work(previous_proof)
        previous_hash = self.hash(previous_block)
        block = self.create_block(proof, previous_hash)
        return block

    def create_wallet(self, address):
        if address in self.wallets:
            raise ValueError("Wallet already exists")
        self.wallets[address] = 0
        return self.wallets[address]

    def get_balance(self, address):
        if address in self.wallets:
            return self.wallets[address]
        else:
            raise ValueError("Wallet does not exist")

    def add_funds(self, address, amount):
        if address in self.wallets:
            self.wallets[address] += amount
        else:
            raise ValueError("Wallet does not exist")

blockchain = Blockchain()

@app.route('/')
def index():
    return render_template('index.html')

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
    receiver = request.form['receiver']
    amount = float(request.form['amount'])
    is_freeze = request.form.get('is_freeze') == 'on'
    try:
        block = blockchain.add_transaction_and_create_block(sender, receiver, amount, is_freeze)
    except ValueError as e:
        return str(e), 400
    return redirect(url_for('get_chain'))

@app.route('/create_wallet', methods=['POST'])
def create_wallet():
    address = request.form['address']
    try:
        balance = blockchain.create_wallet(address)
    except ValueError as e:
        return str(e), 400
    return redirect(url_for('index'))

@app.route('/get_balance', methods=['GET'])
def get_balance():
    address = request.args.get('address')
    try:
        balance = blockchain.get_balance(address)
        return render_template('balance.html', address=address, balance=balance)
    except ValueError as e:
        return str(e), 400

@app.route('/add_funds', methods=['POST'])
def add_funds():
    address = request.form['address']
    amount = random.randint(10, 100)  # Random amount between 10 and 100
    try:
        blockchain.add_funds(address, amount)
    except ValueError as e:
        return str(e), 400
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
