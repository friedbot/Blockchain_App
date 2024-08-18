import datetime
import hashlib
import json
from flask import Flask, jsonify, request, render_template, redirect, url_for

app = Flask(__name__)
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False


class Blockchain:
    def __init__(self):
        self.chain = []
        self.transactions = []
        self.wallets = {}  # Dictionary to store wallet addresses, balances, denominations, and serial numbers
        self.allowed_denominations = [1, 2, 5, 10, 50, 100, 200, 500]
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

    def add_transaction_and_create_block(self, sender, password, receiver, amount, is_freeze=False):
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

        transaction = {
            'sender': sender,
            'receiver': receiver,
            'amount': optimized_amount,
            'is_freeze': is_freeze,
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

    def create_wallet(self, address, password):
        if address in self.wallets:
            raise ValueError("Wallet already exists")
        self.wallets[address] = {
            'balance': 0,
            'password': self.hash_password(password),
            'denominations': {}  # To store denominations with their serial numbers
        }
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
                        'is_freeze': False,
                        'status': 'failed',
                        'reason': 'Duplicate serial number'
                    })
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
                'is_freeze': False,
                'status': 'success'
            }
            self.transactions.append(transaction)

            # Add the transaction to the blockchain by creating a new block
            previous_block = self.get_previous_block()
            previous_proof = previous_block['proof']
            proof = self.proof_of_work(previous_proof)
            previous_hash = self.hash(previous_block)
            block = self.create_block(proof, previous_hash)
            return block

        else:
            raise ValueError("Wallet does not exist")

    def hash_password(self, password):
        return hashlib.sha256(password.encode()).hexdigest()

    def verify_password(self, address, password):
        hashed_password = self.hash_password(password)
        return self.wallets[address]['password'] == hashed_password

    def find_owner_by_serial(self, serial_number):
        for address, wallet in self.wallets.items():
            for amount, serials in wallet['denominations'].items():
                if serial_number in serials:
                    return address
        return None

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
    is_freeze = request.form.get('is_freeze') == 'on'

    response = blockchain.add_transaction_and_create_block(sender, password, receiver, amount, is_freeze)
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
    return redirect(url_for('index'))


@app.route('/get_balance', methods=['GET'])
def get_balance():
    address = request.args.get('address')
    try:
        balance = blockchain.get_balance(address)
        denominations = blockchain.wallets[address]['denominations']
        return render_template('balance.html', address=address, balance=balance, denominations=denominations)
    except ValueError as e:
        return str(e), 400


@app.route('/add_funds', methods=['POST'])
def add_funds():
    address = request.form['address']
    amount = int(request.form['amount'])
    serial = request.form['serial']
    try:
        response = blockchain.add_funds(address, amount, serial)
        if isinstance(response, tuple) and response[1] == 400:
            return response[0], 400  # Return the error message if there's an issue
    except ValueError as e:
        return str(e), 400
    return redirect(url_for('get_chain'))


@app.route('/find_owner', methods=['GET'])
def find_owner():
    serial_number = request.args.get('serial_number')
    if not serial_number:
        return "Serial number is required", 400

    owner = blockchain.find_owner_by_serial(serial_number)
    if owner:
        return jsonify({'serial_number': serial_number, 'owner': owner})
    else:
        return "Serial number not found", 404

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
