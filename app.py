import datetime
import hashlib
import json
from flask import Flask, jsonify, request, render_template, redirect, url_for, session
from blockchain import Blockchain

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'  # Set a secret key for session management
app.config['JSONIFY_PRETTYPRINT_REGULAR'] = False

blockchain = Blockchain()

@app.route('/')
def index():
    if 'username' in session:
        address = session['username']
        try:
            balance = blockchain.get_balance(address)
        except ValueError:
            balance = None
        return render_template('index.html', balance=balance)
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

@app.route('/create_wallet_page', methods=['GET'])
def create_wallet_page():
    return "Wallet creation is not allowed. Please log in to access other features."

@app.route('/create_wallet', methods=['POST'])
def create_wallet():
    return "Wallet creation is not allowed. Please log in to access other features."

@app.route('/get_balance_page', methods=['GET'])
def get_balance_page():
    return render_template('check_balance.html')

@app.route('/get_balance', methods=['GET'])
def get_balance():
    if 'username' not in session:
        return "Unauthorized access", 403

    address = session['username']
    try:
        balance = blockchain.get_balance(address)
        return jsonify({'balance': balance}), 200
    except ValueError as e:
        return str(e), 400

@app.route('/check_balance', methods=['POST'])
def check_balance():
    address = request.form.get('address')
    balance = None
    if address:
        try:
            balance = blockchain.get_balance(address)
        except ValueError as e:
            balance = str(e)
    return render_template('index.html', balance=balance)

@app.route('/add_funds_page', methods=['GET'])
def add_funds_page():
    return render_template('add_funds.html')

@app.route('/add_funds', methods=['POST'])
def add_funds():
    if 'username' not in session:
        return "Unauthorized access", 403

    address = session['username']
    amount = float(request.form['amount'])
    serial = request.form['serial']
    try:
        block = blockchain.add_funds(address, amount, serial)
        return redirect(url_for('get_chain'))
    except ValueError as e:
        return str(e), 400

@app.route('/suspend_wallet_page', methods=['GET'])
def suspend_wallet_page():
    return render_template('suspend_wallet.html')

@app.route('/suspend_wallet', methods=['POST'])
def suspend_wallet():
    if 'username' not in session:
        return "Unauthorized access", 403

    address = session['username']
    try:
        blockchain.suspend_wallet(address)
        return redirect(url_for('index'))
    except ValueError as e:
        return str(e), 400

@app.route('/find_owner_page', methods=['GET'])
def find_owner_page():
    return render_template('find_owner.html')

@app.route('/find_owner', methods=['GET'])
def find_owner():
    serial = request.args.get('serial')
    owner = None
    for address, wallet in blockchain.wallets.items():
        for denom, serials in wallet['denominations'].items():
            if serial in serials:
                owner = address
                break
        if owner:
            break
    if owner:
        return jsonify({'owner': owner}), 200
    return "Serial number not found", 404

@app.route('/transfer_funds_page', methods=['GET'])
def transfer_funds_page():
    return render_template('transfer_funds.html')

@app.route('/add_transaction', methods=['POST'])
def add_transaction():
    if 'username' not in session:
        return "Unauthorized access", 403

    sender = session['username']
    password = request.form['password']
    receiver = request.form['receiver']
    amount = float(request.form['amount'])
    response = blockchain.add_transaction_and_create_block(sender, password, receiver, amount)
    if isinstance(response, tuple) and response[1] == 400:
        return response[0], 400
    return redirect(url_for('get_chain'))

@app.route('/login', methods=['GET', 'POST'])
def login_page():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if blockchain.verify_password(username, password):
            session['username'] = username
            return redirect(url_for('index'))
        return "Invalid credentials", 400
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register_page():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username in blockchain.users:
            return "User already exists", 400

        # Register user and create a wallet
        blockchain.users[username] = blockchain.hash_password(password)
        blockchain.save_users()

        # Create a wallet for the new user
        try:
            blockchain.create_wallet(username, password)
        except ValueError as e:
            return str(e), 400

        return redirect(url_for('login_page'))
    return render_template('register.html')

@app.route('/admin', methods=['GET', 'POST'])
def admin_page():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username == 'admin' and password == '123':
            session['admin'] = True
            return redirect(url_for('admin_dashboard'))
        return "Invalid admin credentials", 400
    return render_template('admin_login.html')

@app.route('/admin/dashboard', methods=['GET'])
def admin_dashboard():
    if 'admin' not in session:
        return redirect(url_for('admin_page'))
    return render_template('admin_dashboard.html')

@app.route('/admin/suspend_wallet', methods=['POST'])
def admin_suspend_wallet():
    if 'admin' not in session:
        return "Unauthorized access", 403

    address = request.form['address']
    try:
        blockchain.suspend_wallet(address)
        return "Wallet suspended successfully", 200
    except ValueError as e:
        return str(e), 400

@app.route('/admin/find_owner', methods=['GET'])
def admin_find_owner():
    if 'admin' not in session:
        return "Unauthorized access", 403

    serial = request.args.get('serial')
    owner = None
    for address, wallet in blockchain.wallets.items():
        for denom, serials in wallet['denominations'].items():
            if serial in serials:
                owner = address
                break
        if owner:
            break
    if owner:
        return jsonify({'owner': owner}), 200
    return "Serial number not found", 404

@app.route('/logout')
def logout():
    session.pop('username', None)
    session.pop('admin', None)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
