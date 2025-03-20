import hashlib
import os
import secrets
from flask import Blueprint, Flask, render_template, request, redirect, url_for, session, flash
from web3 import Web3
from eth_account import Account

# Blueprint Setup
admin_bp = Blueprint("admin", __name__)

# Predefined admin credentials (hashed for security)
ADMIN_USERNAME = "qaricc"
ADMIN_PASSWORD = "0equity"

# Blockchain Setup
INFURA_URL = "https://sepolia.infura.io/v3/ee5d0a549d0f4ae387b61a3e9a011ade"
CONTRACT_ADDRESS = "0x6E4F87068b64d8AE99F7F1CdbF61Ab8617025D0B"

# Contract ABI (this would be generated when compiling your smart contract)
CONTRACT_ABI = [
    {
        "anonymous": False,
        "inputs": [
            {"indexed": False, "internalType": "string", "name": "certID", "type": "string"},
            {"indexed": False, "internalType": "string", "name": "documentHash", "type": "string"},
            {"indexed": False, "internalType": "string", "name": "issuer", "type": "string"},
            {"indexed": False, "internalType": "uint256", "name": "issueDate", "type": "uint256"},
            {"indexed": False, "internalType": "string", "name": "blockReference", "type": "string"}
        ],
        "name": "CertificateIssued",
        "type": "event"
    },
    {
        "inputs": [
            {"internalType": "string", "name": "certID", "type": "string"},
            {"internalType": "string", "name": "documentHash", "type": "string"},
            {"internalType": "string", "name": "issuer", "type": "string"}
        ],
        "name": "issueCertificate",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function"
    }
]

@admin_bp.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('admin.upload'))
    return redirect(url_for('admin.login'))

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password'].strip()

        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session['username'] = username
            flash('Login Successful!', 'success')
            return redirect(url_for('admin.upload'))
        else:
            flash('Invalid credentials. Try again.', 'error')

    return render_template('login.html')

@admin_bp.route('/upload', methods=['GET', 'POST'])
def upload():
    if 'username' not in session:
        return redirect(url_for('admin.login'))

    if request.method == 'POST':
        cert_id = request.form['cert_id'].strip()
        issuer = request.form['issuer'].strip()
        private_key = '01d76310651d0e507c43fbb86235a82bdccb0f196ffc1db73c828c6594c7eac8'.strip()

        if 'certificate' not in request.files:
            flash('No file part', 'error')
            return redirect(request.url)

        file = request.files['certificate']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(request.url)

        if file:
            temp_path = "temp_certificate.pdf"
            file.save(temp_path)
            pdf_hash = generate_pdf_hash(temp_path)

            # Issue certificate on blockchain
            result = issue_certificate(cert_id, pdf_hash, issuer, private_key)

            # Clean up temporary file
            os.remove(temp_path)

            if result:
                flash(f'Certificate issued successfully! Transaction hash: {result}', 'success')
            else:
                flash('Failed to issue certificate', 'error')

    return render_template('upload.html')

@admin_bp.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('admin.login'))

def generate_pdf_hash(pdf_path):
    with open(pdf_path, "rb") as file:
        pdf_content = file.read()
        pdf_hash = hashlib.sha256(pdf_content).hexdigest()
    return pdf_hash

def issue_certificate(cert_id, document_hash, issuer, private_key):
    try:
        web3 = Web3(Web3.HTTPProvider(INFURA_URL))
        if not web3.is_connected():
            flash('Failed to connect to Ethereum network', 'error')
            return None

        account = Account.from_key(private_key)
        contract = web3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
        tx = contract.functions.issueCertificate(cert_id, document_hash, issuer).build_transaction({
            'from': account.address,
            'nonce': web3.eth.get_transaction_count(account.address),
            'gas': 2500000,
            'gasPrice': web3.to_wei('30', 'gwei')
        })

        signed_tx = web3.eth.account.sign_transaction(tx, private_key)
        tx_hash = web3.eth.send_raw_transaction(signed_tx.raw_transaction)
        tx_hex = web3.to_hex(tx_hash)

        return tx_hex
    except Exception as e:
        flash(f'Error during transaction: {str(e)}', 'error')
        return None
