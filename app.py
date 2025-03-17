import datetime
import hashlib
import logging
from web3 import Web3
from flask import Flask, request, render_template, jsonify, Response

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Blockchain Setup
INFURA_URL = "https://sepolia.infura.io/v3/ee5d0a549d0f4ae387b61a3e9a011ade"
CONTRACT_ADDRESS = "0x6E4F87068b64d8AE99F7F1CdbF61Ab8617025D0B"

# Connect to Ethereum
try:
    web3 = Web3(Web3.HTTPProvider(INFURA_URL))
    if web3.is_connected():
        logger.info("✅ Successfully connected to Ethereum network")
    else:
        logger.error("❌ Failed to connect to Ethereum network")
except Exception as e:
    logger.error(f"❌ Error connecting to Ethereum: {e}")
    web3 = None

# Smart Contract ABI
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
    },
    {
        "inputs": [
            {"internalType": "string", "name": "", "type": "string"}
        ],
        "name": "certificatesByCertID",
        "outputs": [
            {"internalType": "string", "name": "documentHash", "type": "string"},
            {"internalType": "string", "name": "issuer", "type": "string"},
            {"internalType": "uint256", "name": "issueDate", "type": "uint256"},
            {"internalType": "string", "name": "blockReference", "type": "string"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "string", "name": "", "type": "string"}
        ],
        "name": "certificatesByHash",
        "outputs": [
            {"internalType": "string", "name": "", "type": "string"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "string", "name": "certID", "type": "string"}
        ],
        "name": "verifyByCertID",
        "outputs": [
            {"internalType": "bool", "name": "", "type": "bool"},
            {"internalType": "string", "name": "", "type": "string"},
            {"internalType": "string", "name": "", "type": "string"},
            {"internalType": "uint256", "name": "", "type": "uint256"},
            {"internalType": "string", "name": "", "type": "string"}
        ],
        "stateMutability": "view",
        "type": "function"
    },
    {
        "inputs": [
            {"internalType": "string", "name": "documentHash", "type": "string"}
        ],
        "name": "verifyByHash",
        "outputs": [
            {"internalType": "bool", "name": "", "type": "bool"},
            {"internalType": "string", "name": "", "type": "string"},
            {"internalType": "uint256", "name": "", "type": "uint256"},
            {"internalType": "string", "name": "", "type": "string"},
            {"internalType": "string", "name": "", "type": "string"}
        ],
        "stateMutability": "view",
        "type": "function"
    }
]

# Initialize contract if web3 is connected
if web3 and web3.is_connected():
    try:
        contract = web3.eth.contract(address=CONTRACT_ADDRESS, abi=CONTRACT_ABI)
        logger.info(f"✅ Contract initialized at {CONTRACT_ADDRESS}")
    except Exception as e:
        logger.error(f"❌ Error initializing contract: {e}")
        contract = None
else:
    contract = None


# Convert Epoch Time to Readable Date
def convert_epoch_to_date(epoch_time):
    if epoch_time == 0:
        return "N/A"
    return datetime.datetime.fromtimestamp(epoch_time, datetime.UTC).strftime('%Y-%m-%d %H:%M:%S UTC')


# Parse block reference to get block number for creating a link
def get_block_number_from_ref(block_ref):
    try:
        # Extract block number from format "block:12345-time:1234567890"
        if block_ref and "block:" in block_ref:
            parts = block_ref.split("-")
            block_number = parts[0].replace("block:", "")
            return block_number
    except Exception as e:
        logger.error(f"Error parsing block reference: {e}")
    return None


# Verify by Cert ID
def verify_by_cert_id(cert_id):
    if not web3 or not web3.is_connected() or not contract:
        logger.error("Not connected to Ethereum or contract not initialized")
        return {"valid": False, "error": "Blockchain connection error"}

    try:
        logger.info(f"🔍 Verifying certificate with ID: {cert_id}")
        raw_response = contract.functions.verifyByCertID(cert_id).call()
        logger.info(f"🔍 Raw Response from Contract: {raw_response}")

        is_valid, document_hash, issuer, timestamp, block_reference = raw_response

        if not is_valid:
            logger.warning(f"❌ Invalid certificate: {cert_id}")
            return {"valid": False, "error": "Invalid certificate"}

        # Get block number from reference for explorer link
        block_number = get_block_number_from_ref(block_reference)
        block_explorer_url = f"https://sepolia.etherscan.io/block/{block_number}" if block_number else None

        result = {
            "valid": True,
            "cert_id": cert_id,
            "document_hash": document_hash,
            "issuer": issuer,
            "issue_date": convert_epoch_to_date(timestamp),
            "block_reference": block_reference,
            "block_explorer_url": block_explorer_url
        }
        logger.info(f"✅ Certificate validation successful: {result}")
        return result

    except Exception as e:
        logger.error(f"❌ Error verifying certID: {e}")
        return {"valid": False, "error": f"Certificate verification error: {str(e)}"}


# Verify by Document Hash
def verify_by_hash(document_hash):
    if not web3 or not web3.is_connected() or not contract:
        logger.error("Not connected to Ethereum or contract not initialized")
        return {"valid": False, "error": "Blockchain connection error"}

    try:
        logger.info(f"🔍 Verifying document with hash: {document_hash}")
        raw_response = contract.functions.verifyByHash(document_hash).call()
        logger.info(f"🔍 Raw Response from Contract: {raw_response}")

        is_valid, issuer, timestamp, cert_id, block_reference = raw_response

        if not is_valid:
            logger.warning(f"❌ Invalid document hash: {document_hash}")
            return {"valid": False, "error": "Invalid certificate"}

        # Get block number from reference for explorer link
        block_number = get_block_number_from_ref(block_reference)
        block_explorer_url = f"https://sepolia.etherscan.io/block/{block_number}" if block_number else None

        result = {
            "valid": True,
            "issuer": issuer,
            "cert_id": cert_id,
            "document_hash": document_hash,
            "issue_date": convert_epoch_to_date(timestamp),
            "block_reference": block_reference,
            "block_explorer_url": block_explorer_url
        }
        logger.info(f"✅ Document validation successful: {result}")
        return result

    except Exception as e:
        logger.error(f"❌ Error verifying document hash: {e}")
        return {"valid": False, "error": f"Document verification error: {str(e)}"}


# Flask App
app = Flask(__name__,
            static_folder='static',
            template_folder='templates')


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/verify-cert-id", methods=["POST"])
def verify_certificate_id():
    try:
        data = request.json
        if not data:
            logger.warning("No JSON data in request")
            return jsonify({"valid": False, "error": "Invalid request format"}), 400

        cert_id = data.get("cert_id")
        if not cert_id:
            logger.warning("No certificate ID provided")
            return jsonify({"valid": False, "error": "No certificate ID provided"}), 400

        logger.info(f"Received verification request for cert_id: {cert_id}")
        result = verify_by_cert_id(cert_id)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in verify_certificate_id endpoint: {e}")
        return jsonify({"valid": False, "error": f"Server error: {str(e)}"}), 500


@app.route("/verify-pdf", methods=["POST"])
def verify_certificate_pdf():
    try:
        if 'pdf_file' not in request.files:
            logger.warning("No file part in request")
            return jsonify({"valid": False, "error": "No PDF file uploaded"}), 400

        pdf_file = request.files.get("pdf_file")
        if not pdf_file or pdf_file.filename == '':
            logger.warning("No file selected")
            return jsonify({"valid": False, "error": "No PDF file selected"}), 400

        logger.info(f"Received PDF verification request for file: {pdf_file.filename}")
        pdf_content = pdf_file.read()
        pdf_hash = hashlib.sha256(pdf_content).hexdigest()
        logger.info(f"Generated PDF hash: {pdf_hash}")

        result = verify_by_hash(pdf_hash)
        return jsonify(result)
    except Exception as e:
        logger.error(f"Error in verify_certificate_pdf endpoint: {e}")
        return jsonify({"valid": False, "error": f"Server error: {str(e)}"}), 500


@app.route("/health", methods=["GET"])
def health_check():
    status = {
        "status": "healthy",
        "web3_connected": bool(web3 and web3.is_connected()),
        "contract_initialized": contract is not None
    }
    status_code = 200 if status["web3_connected"] and status["contract_initialized"] else 503
    return jsonify(status), status_code


@app.after_request
def after_request(response):
    """Ensure proper content type is set for all responses."""
    if response.headers.get("Content-Type") is None:
        response.headers["Content-Type"] = "application/json"
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "POST, GET, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type"
    return response


@app.errorhandler(404)
def not_found(e):
    return jsonify({"error": "Resource not found"}), 404


@app.errorhandler(500)
def server_error(e):
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    logger.info("Starting Certificate Verification System")
    app.run(host="0.0.0.0", port=5000, debug=True)