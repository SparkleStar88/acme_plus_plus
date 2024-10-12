
from http.server import BaseHTTPRequestHandler, HTTPServer
from socketserver import BaseServer
from OpenSSL import crypto
from hashlib import sha256
from socket import socket
from datetime import datetime
from dataclasses import dataclass
from datetime import datetime, timedelta
import json
import random
import string
import math
import time
import re

ACME = 0
ACMEPLUS = 1
ACME_MODE = ACME
SERVER_URL = "http://localhost:8000"

# client_ip : nonce
NONCE = {}
# account_id : Account()
ACCOUNTS = {}
# (account_id, authz_id) : ClientAuthz()
CLIENT_AUTHZS_BY_ID = {}
# (account_id, client_ip, client_id) : ClientAuthz()
CLIENT_AUTHZS_BY_CLIENT = {}
# (account_id, order_id) : Order()
ORDERS = {}
# (account_id, authz_id) : Authz()
AUTHZS_BY_ID = {}
# (account_id, identifier) : Authz()
AUTHZS_BY_DOMAIN = {}
# (account_id, chall_id) : Challenge()
CHALLENGES = {}
# (account_id, order_id) : certificate
CERTIFICATES = {}

def generate_random_string(length):
    """
    生成一个包含字母和数字的随机字符串

    :param length: 字符串的长度
    :return: 随机生成的字符串
    """
    # 字符集：字母（大小写）和数字
    characters = string.ascii_letters + string.digits
    # 随机选择字符构成字符串
    random_string = ''.join(random.choice(characters) for _ in range(length))
    return random_string

def generate_certificate(csr_pem : str):
    csr = crypto.load_certificate_request(crypto.FILETYPE_PEM, csr_pem.encode('utf-8'))
    cert = crypto.X509()
    cert.set_subject(csr.get_subject())
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)
    cert.set_issuer(cert.get_subject())  # 自签名
    cert.set_pubkey(csr.get_pubkey())
    cert.sign(csr.get_pubkey(), 'sha256')
    return crypto.dump_certificate(crypto.FILETYPE_PEM, cert)

@dataclass
class Account():
    account_id : string
    public_key : string
    email : string

@dataclass
class Order():
    order_id : string
    status : string
    authz_ids : list

@dataclass
class Challenge():
    challenge_id : string
    status : string
    type : string
    domain : string
    token : string

@dataclass
class Authz():
    authz_id : string
    status : string
    expires : datetime
    domain : string
    challenge : Challenge

@dataclass
class ClientAuthz():
    authz_id : string
    status : string
    expires : datetime
    challenges : list[Challenge]

class SimpleACMEServer(BaseHTTPRequestHandler):

    def _set_response(self, code=200):
        self.send_response(code)
        self.send_header('Content-type', 'application/json')
        self.send_header('Replay-Nonce', NONCE[self.client_address])
        self.end_headers()

    def check_nonce(self, nonce):
        if NONCE[self.client_address] != nonce:
            print("Replay Attack detected")
            return False
        return True

    def check_account(self, account_id, account_public_key):
        if ACCOUNTS[account_id].public_key != account_public_key:
            print("Invalid Account")
            return False
        return True

    def check_client_authz(self, account_id, client_ip, client_id):
        if self.client_address != client_ip:
            print("IP spoofing detected")
            return False
        try:
            client_authz : ClientAuthz = CLIENT_AUTHZS_BY_CLIENT[(account_id, client_ip, client_id)]
            if client_authz.status == "valid":
                return True
            else:
                finished = True
                for challenge in client_authz.challenges:
                    if challenge.status != "valid":
                        print("Client Authz not valid")
                        finished = False
                        break
                return finished
        except KeyError:
            print("No Client Authz found yet")
            return False

    def do_HEAD(self):
        if self.path == "/new-nonce":
            self.handle_nonce()
        else:
            self._set_response(404)

    def handle_nonce(self):
        new_nonce = generate_random_string(22)
        NONCE[self.client_address] = new_nonce
        self._set_response(code=200)

    def do_POST(self):

        client_authz_match = re.match(r"^/acme/client-authz/(\w+)$", self.path)
        authz_match = re.match(r"^/acme/authz/(\w+)$", self.path)
        challenge_match = re.match(r"^/acme/chall/(\w+)$", self.path)
        finalize_match = re.match(r"^/acme/order/(\w+)/finalize$", self.path)

        if self.path == "/acme/new-account":
            self.handle_new_account()
        elif self.path == "/acme/new-order":
            self.handle_new_order()
        elif client_authz_match:
            self.handle_client_authz(client_authz_match.group(1))
        elif authz_match:
            self.handle_authz(authz_match.group(1))
        elif challenge_match:
            self.handle_challenge(challenge_match.group(1))
        elif finalize_match:
            self.handle_finalize(finalize_match.group(1))
        else:
            self._set_response(404)
            self.wfile.write(json.dumps({"error": "Not Found"}).encode('utf-8'))

    def handle_new_account(self):
        content_length = int(self.headers['Content-Length'])
        post_data = json.loads(self.rfile.read(content_length))

        if not self.check_nonce(post_data['nonce']):
            self._set_response(403)
            return

        account_public_key = post_data['account_public_key']
        email = post_data['contact']

        account_id = generate_random_string(12)
        ACCOUNTS[account_id] = Account(account_id, account_public_key, email)

        self._set_response(201)
        self.wfile.write(json.dumps({"Location": SERVER_URL + "/acme/acct/" + account_id}).encode('utf-8'))

    def handle_new_order(self):
        content_length = int(self.headers['Content-Length'])
        post_data = json.loads(self.rfile.read(content_length))

        if not self.check_nonce(post_data['nonce']):
            self._set_response(403)
            return

        account_id = post_data['kid']
        account_public_key = post_data['account_public_key']
        identifiers = post_data['identifiers']

        if not self.check_account(account_id, account_public_key):
            self._set_response(400)
            self.wfile.write(json.dumps({"error": "Invalid account"}).encode('utf-8'))
            return

        if ACME_MODE == ACMEPLUS:
            client_ip = post_data['client_ip']
            client_id = post_data['client_id']
            if not self.check_client_authz(account_id, client_ip, client_id):
                # generate client authz and challenges
                new_client_authz = self.generate_new_client_authz(account_id, client_ip, client_id, identifiers)
                self._set_response(401)
                self.wfile.write(json.dumps({"Location": SERVER_URL + "/acme/client-authz/" + new_client_authz.authz_id}).encode('utf-8'))
                return

        authzs = []
        for identifier in identifiers:
            if (account_id, identifier) not in AUTHZS_BY_DOMAIN:
                authzs.append(self.generate_new_authz(account_id, identifier))
            else:
                authzs.append(AUTHZS_BY_DOMAIN[(account_id, identifier)])

        order_id = generate_random_string(12)
        authz_ids = [authz.authz_id for authz in authzs]
        new_order = Order(order_id, "processing", authz_ids)
        ORDERS[(account_id, order_id)] = new_order
        authz_urls = [SERVER_URL + "/acme/authz/" + authz_id for authz_id in authz_ids]

        self._set_response(201)
        self.wfile.write(json.dumps({
            "Location" : SERVER_URL + "/acme/order/" + order_id,
            "authorizations" : authz_urls,
            "finalize" : SERVER_URL + "/acme/order/" + order_id + "/finalize"
        }).encode('utf-8'))

    def generate_new_client_authz(self, account_id, client_ip, client_id, identifiers):
        authz_id = generate_random_string(12)
        expires = datetime.now() + timedelta(days=30)
        challenges = self.generate_new_client_challenge(account_id, identifiers)
        new_client_authz = ClientAuthz(authz_id, "pending", expires, challenges)
        CLIENT_AUTHZS_BY_ID[(account_id, authz_id)] = new_client_authz
        CLIENT_AUTHZS_BY_CLIENT[((account_id, client_ip, client_id))] = new_client_authz
        return new_client_authz

    def generate_new_client_challenge(self, account_id, identifiers, type="dns"):
        # currently, for experiment purposes, we do not choose domain from valid authz
        # but directly from passed identifiers, just choose the first N = log(n+1)
        N = len(identifiers)
        n = math.ceil(math.log2(N + 1))
        challenges = []
        for identifier in identifiers[:n]:
            challenges.append(self.generate_new_challenge(account_id, identifier, type))
        return challenges

    def generate_new_authz(self, account_id, identifier):
        authz_id = generate_random_string(12)
        expires = datetime.now() + timedelta(days=30)
        challenge = self.generate_new_challenge(account_id, identifier)
        new_authz = Authz(authz_id, "pending", expires, identifier, challenge)
        AUTHZS_BY_ID[(account_id, authz_id)] = new_authz
        AUTHZS_BY_DOMAIN[(account_id, identifier)] = new_authz
        return new_authz

    def generate_new_challenge(self, account_id, identifier, type="dns"):
        chall_id = generate_random_string(12)
        token = generate_random_string(16)
        new_challenge = Challenge(chall_id, "pending", type, identifier, token)
        CHALLENGES[(account_id, chall_id)] = new_challenge
        return new_challenge

    def handle_client_authz(self, client_authz_id):
        content_length = int(self.headers['Content-Length'])
        post_data = json.loads(self.rfile.read(content_length))

        if not self.check_nonce(post_data['nonce']):
            self._set_response(403)
            return

        account_id = post_data['kid']
        account_public_key = post_data['account_public_key']

        if not self.check_account(account_id, account_public_key):
            self._set_response(400)
            self.wfile.write(json.dumps({"error": "Invalid account"}).encode('utf-8'))
            return

        client_ip = post_data['client_ip']
        client_id = post_data['client_id']
        if ACME_MODE == ACMEPLUS:
            # here is different from new-order
            # only check if the client exists
            if (account_id, client_ip, client_id) not in CLIENT_AUTHZS_BY_CLIENT:
                self._set_response(403)
                self.wfile.write(json.dumps({"error": "Invalid client"}).encode('utf-8'))
                return

        challenges_info = []
        target_client_authz : ClientAuthz = CLIENT_AUTHZS_BY_ID[(account_id, client_authz_id)]
        for challenge in target_client_authz.challenges:
            challenges_info.append({
                "identifier" : challenge.domain,
                "type" : challenge.type,
                "url" : SERVER_URL + "/acme/chall/" + challenge.challenge_id,
                "token" : challenge.token
            })

        self._set_response(200)
        self.wfile.write(json.dumps({
            "Location" : SERVER_URL + "/acme/client-authz/" + target_client_authz.authz_id,
            "status" : target_client_authz.status,
            "challenges" : challenges_info
        }).encode('utf-8'))

    def handle_authz(self, authz_id):
        content_length = int(self.headers['Content-Length'])
        post_data = json.loads(self.rfile.read(content_length))

        if not self.check_nonce(post_data['nonce']):
            self._set_response(403)
            return

        account_id = post_data['kid']
        account_public_key = post_data['account_public_key']

        if not self.check_account(account_id, account_public_key):
            self._set_response(400)
            self.wfile.write(json.dumps({"error": "Invalid account"}).encode('utf-8'))
            return

        client_ip = post_data['client_ip']
        client_id = post_data['client_id']
        if ACME_MODE == ACMEPLUS:
            # authz check requires full client verification
            if not self.check_client_authz(account_id, client_ip, client_id):
                self._set_response(403)
                self.wfile.write(json.dumps({"error": "Invalid client"}).encode('utf-8'))
                return

        target_authz : Authz = AUTHZS_BY_ID[(account_id, authz_id)]
        challenge_info = ({
                "identifier" : target_authz.challenge.domain,
                "type" : target_authz.challenge.type,
                "url" : SERVER_URL + "/acme/chall/" + target_authz.challenge.challenge_id,
                "token" : target_authz.challenge.token
            })

        self._set_response(200)
        self.wfile.write(json.dumps({
            "Location" : SERVER_URL + "/acme/authz/" + target_authz.authz_id,
            "status" : target_authz.status,
            "challenge" : challenge_info
        }).encode('utf-8'))

    def handle_challenge(self, chall_id):
        content_length = int(self.headers['Content-Length'])
        post_data = json.loads(self.rfile.read(content_length))

        if not self.check_nonce(post_data['nonce']):
            self._set_response(403)
            return

        account_id = post_data['kid']
        account_public_key = post_data['account_public_key']

        if not self.check_account(account_id, account_public_key):
            self._set_response(400)
            self.wfile.write(json.dumps({"error": "Invalid account"}).encode('utf-8'))
            return

        client_ip = post_data['client_ip']
        client_id = post_data['client_id']
        if ACME_MODE == ACMEPLUS:
            # here is different from new-order
            # only check if the client exists
            if (account_id, client_ip, client_id) not in CLIENT_AUTHZS_BY_CLIENT:
                self._set_response(403)
                self.wfile.write(json.dumps({"error": "Invalid client"}).encode('utf-8'))
                return

        if (account_id, chall_id) not in CHALLENGES:
            self._set_response(404)
            self.wfile.write(json.dumps({"error": "Challenge not found"}).encode('utf-8'))
            return

        token = post_data["token"]
        target_challenge : Challenge = CHALLENGES[(account_id, chall_id)]
        if target_challenge.token == token:
            target_challenge.status = "valid"
            self._set_response()
            self.wfile.write(json.dumps({"status": "Challenge validated"}).encode('utf-8'))
        else:
            target_challenge.status = "invalid"
            self._set_response(400)
            self.wfile.write(json.dumps({"error": "Invalid challenge response"}).encode('utf-8'))

    def handle_finalize(self, order_id):
        content_length = int(self.headers['Content-Length'])
        post_data = json.loads(self.rfile.read(content_length))

        if not self.check_nonce(post_data['nonce']):
            self._set_response(403)
            return

        account_id = post_data['kid']
        account_public_key = post_data['account_public_key']

        if not self.check_account(account_id, account_public_key):
            self._set_response(400)
            self.wfile.write(json.dumps({"error": "Invalid account"}).encode('utf-8'))
            return

        if ACME_MODE == ACMEPLUS:
            client_ip = post_data['client_ip']
            client_id = post_data['client_id']
            if not self.check_client_authz(account_id, client_ip, client_id):
                self._set_response(403)
                self.wfile.write(json.dumps({"error": "Invalid client"}).encode('utf-8'))
                return

        # check if order is finished
        csr = post_data['csr']
        target_order : Order = ORDERS[(account_id, order_id)]
        target_authz_ids = target_order.authz_ids
        for authz_id in target_authz_ids:
            if AUTHZS_BY_ID[(account_id, authz_id)].status != "valid":
                self._set_response(400)
                self.wfile.write(json.dumps({"error": "Order not ready"}).encode('utf-8'))
                return

        target_order.status = "valid"
        order_certificate = generate_certificate(csr)
        CERTIFICATES[(account_id, order_id)] = order_certificate
        self._set_response(200)
        self.wfile.write(json.dumps({"certificate": order_certificate.decode('utf-8')}).encode('utf-8'))


# 自定义 HTTPServer 并增加 mode 参数
class CustomHTTPServer(HTTPServer):
    def __init__(self, server_address, RequestHandlerClass, mode):
        super().__init__(server_address, RequestHandlerClass)
        self.mode = mode

def create_server(mode, address='0.0.0.0', port=8000):
    server_address = (address, port)
    httpd = CustomHTTPServer(server_address, SimpleACMEServer, mode)
    print(f"Serving in {mode} mode on {address}:{port}")
    httpd.serve_forever()

if __name__ == '__main__':
    create_server(ACME)
