
from datetime import datetime, timedelta
from requests import Response
from OpenSSL import crypto
import requests
import hashlib
import os

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from time import time, sleep

import threading
import random
import string
import socket

def generate_csr(identifiers):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    csr = crypto.X509Req()
    csr.get_subject().CN = identifiers[0]  # 主域名

    # 构建 SAN 列表
    san_list = [f"DNS:{domain}" for domain in identifiers]
    san_extension = crypto.X509Extension(
        b"subjectAltName", False, ", ".join(san_list).encode('utf-8')
    )
    csr.add_extensions([san_extension])
    csr.set_pubkey(key)
    csr.sign(key, 'sha256')

    return crypto.dump_certificate_request(crypto.FILETYPE_PEM, csr).decode('utf-8'), key

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

def generate_rsa_key(key_size):
    """
    生成指定长度的 RSA 私钥

    :param key_size: RSA 密钥长度（1024、2048、4096等）
    :return: PEM 格式的私钥和公钥
    """
    # 生成 RSA 私钥
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )

    # 以 PEM 格式导出私钥
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    # 以 PEM 格式导出公钥
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pem.decode('utf-8'), public_key_pem.decode('utf-8')

def read_certificate(pem_string):
    # 加载 PEM 字符串为 X509 对象
    certificate = crypto.load_certificate(crypto.FILETYPE_PEM, pem_string)
    
    # 获取证书的相关信息
    subject = certificate.get_subject()
    issuer = certificate.get_issuer()
    serial_number = certificate.get_serial_number()
    version = certificate.get_version() + 1  # OpenSSL 版本是从0开始的
    not_before = certificate.get_notBefore().decode('utf-8')
    not_after = certificate.get_notAfter().decode('utf-8')
    signature_algorithm = certificate.get_signature_algorithm().decode('utf-8')
    
    # 打印证书信息
    print("Certificate:")
    print(f"  Subject: {subject}")
    print(f"  Issuer: {issuer}")
    print(f"  Serial Number: {serial_number}")
    print(f"  Version: {version}")
    print(f"  Valid From: {not_before}")
    print(f"  Valid To: {not_after}")
    print(f"  Signature Algorithm: {signature_algorithm}")

    # 打印 Subject Alternative Names (SAN)
    san_extension = None
    for i in range(certificate.get_extension_count()):
        ext = certificate.get_extension(i)
        if ext.get_short_name().decode('utf-8') == 'subjectAltName':
            san_extension = ext
            break

    if san_extension:
        print(f"  Subject Alternative Names: {san_extension}")

SERVER_URL = "http://localhost:8000"

class SimpleACMEClient():

    def __init__(self) -> None:
        self.client_id = generate_random_string(22)
        self.client_ip = "127.0.0.1"
        # self.client_ip = socket.gethostbyname(socket.gethostname())
        self.account_private_key, self.account_public_key = generate_rsa_key(2048)
        self.client_nonce = self.get_nonce()
        self.account_id = ""

        self.order_id = ""
        self.client_authz = ""
        self.pending_client_challs = []
        self.authzs = []
        self.pending_challs = []
        self.finalize_id = ""

    def get_nonce(self):
        '''
            HEAD /acme/new-nonce HTTP/1.1
            Host: example.com

            HTTP/1.1 200 OK
            Replay-Nonce: oFvnlFP1wIhRlYS2jTaXbA
            Cache-Control: no-store
            Link: <https://example.com/acme/directory>;rel="index"
        '''
        response : Response = requests.head(SERVER_URL + "/acme/new-nonce")
        if response.status_code == 200:
            return response.headers["Replay-Nonce"]
        else:
            raise ValueError("Error when getting new nonce")

    def register_account(self, email):
        '''
            POST /acme/new-account HTTP/1.1
            Host: example.com
            Content-Type: application/jose+json

            {
                "protected": base64url({
                "alg": "ES256",
                "jwk": {...},
                "nonce": "6S8IqOGY7eL2lsGoTZYifg",
                "url": "https://example.com/acme/new-account"
                }),
                "payload": base64url({
                "termsOfServiceAgreed": true,
                "contact": [
                    "mailto:cert-admin@example.org",
                    "mailto:admin@example.org"
                ]
                }),
                "signature": "RZPOnYoPs1PhjszF...-nh6X1qtOFPB519I"
            }

            HTTP/1.1 201 Created
            Content-Type: application/json
            Replay-Nonce: D8s4D2mLs8Vn-goWuPQeKA
            Link: <https://example.com/acme/directory>;rel="index"
            Location: https://example.com/acme/acct/evOfKhNU60wg

            {
                "status": "valid",

                "contact": [
                "mailto:cert-admin@example.org",
                "mailto:admin@example.org"
                ],

                "orders": "https://example.com/acme/acct/evOfKhNU60wg/orders"
            }
        '''
        data = {"account_public_key": self.account_public_key, "nonce" : self.client_nonce, "contact": email}
        response : Response = requests.post(SERVER_URL + "/acme/new-account", json=data)
        if response.status_code == 201:
            self.account_id = response.json()["Location"]
        else:
            raise ValueError("Error when registering an ACME account")

    def new_order(self, identifiers):
        '''
            POST /acme/new-order HTTP/1.1
            Host: example.com
            Content-Type: application/jose+json

            {
                "protected": base64url({
                "alg": "ES256",
                "kid": "https://example.com/acme/acct/evOfKhNU60wg",
                "nonce": "5XJ1L3lEkMG7tR6pA00clA",
                "url": "https://example.com/acme/new-order"
                "client_ip" : "127.0.0.1"
                "client_id" : "23HB324fcdfsdjhBHyo"
                }),
                "payload": base64url({
                "identifiers": [
                    { "type": "dns", "value": "www.example.org" },
                    { "type": "dns", "value": "example.org" }
                ],
                "notBefore": "2016-01-01T00:04:00+04:00",
                "notAfter": "2016-01-08T00:04:00+04:00"
                }),
                "signature": "H6ZXtGjTZyUnPeKn...wEA4TklBdh3e454g"
            }

            # For valid_account_authz
            HTTP/1.1 201 Created
            Replay-Nonce: MYAuvOpaoIiywTezizk5vw
            Link: <https://example.com/acme/directory>;rel="index"
            Location: https://example.com/acme/order/TOlocE8rfgo

            {
                "status": "pending",
                "expires": "2016-01-05T14:09:07.99Z",

                "notBefore": "2016-01-01T00:00:00Z",
                "notAfter": "2016-01-08T00:00:00Z",

                "identifiers": [
                { "type": "dns", "value": "www.example.org" },
                { "type": "dns", "value": "example.org" }
                ],

                "authorizations": [
                "https://example.com/acme/authz/PAniVnsZcis",
                "https://example.com/acme/authz/r4HqLzrSrpI"
                ],

                "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize"
            }

            # For invalid_account_authz
            HTTP/1.1 401 Unauthorized
            Replay-Nonce: MYAuvOpaoIiywTezizk5vw
            Link: <https://example.com/acme/directory>;rel="index"
            Location: https://example.com/acme/authz/PAniVnsZcis

        '''
        current_time = datetime.now()
        not_before = datetime.isoformat(current_time)
        not_after = datetime.isoformat(current_time + timedelta(days=90))
        data = {
            "kid": self.account_id,
            "account_public_key" : self.account_public_key,
            "nonce" : self.client_nonce,
            "client_ip" : self.client_ip,
            "client_id" : self.client_id,
            "identifiers": identifiers,
            "not_before" : not_before,
            "not_after" : not_after
        }
        response : Response = requests.post(SERVER_URL + "/acme/new-order", json=data)
        if response.status_code == 201:
            response_data = response.json()
            self.order_id = response_data["Location"]
            self.authzs = response_data["authorizations"]
            self.finalize_id = response_data["finalize"]
            self.authorize_domains()
        elif response.status_code == 401:
            self.client_authz = response.json()["Location"]
            self.authorize_client()
            self.new_order(identifiers)
        else:
            raise ValueError("Error when getting an new order")

    def authorize_client(self):
        def handle_challenge(chall):
            self.complete_challenge(chall)

        threads = []
        client_challenges = self.get_client_authz_challenges(self.client_authz)
        for chall in client_challenges:
            thread = threading.Thread(target=handle_challenge, args=(chall,))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()

    def authorize_domains(self):
        def handle_authz(authz):
            chall = self.get_authz_challenge(authz)
            self.complete_challenge(chall)

        threads = []
        for authz in self.authzs:
            thread = threading.Thread(target=handle_authz, args=(authz,))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()

    def get_client_authz_challenges(self, authz_url):
        data = {
            "kid": self.account_id,
            "account_public_key" : self.account_public_key,
            "nonce" : self.client_nonce,
            "client_ip" : self.client_ip,
            "client_id" : self.client_id,
        }
        response : Response = requests.post(authz_url, json=data)
        if response.status_code == 200:
            if response.json()["status"] == "pending":
                return response.json()["challenges"]
            else:
                return []
        else:
            raise ValueError("Error when getting client authz")

    def get_authz_challenge(self, authz_url):
        '''
            POST /acme/authz/PAniVnsZcis HTTP/1.1
            Host: example.com
            Content-Type: application/jose+json

            {
                "protected": base64url({
                "alg": "ES256",
                "kid": "https://example.com/acme/acct/evOfKhNU60wg",
                "nonce": "uQpSjlRb4vQVCjVYAyyUWg",
                "url": "https://example.com/acme/authz/PAniVnsZcis"
                }),
                "payload": "",
                "signature": "nuSDISbWG8mMgE7H...QyVUL68yzf3Zawps"
            }

            HTTP/1.1 200 OK
            Content-Type: application/json
            Link: <https://example.com/acme/directory>;rel="index"

            {
                "status": "pending",
                "expires": "2016-01-02T14:09:30Z",

                "identifier": {
                "type": "dns",
                "value": "www.example.org"
                },

                "challenges": [
                {
                    "type": "http-01",
                    "url": "https://example.com/acme/chall/prV_B7yEyA4",
                    "token": "DGyRejmCefe7v4NfDGDKfA"
                },
                {
                    "type": "dns-01",
                    "url": "https://example.com/acme/chall/Rg5dV14Gh1Q",
                    "token": "DGyRejmCefe7v4NfDGDKfA"
                }
                ]
            }
        '''
        data = {
            "kid": self.account_id,
            "account_public_key" : self.account_public_key,
            "nonce" : self.client_nonce,
            "client_ip" : self.client_ip,
            "client_id" : self.client_id,
        }
        response : Response = requests.post(authz_url, json=data)
        if response.status_code == 200:
            if response.json()["status"] == "pending":
                return response.json()["challenge"]
            else:
                return None
        elif response.status_code == 401:
            self.client_authz = response.json()["Location"]
            self.authorize_client()
            self.get_authz_challenge(authz_url)
        else:
            raise ValueError("Error when getting authz")

    def complete_challenge(self, challenge):
        '''
            POST /acme/chall/prV_B7yEyA4 HTTP/1.1
            Host: example.com
            Content-Type: application/jose+json

            {
                "protected": base64url({
                "alg": "ES256",
                "kid": "https://example.com/acme/acct/evOfKhNU60wg",
                "nonce": "Q_s3MWoqT05TrdkM2MTDcw",
                "url": "https://example.com/acme/chall/prV_B7yEyA4"
                }),
                "payload": base64url({}),
                "signature": "9cbg5JO1Gf5YLjjz...SpkUfcdPai9uVYYQ"
            }

            The server
            provides a 200 (OK) response with the updated challenge object as its
            body.
        '''
        data = {
            "kid": self.account_id,
            "account_public_key" : self.account_public_key,
            "nonce" : self.client_nonce,
            "client_ip" : self.client_ip,
            "client_id" : self.client_id,
            "token" : challenge["token"]
        }
        # simulate the challenge process
        sleep(5)
        response : Response = requests.post(challenge["url"], json=data)
        if response.status_code == 200:
            pass
        # elif response.status_code == 401:
        #     self.client_authz = response.json()["Location"]
        #     self.authorize_client()
        #     self.complete_challenge(challenge)
        else:
            url = challenge["url"]
            print(f"Challenge to {url} failed")

    def finalize_order(self, csr_pem):
        '''
            POST /acme/order/TOlocE8rfgo/finalize HTTP/1.1
            Host: example.com
            Content-Type: application/jose+json

            {
                "protected": base64url({
                "alg": "ES256",
                "kid": "https://example.com/acme/acct/evOfKhNU60wg",
                "nonce": "MSF2j2nawWHPxxkE3ZJtKQ",
                "url": "https://example.com/acme/order/TOlocE8rfgo/finalize"
                }),
                "payload": base64url({
                "csr": "MIIBPTCBxAIBADBFMQ...FS6aKdZeGsysoCo4H9P",
                }),
                "signature": "uOrUfIIk5RyQ...nw62Ay1cl6AB"
            }

            HTTP/1.1 200 OK
            Replay-Nonce: CGf81JWBsq8QyIgPCi9Q9X
            Link: <https://example.com/acme/directory>;rel="index"
            Location: https://example.com/acme/order/TOlocE8rfgo

            {
                "status": "valid",
                "expires": "2016-01-20T14:09:07.99Z",

                "notBefore": "2016-01-01T00:00:00Z",
                "notAfter": "2016-01-08T00:00:00Z",

                "identifiers": [
                { "type": "dns", "value": "www.example.org" },
                { "type": "dns", "value": "example.org" }
                ],

                "authorizations": [
                "https://example.com/acme/authz/PAniVnsZcis",
                "https://example.com/acme/authz/r4HqLzrSrpI"
                ],

                "finalize": "https://example.com/acme/order/TOlocE8rfgo/finalize",

                "certificate": "https://example.com/acme/cert/mAt3xBGaobw"
            }
        '''
        data = {
            "kid": self.account_id,
            "account_public_key" : self.account_public_key,
            "nonce" : self.client_nonce,
            "client_ip" : self.client_ip,
            "client_id" : self.client_id,
            "csr" : csr_pem
        }
        response : Response = requests.post(self.finalize_id, json=data)
        if response.status_code == 200:
            self.certificate = response.json()["certificate"]
        elif response.status_code == 401:
            self.client_authz = response.json()["Location"]
            self.authorize_client()
            self.finalize_order(csr_pem)
        else:
            print(response.content)
            raise ValueError("Error when finalizing the order")

    def run(self, email, ids):

        # 注册账号
        self.register_account(email)

        # 请求新订单
        self.new_order(ids)

        # 生成 CSR
        csr_pem, key = generate_csr(ids)

        # 完成订单并获取证书
        self.finalize_order(csr_pem)
        read_certificate(self.certificate)

def generate_domains(length):
    domains = []
    for i in range(length):
        domains.append(f"www.example{i}.com")
    return domains

if __name__ == '__main__':
    email = "example@example.com"

    _time = []
    for i in [1, 5, 10, 50, 100]:
        identifiers = generate_domains(i)
        start = time()
        client = SimpleACMEClient()
        client.run(email, identifiers)
        end = time()

        delta_time = end - start
        print(f"Time taken for {i} domains: {delta_time} seconds")
        _time.append(delta_time)

    print(_time)

# PLUS [28.46462392807007, 28.475237369537354, 29.000176668167114, 29.489553451538086, 30.080427169799805]
# ACME [17.357086181640625, 17.390870809555054, 17.349021673202515, 18.374998569488525, 18.449873208999634]
