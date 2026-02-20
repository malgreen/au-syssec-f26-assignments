import json
import base64
import requests
import sys

assert len(sys.argv) == 2, "missing url parameter"
url = sys.argv[1]

pk_response = requests.get(url + "/pk/").json()
N: int = int(pk_response["N"])
e: int = int(pk_response["e"])

msg = b'You got a 12 because you are an excellent student! :)'

r: int = 2
msg_int: int = int.from_bytes(msg, 'big')
msg_q_int = r ** e * msg_int % N
msg_q = msg_q_int.to_bytes(msg_int.bit_length(), 'big').hex()

sig_response = requests.get(url + "/sign_random_document_for_students/" + msg_q + "/").json()
sig_q: int = int(sig_response["signature"], 16) # because answer is a hex string
sig: int = (sig_q // r) % N # '//' means that we don't do float calculations

cookie_json = json.dumps({
    "msg": msg.hex(),
    "signature": hex(sig).removeprefix("0x")
})

cookie_base64 = base64.b64encode(cookie_json.encode(), altchars=b'-_').decode()

quote_response = requests.get(url + "/quote/", cookies={"grade": cookie_base64})
print(quote_response.content.decode())

grade_response = requests.get(url + "/grade/", cookies={"grade": cookie_base64})
print(grade_response.content.decode())
