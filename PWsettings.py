

BROKER_PUBKEY_FILE = 'broker-keys/pubkey.pem'
BROKER_PRIVKEY_FILE = 'broker-keys/privkey.pem'

USER_PUBKEY_FILE = 'user-keys/pubkey.pem'
USER_PRIVKEY_FILE = 'user-keys/privkey.pem'



BROKER_PORT = 7070
BROKER_ADDR = 'http://localhost:'+str(BROKER_PORT)

VENDOR_PORT = 8080
VENDOR_ADDR = 'http://localhost:'+str(VENDOR_PORT)



CERT_ROUTE = BROKER_ADDR+'/register'
REDEEM_ROUTE = BROKER_ADDR+'/redeem'

COMMIT_ROUTE = VENDOR_ADDR+'/commit'
# PAY_ROUTE = VENDOR_ADDR+'/pay'


PW_VALUE = 1    # 1 cent

TO_PAY = 5
TO_RECEIVE = TO_PAY
