
import macaroons_lib
import hmac
import hashlib
import base64
import time
from Crypto.Cipher import AES




def testVerifyOfFirstPartyCaveats():
    K_TargetService1 = "this is the secret key "
    K_TargetService2 = "this is also the secret key "
    random_nonce = str(433242342)
    location = "Catonsville, 21228"

    caveat1 = "level of coolness == high"
    caveat2 = "champions == USA Women's Team"

    M = macaroons_lib.CreateMacaroon(K_TargetService1, random_nonce, location)
    M.addFirstPartyCaveat(caveat1)
    M.addFirstPartyCaveat(caveat2)

    receivedMacaroon = M

    # M2 = macaroons_lib.CreateMacaroon(K_TargetService1, random_nonce, location)
    # M2.addFirstPartyCaveat(caveat1)
    # M2.addFirstPartyCaveat(caveat2)

    assert(macaroons_lib.verify(receivedMacaroon, K_TargetService2 ) == False)
    assert(macaroons_lib.verify(receivedMacaroon, K_TargetService1 ) == True)

"""
    This function tests... 
"""
def test1_CreateMacaroon():
    #### Input: data 
    id = "abc"
    key = "234324"
    location = "DC"
    #### Output:  compute hmac on the outside 
    hmac_value = hmac.new(key, id, hashlib.sha256)
    hmac_value_digest = hmac_value.hexdigest()
    #### use library to compute HMAC
    M = macaroons_lib.CreateMacaroon(key, id, location)
    #### Assertion: Does the library's output equal the expected value
    print(M.sig)
    print(hmac_value_digest)
    assert(M.sig == hmac_value_digest)
    assert(M.id == id)
    
def test2_CreateMacaroon():
    id = ""
    key = ""
    location = ""
    macaroon = macaroons_lib.createMacaroon()



if(__name__ == "__main__"):
    test1_CreateMacaroon()
    testVerify()