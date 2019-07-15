
import macaroons_lib2 as mlib
import hmac
import hashlib
import base64
import time
from Crypto.Cipher import AES

def printTestDesc(testName):
    print("------------------------------------------ ATTEMPTING "+ testName)

def printTestResult(testName, string):
    print("------------------------------------------ "+ testName + ":"+ string )



def testVerifyOfFirstPartyCaveats():
    K_TargetService1 = "this is the secret key "
    K_TargetService2 = "this is also the secret key "
    random_nonce = str(433242342)
    location = "Catonsville, 21228"
    caveat1 = "level of coolness == high"
    caveat2 = "champions == USA Women's Team"
    M = mlib.CreateMacaroon(K_TargetService1, random_nonce, location)
    M.addFirstPartyCaveat(caveat1)
    M.addFirstPartyCaveat(caveat2)
    receivedMacaroon = M
    # M2 = mlib.CreateMacaroon(K_TargetService1, random_nonce, location)
    # M2.addFirstPartyCaveat(caveat1)
    # M2.addFirstPartyCaveat(caveat2)
    assert(mlib.verify(receivedMacaroon, K_TargetService2 ) == False)
    assert(mlib.verify(receivedMacaroon, K_TargetService1 ) == True)

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
    M = mlib.CreateMacaroon(key, id, location)
    #### Assertion: Does the library's output equal the expected value
    #print(M.sig)
    #print(hmac_value_digest)
    printTestDesc("CreateMacaroon")
    assert(M.sig == hmac_value_digest)
    assert(M.id == id)
    printTestResult("CreateMacaroon" , "SUCCESS")

"""
    This function tests... addCaveatHelper
"""
def test2_addCaveatHelper():
    printTestDesc("addCaveatHelper")
    id = "abc"
    key = "234324"
    location = "DC"
    M = mlib.CreateMacaroon(key, id, location)
    oldMacaroonCopy = mlib.parseFromJSON(mlib.marshalToJSON(M))
    assert(M.sig == oldMacaroonCopy.sig)
    caveat_cid = "123"
    caveat_vid = "sdfd"
    caveat_cl = "NYC"
    ## test addCaveatHelper
    M.addCaveatHelper(caveat_cid , caveat_vid,  caveat_cl)
    assert(M.sig != oldMacaroonCopy.sig)
    #### what to verify 
    #### test if the caveat was properly added 
    string_caveat = caveat_cid + ":" + caveat_vid + ":" + caveat_cl 
    assert(M.caveats[-1] == string_caveat)
    #### test if the caveat signature "evolved" correctly
    new_sig = hmac.new(oldMacaroonCopy.sig, caveat_vid+caveat_cid , hashlib.sha256)
    assert(M.sig == new_sig.hexdigest())
    printTestResult("addCaveatHelper" , "SUCCESS")

"""
    This function tests... addFirstPartyCaveat  --> this function wraps add caveat helper
"""
def test2_addFirstPartyCaveat():
    id = ""
    key = ""
    location = ""
    macaroon = mlib.createMacaroon()





if(__name__ == "__main__"):
    test1_CreateMacaroon()
    test2_addCaveatHelper()
    #testVerify()





# id = "abc"
# key = "234324"
# location = "DC"
# M = CreateMacaroon(key, id, location)
# M.addCaveatHelper("123", "sdfd", "NYC")
# M.addCaveatHelper("13423", "sdfdfd", "DC")
# M.addCaveatHelper("12dfd3", "sd343fd", "Baltimore")
# json_string = marshalToJSON(M)
# M_returned = parseFromJSON(json_string)


# M.thirdPartyLocations = ["NYC" , "DC", "Baltimore"]
# json_string2 = marshalToJSON(M)
# M_returned2 = parseFromJSON(json_string2)

