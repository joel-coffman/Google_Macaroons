import macaroons_lib2 as mlib
import hmac
import hashlib
import base64
import time
from Crypto.Cipher import AES

# In this test file, we will be testing each of the functions defined in macaroons_lib2 to ensure they are behaving as expected

def printTestDesc(testName):
    print("------------------------------------------ ATTEMPTING "+ testName)

def printTestResult(testName, string):
    print("------------------------------------------ "+ testName + ":"+ string )

"""
	completed so far as of 3pm 7/20: create macaroon, verift 1st party caveat
	to do: add 1st party caveat, marshal and parse from json, conversion to dict and obj
	not needed: 3rd party caveat since it is not in the table we are reproducing
"""


"""
        completed so far as of 420pm 7/20: create macaroon, verift 1st party caveat, add 1st party caveat, marshal and parse from json
        to do: conversion to dict and obj
        not needed: 3rd party caveat since it is not in the table we are reproducing
"""


# this function verifies first party caveats
def test1_VerifyOfFirstPartyCaveats():
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

# this function creates a simple macaroon
def test2_CreateMacaroon():
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
def test3_addCaveatHelper():
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
def test4_addFirstPartyCaveat():
    printTestDesc("addFirstPartyCaveat")
    id = "abc"
    key = "234324"
    location = "DC"
    M = mlib.CreateMacaroon(key, id, location)
    caveat_cid = "123"
    caveat_vid = "0"
    caveat_cl = "NYC"
    M.addCaveatHelper(caveat_cid , caveat_vid,  caveat_cl)
    assert(M.sig != oldMacaroonCopy.sig)
    #### what to verify
    #### test if the caveat was properly added
    string_caveat = caveat_cid + ":" + caveat_vid + ":" + caveat_cl
    assert(M.caveats[-1] == string_caveat)
    #### test if the caveat signature "evolved" correctly
    new_sig = hmac.new(oldMacaroonCopy.sig, caveat_vid+caveat_cid , hashlib.sha256)
    assert(M.sig == new_sig.hexdigest())
    printTestResult("addFirstPartyCaveat" , "SUCCESS")

def test5_marshalAndParseJSON():
    printTestDesc("marshalToJSON")
    id = "abc"
    key = "234324"
    location = "DC"
    M = mlib.CreateMacaroon(key, id, location)
    json_string = marshalToJSON(M)
    print(json_string)
    printTestDesc("parseToJSON")
    M_returned = parseFromJSON(json_string)
    print(M_returned)


if(__name__ == "__main__"):
    test1_VerifyOfFirstPartyCaveats()
    test2_CreateMacaroon()
    test3_addCaveatHelper()
    test4_addFirstPartyCaveat()
    test5_marshalAndParseJSON()




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

