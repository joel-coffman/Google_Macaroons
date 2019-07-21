import macaroons_lib2 as mlib	# library of macroons being tested
import hmac
import hashlib
import base64
import time
from Crypto.Cipher import AES	

"""This is a test file for testing each of the functions defined in macaroons_lib2

The five functional tests are written to ensure the appliable macaroons functions operate 
as defined within the paper written by Birgisson et al.'s "Macaroons: Cookies with Contextual 
Caveats for Decentralized Authorization in the Cloud". The macaroons functions from the 
paper's Figure 8 (Page 7) being tested within this test file include the following: 
    Test 2 - CreateMacaroon(k, id , L); 
    Test 3 - M.addCaveatHelper(cId, vId, cL)
    Test 4 - M.AddFirstPartyCaveat(a)
    Test 1 - M.Verify(TM , k, A, M)
The additional functions for marshalling and pasing JSONs are being also tested to support 
the replication of results in Birgisson et al. Table II.
    Test 5 - Mashal as JSON
    Test 5 - Parse from JSON
    
...

Test File Development Status
-------
    as of 3pm 7/20
        completed so far: 
            create macaroon
            verify 1st party caveat
        to do: 
            add 1st party caveat
            marshal and parse from json
            conversion to dict and obj
        not needed: 3rd party caveat since it is not in the table we are reproducing

        as of 420pm 7/20
        completed so far: 
            create macaroon, 
            verify 1st party caveat, 
            add 1st party caveat, 
            marshal and parse from json
            to do: 
            conversion to dict and obj 
                (talk to Ali, may not need testing, since we pulled straight from online source)
               not needed: 
            3rd party caveat since it is not in the table we are reproducing

...

Methods
-------
    printTestDesc(testName)
        Prints the tests name (i.e. testName) that is being attempted 
    printTestResult(testName, string)
        Prints the test name and its reuslts (i.e. testName and string) following test completion 
    test1_VerifyOfFirstPartyCaveats()
        Test 1 creates a macaroon and add first party caveats then tests the verify function
    test2_CreateMacaroon()
        Test 2 creates a simple macaroon and tests its creation
    test3_addCaveatHelper():
        Test 3 creates a simple macaroon and tests the caveat helper function
    test4_addFirstPartyCaveat():
        Test 4 tests add First Party Caveat function which is a function wrapper of addCaveatHelper
    test5_marshalAndParseJSON():
        Test 5 creates a macaroon and tests the marshal and parse to JSON functions
"""

def printTestDesc(testName):
    """Prints the tests name (i.e. testName) that is being attempted 	
    Parameters
    ----------
    testName : str
    The name of the test being run
    """
    print("------------------------------------------ ATTEMPTING ", testName)

def printTestResult(testName, string):
    """Prints the test name and its reuslts (i.e. testName and string) following test completion 
    
    Parameters
    ----------
    testName : str
        The name of the test being run
    testName : str
        The results of the test
    """
    print("------------------------------------------ "+ testName + ":"+ string )

def test1_VerifyOfFirstPartyCaveats():
    """Test 1 creates a macaroon and add first party caveats then tests the verify function
    """
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

def test2_CreateMacaroon():
    """Test 2 creates a simple macaroon and tests its creation
    """
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

oldMacaroonCopy = None 

def test3_addCaveatHelper():
    """Test 3 creates a simple macaroon and tests the caveat helper function
    """
    printTestDesc("addCaveatHelper")
    id = "abc"
    key = "234324"
    location = "DC"
    M = mlib.CreateMacaroon(key, id, location)
    global oldMacaroonCopy
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

def test4_addFirstPartyCaveat():
    """Test 4 tests add First Party Caveat function which is a function wrapper of addCaveatHelper
    """
    global oldMacaroonCopy
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
    """Test 5 creates a macaroon and tests the marshal and parse to JSON functions
    """
    printTestDesc("marshalToJSON")
    id = "abc"
    key = "234324"
    location = "DC"
    M = mlib.CreateMacaroon(key, id, location)
    caveat_cid = "123"
    caveat_vid = "0"
    caveat_cl = "NYC"
    M.addCaveatHelper(caveat_cid , caveat_vid,  caveat_cl)
    json_string = mlib.marshalToJSON(M)
    print(json_string)
    printTestDesc("parseToJSON")
    M_returned = mlib.parseFromJSON(json_string)
    #assert(M == M_returned)
    for key in M.__dict__.keys():
        object_of_M = M.__dict__[key]
        object_of_M_returned = M_returned.__dict__[key]
        print(key, object_of_M)
        if(type(object_of_M) == type([])):#list of strings
            assert(set(object_of_M) == set(object_of_M_returned))
        else:#string type
            assert(object_of_M_returned == object_of_M)
    #print(M_returned)
    printTestResult("test5_marshalAndParseJSON" , "SUCCESS")

if(__name__ == "__main__"):
    #  call all five tests
    test1_VerifyOfFirstPartyCaveats()
    test2_CreateMacaroon()
    test3_addCaveatHelper()
    test4_addFirstPartyCaveat()
    test5_marshalAndParseJSON()

"""old code
"""
# id = "abc"
# key = "234324"
# location = "DC"
# M = CreateMacaroon(key, id, location)
# M.addCaveatHelper("123", "sdfd", "NYC")
# M.addCaveatHelper("13423", "sdfdfd", "DC")
# M.addCaveatHelper("12dfd3", "sd343fd", "Baltimore")
# json_string = marshalToJSON(M)
# M_returned = parseFromJSON(json_string)

"""old code
"""
# M.thirdPartyLocations = ["NYC" , "DC", "Baltimore"]
# json_string2 = marshalToJSON(M)
# M_returned2 = parseFromJSON(json_string2)
