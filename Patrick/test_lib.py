
import macaroons_lib


"""
    This function tests... 
"""
def test1_CreateMacaroon():
    #### Input: data 
    id = ""
    key = ""
    location = ""
    #### Output:  compute hmac on the outside 
    hmac_value = hmac.new(key, id, hashlib.sha256)
    #### use library to compute HMAC
    M = macaroons_lib.CreateMacaroon(key, id, location)
    #### Assertion: Does the library's output equal the expected value
    assert(M.sig == hmac_value)
    assert(M.id == id)
    
def test2_CreateMacaroon():
    id = ""
    key = ""
    location = ""
    macaroon = macaroons_lib.createMacaroon()



if(__name__ == "__main__"):
    test1_CreateMacaroon()
