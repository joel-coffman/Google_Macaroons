import hmac
import hashlib
import base64
import time

"""
key: encryption key
id: random_nonce / payload
"""
def CreateMacaroon(key, id, location):
    data = hmac.new(key, id, hashlib.sha256)
    signature_str = data.hexdigest()  # KLUDGE: can we go back and forth from hexdigest()
    macaroon_obj = Macaroon( id , [], signature_str)
    macaroon_obj.targetLocation = location 
    return macaroon_obj

class Macaroon(object):
    def __init__(self, id, caveatsList, signature):
        self.caveats = caveatsList
        self.id = id
        self.sig = signature 
        #### 
        self.targetLocation = None
        self.thirdPartyLocations = [] 

    def addCaveatHelper(self, cId, vId, caveat_location):
        ### KLUDGE: "pattern matching" in the addCaveatHelper
        caveat = {'cid': cId, 'vid': vId, 'clocation':caveat_location }
        sig_prime =  hmac.new(self.sig, caveat['vid']+caveat['cid'] , hashlib.sha256)
        self.caveats.append(caveat)
        self.sig = sig_prime
        return self  

    def addThirdPartyCaveat(self):
        vId = 
        pass
    
    def addFirstPartyCaveat(self, a):
        self.addCaveatHelper(a, 0, self.targetLocation )
    
    def prepareForRequest(self):
        pass
    
    def verify(self):
        pass 



##
#
#
#
#
#
#
##