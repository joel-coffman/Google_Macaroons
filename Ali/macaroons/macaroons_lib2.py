import hmac
import hashlib
import base64
import time
from Crypto.Cipher import AES
import json 

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


def ENC(sig, key):
    password = "12324211231"
    key = hashlib.sha256(password).digest() ## output is 16 bytes
    key = key[:16]
    IV = 16 * '\x00'           # Initialization vector: discussed later
    mode = AES.MODE_CBC
    encryptor = AES.new(key, mode, IV=IV)
    forEncryption = hashlib.sha256(str(sig) + str(key)).digest() 
    ciphertext = encryptor.encrypt(forEncryption)
    return 


#KTS = dictionaryOfKeys[macaroon.id]
#verify(myMacaroon, KTS)

"""
    Not the original "verify" in paper. 
    This method only assumes that the Macaroon was created with first party caveats. 
"""
def verify(macaroon, K_TargetService ):
    #### verify the K_TargetService with Random_Nonce
    data = hmac.new(K_TargetService, macaroon.id, hashlib.sha256)
    signature_str = data.hexdigest() 
    #### verify the caveats 
    for caveat in macaroon.caveats:
        cId = caveat['cid']
        vId = caveat['vid']
        sig_prime =  hmac.new(signature_str, caveat['vid']+caveat['cid'] , hashlib.sha256)
        signature_str = sig_prime.hexdigest()
    if(signature_str != macaroon.sig):
        return false #### incorrect 
    else: 
        return true #### verified to be correct 

class Macaroon(object):
    def __init__(self, id, caveatsList, signature):
        caveatsList = [unicode(x) for x in caveatsList]
        signature = unicode(signature)
        id = unicode(id)
        self.caveats = caveatsList
        self.id = id
        self.sig = signature 
        #### 
        self.targetLocation = None
        self.thirdPartyLocations = [] 
    def addCaveatHelper(self, cId, vId, caveat_location):
        ### KLUDGE: "pattern matching" in the addCaveatHelper
        caveat =  cId +":" + vId + ":" + caveat_location
        sig_prime =  hmac.new(self.sig, vId+cId , hashlib.sha256)
        self.caveats.append(caveat)
        self.sig = sig_prime.hexdigest()
        return self  
    def addThirdPartyCaveat(self, cK, cId, cL):
        vId = ENC(self.sig, cK)
        self.thirdPartyLocations.append(cL)
        self.addCaveatHelper(cId, vId, cL)
    def addFirstPartyCaveat(self, a):
        self.addCaveatHelper(a, 0, self.targetLocation )
    def prepareForRequest(self):
        pass

"""
 Reference is https://www.w3schools.com/python/python_json.asp 
 https://medium.com/python-pandemonium/json-the-python-way-91aac95d4041
"""
def marshalToJSON(macaroon):
    json_string = json.dumps(macaroon, default=convert_to_dict)
    return json_string 

def parseFromJSON(json_string):
    macaroon_object = json.loads(json_string, object_hook=dict_to_obj)
    return macaroon_object 

def convert_to_dict(mac_obj):
    dictionary = {"caveats": mac_obj.caveats,
                 "id": mac_obj.id, 
                "sig": mac_obj.sig, 
                "targetLocation":mac_obj.targetLocation,
                "thirdPartyLocations": mac_obj.thirdPartyLocations
    }
    obj_dict = {
    "__class__": mac_obj.__class__.__name__,
    "__module__": mac_obj.__module__
    }
    obj_dict.update(mac_obj.__dict__)
    return obj_dict

def dict_to_obj(dictionary_obj):
    print("---", str(dictionary_obj))
    caveatsList = dictionary_obj['caveats']
    macaroon_object = Macaroon(dictionary_obj["id"] , caveatsList , dictionary_obj['sig'] )
    macaroon_object.targetLocation = dictionary_obj["targetLocation"]
    print(" in dict_to_obj = ", dictionary_obj["thirdPartyLocations"])
    macaroon_object.thirdPartyLocations = dictionary_obj["thirdPartyLocations"]
    return macaroon_object

