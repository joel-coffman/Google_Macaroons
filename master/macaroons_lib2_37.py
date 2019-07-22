import hmac
import hashlib
import base64
import time
from Crypto.Cipher import AES
import json 
#C:/Users/User/Anaconda3_7/python.exe macaroons_benchmark_37.py
"""This is a library file for creating macaroons. The functions defined are only those
necessary to duplicate the results in Table 2 of Birgisson et al.'s "Macaroons: Cookies
with Contextual Caveats for Decentralized Authorization in the Cloud". 

The definition of a macaroon (M) as defined by Birgisson et al. is a tuple of the form
of macaroon@L(id,C,sig) where (per Figure 7)
    * L - Locs (optional) is a hint to the target's location
    * id - BitStrs is the macaroon identifier
    * C is a list of caveats of the form cav@cL(cId, vId), where
        * cL - Locs (optional) is a hint to a discharge location
        * cId - BitStrs is the caveat identifier
        * vId - BitStrs is the verification-key identifier
    * sig - Keys is a chained-MAC signature over the macaroon identifier id, as well as each of the caveats in C, in linear sequence.

The macaroons functions herein relative to the paper's Figure 8 definitions: 
	* CreateMacaroon(key, id, location) = CreateMacaroon(k, id , L); 
    * addCaveatHelper(self, cId, vId, caveat_location) = M.addCaveatHelper(cId, vId, cL)
	* addFirstPartyCaveat(self, a) = M.AddFirstPartyCaveat(a)
	* verify(macaroon, K_TargetService ) = M.Verify(TM , k, A, M)
The additional functions for marshalling and pasing JSONs are being also tested to support 
the replication of results in Birgisson et al. Table II.
	* marshalToJSON(macaroon) = Mashal as JSON to create JSON String
	* parseFromJSON(json_string): = Parse from JSON to create a macaroon

Methods
-------
	CreateMacaroon(key, id, location)
        Creates a macaroon
    ENC(sig, key)
        encrypts the signature with a secret key
	verify(macaroon, K_TargetService ):
        Verifies a macaroon and its caveats
    marshalToJSON(macaroon):
        creates a JSOOn string from a macaroon
    parseFromJSON(json_string):
        creates a macaroon from JSON string
    convert_to_dict(mac_obj):
        convert macaroon object to JSON object
    dict_to_obj(dictionary_obj):
        creates a macaroon from JSON object

Class Methods - macaroons(object)
-------
    addCaveatHelper(self, cId, vId, caveat_location)
        adds a caveat
    def addThirdPartyCaveat(self, cK, cId, cL)
        adds a third party caveat using the caveat helper function
    addFirstPartyCaveat(self, a)
        adds a first party caveat using the caveat helper function
    prepareForRequest(self)
        passes
"""

def CreateMacaroon(key, id, location):
    """Creates a macaroon
    
    Given a high-entropy root key k and an identifier id, the function CreateMacaroon(k,id) returns 
    a macaroon that has the identifier id, an empty caveat list, and a valid signature sig = MAC(k, id ).
    
    Parameters
	----------
    key : str
        encryption key   
    id : str
        random_nonce / payload
    location : str
        specified location
    """
    data = hmac.new(key.encode('utf-8'), id.encode('utf-8'), hashlib.sha256)
    signature_str = data.hexdigest()  # KLUDGE: can we go back and forth from hexdigest()
    macaroon_obj = Macaroon( id , [], signature_str)
    macaroon_obj.targetLocation = location 
    return macaroon_obj

def ENC(sig, key):
    """encrypts the signature with a secret key
    
    Parameters
	----------
    sig : str
        signaure to be encrypted   
    key : str
        secret key
    """
    password = "12324211231"
    key = hashlib.sha256(password).digest() ## output is 16 bytes
    key = key[:16]
    IV = 16 * '\x00'           # Initialization vector: discussed later
    mode = AES.MODE_CBC
    encryptor = AES.new(key, mode, IV=IV)
    forEncryption = hashlib.sha256(str(sig) + str(key)).digest() 
    ciphertext = encryptor.encrypt(forEncryption)
    return 

"""old code to delete?
"""
#KTS = dictionaryOfKeys[macaroon.id]
#verify(myMacaroon, KTS)

def verify(macaroon, K_TargetService ):
    """Verifies a macaroon and its caveats

    This function operates such that it can verify an incoming access request consisting of an 
    authorizing macaroon TM so a target service can ensure that all first-party embedded caveats 
    in TM are satisfied.

    Note this function is not the original "verify" in paper. (Since Table 2 doesn't require 
    third part caveats and verifying discharge macaroons). Thus this method only assumes 
    that the Macaroon was created with first party caveats. 
    
    Parameters
	----------
    macaroon : macaroon class object
        macaroon to be verified  
    K_TargetService : str
        key of target service
    """
    #### verify the K_TargetService with Random_Nonce
    data = hmac.new(K_TargetService.encode('utf-8'), macaroon.id.encode('utf-8'), hashlib.sha256)
    signature_str = data.hexdigest() 
    #### verify the caveats 
    for caveat in macaroon.caveats:
        #print(type(caveat))
        #print(caveat)
        caveatArr = caveat.split(':')
        cId = caveatArr[0] # str(caveat['cid'])
        vId = caveatArr[1] #str(caveat['vid'])
        sig_prime =  hmac.new(signature_str.encode('utf-8'), (str(vId)+str(cId)).encode('utf-8') , hashlib.sha256)
        signature_str = sig_prime.hexdigest()
    if(signature_str != macaroon.sig):
        return False #### incorrect 
    else: 
        return True #### verified to be correct 

class Macaroon(object):
    """
    A class used to represent a macaroon

    ...

    Attributes
    ----------
    caveats : [str]
        C is a list of caveats of the form cav@cL(cId, vId), where
            * cL - Locs (optional) is a hint to a discharge location
            * cId - BitStrs is the caveat identifier
            * vId - BitStrs is the verification-key identifier
    id : str
        BitStrs is the macaroon identifier
    signature : str
        Keys is a chained-MAC signature over the macaroon identifier id, as well as each of the caveats in C, in linear sequence 

    Methods
    -------
    addCaveatHelper(self, cId, vId, caveat_location)
        adds a caveat
    def addThirdPartyCaveat(self, cK, cId, cL)
        adds a third party caveat using the caveat helper function
    addFirstPartyCaveat(self, a)
        adds a first party caveat using the caveat helper function
    prepareForRequest(self)
        passes
    """

    def __init__(self, id, caveatsList, signature):
        """
        Parameters
	    ----------
        id : str
            BitStrs is the macaroon identifier
        caveatsList : [str]
            C is a list of caveats of the form cav@cL(cId, vId)
        signature = str
            Keys is a chained-MAC signature over the macaroon identifier id, as well as each of the caveats in C, in linear sequence
        """
        caveatsList = [str(x) for x in caveatsList]
        signature = str(signature)
        id = str(id)
        self.caveats = caveatsList
        self.id = id
        self.sig = signature 
        #### 
        self.targetLocation = None
        self.thirdPartyLocations = [] 

    def addCaveatHelper(self, cId, vId, caveat_location):
        """adds a caveat
        
        Parameters
	    ----------
        cId : str
            cId - BitStrs is the caveat identifier
        vId : str
            vId - BitStrs is the verification-key identifier
        caveat_location : str
            cL - Locs (optional) is a hint to a discharge location
        """
        ### KLUDGE: "pattern matching" in the addCaveatHelper
        typeCaveat = type(caveat_location)
        caveat =  str(cId) +":" + str(vId) + ":" + str(caveat_location)
        #print("self.sig ", self.sig, "  and type is: ", type(self.sig))
        sig_prime =  hmac.new( str(self.sig).encode('utf-8'), (str(vId)+str(cId)).encode('utf-8') , hashlib.sha256)
        self.caveats.append(caveat)
        self.sig = sig_prime.hexdigest()
        return self  

    def addThirdPartyCaveat(self, cK, cId, cL):
        """adds a third party caveat using the caveat helper function
        
        Parameters
	    ----------
        cK : str
            caveat key
        cId : str
            verification-key identifier
        cL : str
            cL - Locs (optional) is a hint to a discharge location
        """
        vId = ENC(self.sig, cK)
        self.thirdPartyLocations.append(cL)
        self.addCaveatHelper(cId, vId, cL)

    def addFirstPartyCaveat(self, a):
        """adds a first party caveat using the caveat helper function
        
        Parameters
	    ----------
        a : str
            caveat to be added to a macaroon
        """
        self.addCaveatHelper(a, '0', self.targetLocation )
   
    def prepareForRequest(self):
        '''passes
        '''
        pass

"""
 Reference is https://www.w3schools.com/python/python_json.asp 
 https://medium.com/python-pandemonium/json-the-python-way-91aac95d4041
"""

def marshalToJSON(macaroon):
    """creates a JSOOn string from a macaroon

    Parameters
	----------
    macaroon : macaroon class object
        macaroon for converting to JSON   
    """
    json_string = json.dumps(macaroon, default=convert_to_dict)
    return json_string 

def parseFromJSON(json_string):
    """creates a macaroon from JSON string

    Parameters
	----------
    json_string : json class object
        json class object for parsing  
    """
    macaroon_object = json.loads(json_string, object_hook=dict_to_obj)
    return macaroon_object 

def convert_to_dict(mac_obj):
    """convert macaroon object to JSON object

    Parameters
	----------
    mac_obj : macaroon class object
        macaroon class object for marshalling  
    """
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
    """creates a macaroon from JSON object

    Parameters
	----------
    dictionary_obj : json class object
        json class object for parsing  
    """
    #print("---", str(dictionary_obj))
    caveatsList = dictionary_obj['caveats']
    #print(type(caveatsList))
    #print(caveatsList)
    macaroon_object = Macaroon(dictionary_obj["id"] , caveatsList , dictionary_obj['sig'] )
    macaroon_object.targetLocation = dictionary_obj["targetLocation"]
    #print(" in dict_to_obj = ", dictionary_obj["thirdPartyLocations"])
    macaroon_object.thirdPartyLocations = dictionary_obj["thirdPartyLocations"]
    return macaroon_object