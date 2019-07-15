
import numpy as np
import string
import time 
import hmac
import hashlib
import base64
import macaroons_lib2 as mlib

##########
##########
##########
# variables

# https://pynative.com/python-generate-random-string/
alphabet = [x for x in string.lowercase]
allAlphabet = alphabet + [x.upper() for x in alphabet]


##########
##########
##########
#functions 

#### Taken from: https://stackoverflow.com/questions/30686701/python-get-size-of-string-in-bytes
def utf8len(s):
    return len(s.encode('utf-8'))


def generateStringOfBytes(length):
    result = ''
    while(utf8len(result) != length):
        result+=np.random.choice(allAlphabet)
    return result


def generatePayloads(numPayloads, sizePayload):
    string_payloads = [generateStringOfBytes(sizePayload) for x in range(numPayloads)]
    return string_payloads


def hmac_sha_256(arr):
    payload = arr[0]
    key = arr[1]
    hexVal =  hmac.new(key, payload , hashlib.sha256).hexdigest()
    #print('here', hexVal)
    return hexVal

def timingModule(func, inputs ,numRuns =10000):
    startTime = time.time()
    outputs = []
    for i in range(numRuns):
        outputs.append(func(inputs[i]))
    endTime = time.time()
    return (outputs, startTime, endTime)
#### Generate 300 , 500, and  700 bytes of data 

def mint_macaroon(arr):
    public_id = arr[0]
    private_key = arr[1]
    location = arr[2]
    #### use library to compute HMAC
    M = mlib.CreateMacaroon(key, public_id, location)
    

def BENCHMARK_HMAC_SHA_256(numRuns, sizePayload, randomKeySizeBits=128):
    randomKey = generateStringOfBytes(int(randomKeySizeBits/8))
    payloads = generatePayloads(numRuns, sizePayload)
    data_inputs = [[payload , randomKey] for payload in payloads]
    (outputs, startTime, endTime) = timingModule(hmac_sha_256, payloads, numRuns = numRuns)
    diff = (endTime - startTime+.0)/numRuns
    print(startTime)
    print(endTime)
    diff = diff * 1000000.
    print("BENCHMARK_HMAC_SHA_256: The difference in time for ", numRuns , "numRuns is ", diff , " microseconds")
    return outputs

def BENCHMARK_MINT_MACAROON(numRuns, sizePayload , randomKeySizeBits=128):
    randomKey = generateStringOfBytes(int(randomKeySizeBits/8))
    payloads = generatePayloads(numRuns, sizePayload)

###########################
### Experiment 1: 300 bytes
##########import macaroons_lib2 as mlib#################
numberOfRuns = 1000
BYTES_SIZE = 300
result = BENCHMARK_HMAC_SHA_256(numberOfRuns, BYTES_SIZE, randomKeySizeBits=128)
 

