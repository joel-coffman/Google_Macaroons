# different hashlib,  different python version, 
import numpy as np
import string
import time 
import hmac
import hashlib
import base64
import macaroons_lib2_27 as mlib
import copy
import random
import math
##########
########## C:/Users/User/Anaconda3_7/python.exe
##########
# variables

# https://pynative.com/python-generate-random-string/
alphabet = [x for x in 'abcdefghijklmnopqrstuvwxyz']
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
        #index = int(math.floor(len(allAlphabet)*random.random()))
        result+=np.random.choice(allAlphabet)
    return result


def generatePayloads(numPayloads, sizePayload):
    string_payloads = [generateStringOfBytes(sizePayload) for x in range(numPayloads)]
    return string_payloads


def hmac_sha_256(arr):
    payload = arr[0]
    key = arr[1]
    #print("len arr, ", len(arr))
    #print(key)
    #print(payload)
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

# globalTimes_diff = []

# def timingModule(func, inputs ,numRuns =10000):
#     startTime = time.time()
#     outputs = []
#     for i in range(numRuns):
#         startTime = time.time()
#         outputs.append(func(inputs[i]))
#         endTime = time.time()
#         diff = endTime - startTime
#         global globalTimes_diff 
#         globalTimes_diff.append(diff)
#     endTime = time.time()
#     return (outputs, startTime, endTime)

#### Generate 300 , 500, and  700 bytes of data 

def mint_macaroon(arr):
    public_id = arr[0]
    private_key = arr[1]
    location = arr[2]
    #### use library to compute HMAC
    M = mlib.CreateMacaroon(private_key, public_id, location)
    #M.addFirstPartyCaveat("chunk E 100 ... 500")
    #M.addFirstPartyCaveat("op E read, write")
    #M.addFirstPartyCaveat("time < 5/1/13 3pm")
    return M

def add_caveat(arr):
    macaroon= arr[0] 
    caveat_strings = arr[1]
    for caveat_string in caveat_strings:
        macaroon.addFirstPartyCaveat(caveat_string)
    return macaroon

def verify_macaroon(arr):
    macaroon = arr[0] 
    K_TargetService = arr[1]
    assert(mlib.verify(macaroon, K_TargetService ) == True)
    return macaroon

def calculate_AES(arr):
    sig = arr[0]
    key = arr[1]
    ciphertext = mlib.ENC4(sig, key)
    return ciphertext


def extendPayload(data):
    if(len(data)< 256):
        data = data + (256 - len(data)) * '#'
    else: 
        bytes_to_add = int(len(data)%256)
        data =data+(256-bytes_to_add)*"#"
    return data 



def BENCHMARK_AES_128(numRuns, sizePayload, randomKeySizeBits=128):
    randomKey = generateStringOfBytes(int(randomKeySizeBits/8))
    payloads = generatePayloads(numRuns, sizePayload)
    payloads = [extendPayload(payload) for payload in payloads]
    #print("length of payloads is: ", len(payloads))
    data_inputs = [[payload , randomKey] for payload in payloads]
    (outputs, startTime, endTime) = timingModule(calculate_AES,data_inputs, numRuns = numRuns)
    diff = (endTime - startTime+.0)/numRuns
    #print(startTime)
    #print(endTime)
    diff = diff * 1000000.
    global results_data
    results_data.append(diff)
    print("BENCHMARK_AES_128: The difference in time for ", numRuns , "numRuns is ", diff , " microseconds")
    return outputs


# def BENCHMARK_AES_256(numRuns, sizePayload, randomKeySizeBits=128):
#     randomKey = generateStringOfBytes(int(randomKeySizeBits/8))
#     payloads = generatePayloads(numRuns, sizePayload)
#     payloads = [extendPayload(payload) for payload in payloads]
#     #print("length of payloads is: ", len(payloads))
#     data_inputs = [[payload , randomKey] for payload in payloads]
#     (outputs, startTime, endTime) = timingModule(calculate_AES,data_inputs, numRuns = numRuns)
#     diff = (endTime - startTime+.0)/numRuns
#     #print(startTime)
#     #print(endTime)
#     diff = diff * 1000000.
#     print("BENCHMARK_AES_128: The difference in time for ", numRuns , "numRuns is ", diff , " microseconds")
#     return outputs



a= []
results_data = []
def BENCHMARK_HMAC_SHA_256(numRuns, sizePayload, randomKeySizeBits=128):
    randomKey = generateStringOfBytes(int(randomKeySizeBits/8))
    payloads = generatePayloads(numRuns, sizePayload)
    #print("length of payloads is: ", len(payloads))
    global a 
    a = copy.deepcopy(payloads)
    data_inputs = [[payload , randomKey] for payload in payloads]
    (outputs, startTime, endTime) = timingModule(hmac_sha_256,data_inputs, numRuns = numRuns)
    diff = (endTime - startTime+.0)/numRuns
    #print(startTime)
    #print(endTime)
    diff = diff * 1000000.
    global results_data
    results_data.append(diff)
    print("BENCHMARK_HMAC_SHA_256: The difference in time for ", numRuns , "numRuns is ", diff , " microseconds")
    return outputs

def BENCHMARK_MINT_MACAROON(numRuns, sizePayload , randomKeySizeBits=128):
    randomKey = generateStringOfBytes(int(randomKeySizeBits/8))
    payloads = generatePayloads(numRuns, sizePayload)
    print("length of payloads is: ", len(payloads))
    data_inputs = [[payload , randomKey, "MY LOCATION"] for payload in payloads]
    (outputs, startTime, endTime) = timingModule(mint_macaroon, data_inputs, numRuns = numRuns)
    diff = (endTime - startTime+.0)/numRuns
    #print(startTime)
    #print(endTime)
    diff = diff * 1000000.
    global results_data
    results_data.append(diff)
    print("BENCHMARK_MINT_MACAROON: The difference in time for ", numRuns , "numRuns is ", diff , " microseconds")
    return outputs, randomKey

"""
caveats_to_copy is a list of strings, so you could have caveats_to_copy =[string1, string2, string3]
"""
def BENCHMARK_ADD_CAVEAT(list_macaroons, caveats_to_copy):
    numRuns = len(list_macaroons)
    list_caveats  = [copy.deepcopy(caveats_to_copy) for x in range(numRuns)]
    data_inputs = []
    for index in range(numRuns):
        data_inputs.append([list_macaroons[index], list_caveats[index]])
    (outputs, startTime, endTime) = timingModule(add_caveat, data_inputs, numRuns = numRuns)
    diff = (endTime - startTime+.0)/numRuns
    #print(startTime)
    #print(endTime)
    diff = diff * 1000000.
    global results_data
    results_data.append(diff)
    print("BENCHMARK_ADD_CAVEAT: The difference in time for ", numRuns , "numRuns is ", diff , " microseconds")
    return outputs

def BENCHMARK_VERIFY(list_macaroons, randomKey):
    numRuns = len(list_macaroons)
    listRandomKeys  = [randomKey for x in range(numRuns)]
    data_inputs = []
    for index in range(numRuns):
        data_inputs.append([list_macaroons[index], listRandomKeys[index]])
    (outputs, startTime, endTime) = timingModule(verify_macaroon, data_inputs, numRuns = numRuns)
    diff = (endTime - startTime+.0)/numRuns
    #print(startTime)
    #print(endTime)
    diff = diff * 1000000.
    global results_data
    results_data.append(diff)
    print("BENCHMARK_VERIFY: The difference in time for ", numRuns , "numRuns is ", diff , " microseconds")
    return outputs

def BENCHMARK_MARSHALL_JSON(list_macaroons):
    numRuns = len(list_macaroons)
    data_inputs = list_macaroons
    (outputs, startTime, endTime) = timingModule(  mlib.marshalToJSON , data_inputs, numRuns = numRuns)
    diff = (endTime - startTime+.0)/numRuns
    #print(startTime)
    #print(endTime)
    diff = diff * 1000000.
    global results_data
    results_data.append(diff)
    print("BENCHMARK_MARSHALL_JSON: The difference in time for ", numRuns , "numRuns is ", diff , " microseconds")
    return outputs


def BENCHMARK_PARSE_JSON(list_macaroons_strings):
    numRuns = len(list_macaroons_strings)
    data_inputs = list_macaroons_strings
    (outputs, startTime, endTime) = timingModule(  mlib.parseFromJSON , data_inputs, numRuns = numRuns)
    diff = (endTime - startTime+.0)/numRuns
    #print(startTime)
    #print(endTime)
    diff = diff * 1000000.
    global results_data
    results_data.append(diff)
    print("BENCHMARK_PARSE_JSON: The difference in time for ", numRuns , "numRuns is ", diff , " microseconds")
    return outputs




###########################
### Experiment 1: 300 bytes
##########import macaroons_lib2 as mlib#################
numberOfRuns = 5000
BYTES_SIZE = 300
print("-------------------------------------------------------------------------")
print("------------------------BYTES IN PAYLOAD = "+str(BYTES_SIZE)+"---------------------------")
print("-------------------------------------------------------------------------")



result = BENCHMARK_HMAC_SHA_256(numberOfRuns, BYTES_SIZE, randomKeySizeBits=128)
resulta = BENCHMARK_AES_128(numberOfRuns, BYTES_SIZE, randomKeySizeBits=128)
# datarun = np.array(globalTimes_diff)
# print(datarun.min(), " ", datarun.max(), " ", datarun.std(), " ", datarun.var(), " ", datarun.mean())
(macaroons_, randomKey) = BENCHMARK_MINT_MACAROON(numberOfRuns, BYTES_SIZE, randomKeySizeBits=128)
macaroons_with_caveats_added = BENCHMARK_ADD_CAVEAT(macaroons_, caveats_to_copy=["chunk E 100 ... 500", "op E read, write", "time < 5/1/13 3pm"])
macaroons_verified=BENCHMARK_VERIFY(macaroons_with_caveats_added, randomKey)
macaroons_as_json_strings=BENCHMARK_MARSHALL_JSON(macaroons_verified)
macaroons_back_as_objects=BENCHMARK_PARSE_JSON(macaroons_as_json_strings)
print(results_data)
results_data = []


BYTES_SIZE = 500
print("-------------------------------------------------------------------------")
print("------------------------BYTES IN PAYLOAD = "+str(BYTES_SIZE)+"---------------------------")
print("-------------------------------------------------------------------------")

result = BENCHMARK_HMAC_SHA_256(numberOfRuns, BYTES_SIZE, randomKeySizeBits=128)
resulta = BENCHMARK_AES_128(numberOfRuns, BYTES_SIZE, randomKeySizeBits=128)
(macaroons_, randomKey) = BENCHMARK_MINT_MACAROON(numberOfRuns, BYTES_SIZE, randomKeySizeBits=128)
macaroons_with_caveats_added = BENCHMARK_ADD_CAVEAT(macaroons_, caveats_to_copy=["chunk E 100 ... 500", "op E read, write", "time < 5/1/13 3pm"])
macaroons_verified=BENCHMARK_VERIFY(macaroons_with_caveats_added, randomKey)
macaroons_as_json_strings=BENCHMARK_MARSHALL_JSON(macaroons_verified)
macaroons_back_as_objects=BENCHMARK_PARSE_JSON(macaroons_as_json_strings)
print(results_data)
results_data = []



BYTES_SIZE = 700
print("-------------------------------------------------------------------------")
print("------------------------BYTES IN PAYLOAD = "+str(BYTES_SIZE)+"---------------------------")
print("-------------------------------------------------------------------------")

result = BENCHMARK_HMAC_SHA_256(numberOfRuns, BYTES_SIZE, randomKeySizeBits=128)
resulta = BENCHMARK_AES_128(numberOfRuns, BYTES_SIZE, randomKeySizeBits=128)
(macaroons_, randomKey) = BENCHMARK_MINT_MACAROON(numberOfRuns, BYTES_SIZE, randomKeySizeBits=128)
macaroons_with_caveats_added = BENCHMARK_ADD_CAVEAT(macaroons_, caveats_to_copy=["chunk E 100 ... 500", "op E read, write", "time < 5/1/13 3pm"])
macaroons_verified=BENCHMARK_VERIFY(macaroons_with_caveats_added, randomKey)
macaroons_as_json_strings=BENCHMARK_MARSHALL_JSON(macaroons_verified)
macaroons_back_as_objects=BENCHMARK_PARSE_JSON(macaroons_as_json_strings)
print(results_data)
results_data = []

