import hmac
import hashlib
import base64
import time

# https://stackoverflow.com/questions/39767297/how-to-use-sha256-hmac-in-python-code 
#  https://docs.python.org/2/library/hmac.html 
# time it: https://stackoverflow.com/questions/1938048/high-precision-clock-in-python
key = "our key"
msg = 'this is the message'


def getSampleMacaroon(key, msg):
    data = hmac.new(key, msg, hashlib.sha256)
    datastr = data.hexdigest()
    caveat = "photo == cat"
    macaroon_with_caveat = hmac.new(datastr, caveat, hashlib.sha256)
    macaroon = [msg, caveat, macaroon_with_caveat]
    return macaroon

total_runs = 10000
start = time.time()
macs = []
for x in range(0,total_runs ):
    macs.append(getSampleMacaroon(key, msg))

end = time.time()

diff = (end -start)#/(10**9+.0)

average_time = diff/(total_runs+.0)