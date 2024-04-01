local caPubPath = "/home/caPub.txt"
local certPath = "/home/cert.txt"
local component = require("component")
local dataCard = component.data
local serialization = require("serialization")
local event = require("event")

local function read(file) --file = name of file
    local filed = io.open(file)
    if filed ~= nil then
        local text = filed:read("*all")
        filed:close()
        return text
    else
        return nil
    end
end
local caPub = dataCard.deserializeKey(read(caPubPath), "ec-public")
local cert = serialization.unserialize(read(certPath) or "")

local keylist = {}

local blockSize = 64
local opad = tonumber("0x"..string.rep("5c", blockSize))
local ipad = tonumber("0x"..string.rep("36", blockSize))
local function HMAC(K, m)
    local k
    if #K == blockSize then
        k = tonumber(string.gsub(K, ".", string.byte))
    else
        k = tonumber(string.gsub(dataCard.sha256(K), ".", string.byte))
    end
    return dataCard.sha256((k~opad)..dataCard.sha256((k~ipad)..m))
end
local function PRF(len, ...)
    local hash = dataCard.sha256(serialization.serialize({...}))
    repeat
        hash = hash..dataCard.sha256(hash)
    until string.len(hash) >= len
    return string.sub(hash, 1, len)
end
local function split(data, len)
    local split = {}
    for i=1, math.ceil(string.len(data)/len) do
        split[i] = string.sub(data, ((i-1)*len)+1, i*len)
    end
    return split
end
local function validateCert(cert, name, remotePub)
    if not dataCard.ecdsa(cert.data, caPub) then
        return false
    end
    if not cert.data.name == name then
        return false
    end
    if not cert.data.pub == remotePub then
        return false
    end
end
local network = {}
network.encrypt = function(plaintext, name)
    local keys = keylist[name]
    local IV = dataCard.random(16)
    local ciphertext = dataCard.encrypt(plaintext, keys.aes, IV)
    local encrypted = {data = ciphertext, HMAC = HMAC(keys.HMAC, ciphertext)}
    local authenticated = {data = IV, HMAC = HMAC(keys.HMAC, IV)}
    return {encrypted=encrypted, authenticated=authenticated}
end
network.decrypt = function(message, name)
    local keys = keylist[name]
    local IV = message.authenticated.data
    local ciphertext = message.encrypted.data
    local plaintext = dataCard.decrypt(ciphertext, keys.aes, IV)
    if not HMAC(keys.HMAC, IV) == message.authenticated.HMAC then
        return nil, false
    end
    if not HMAC(keys.HMAC, ciphertext) == message.encrypted.HMAC then
        return nil, false
    end
    return plaintext, true
end
network.send = function(message, name)
    table.insert(send[name], network.encrypt(message, name))
end
network.receive = function(name)
    local message = table.remove(received[name], 1)
    return network.decrypt(message, name)
end
network.keyExchange = function(name, requireAuthentication, timeout)
    local timeout = timeout or math.huge
    keylist[name] = {}
    local pub, pri = dataCard.generateKeyPair(384)
    send[name] = {}
    table.insert(send[name], pub.serialize())
    if cert then
        table.insert(send[name], cert)
    end
    if not received[name] then
        received[name] = {}
    end
    while #received[name] <= 0 and timeout > 0 do
        os.sleep(0.01)
        timeout = timeout - 0.01
    end
    local message = table.remove(received[name], 1)
    local remotePub = dataCard.deserializeKey(message, "ec-public")
    if requireAuthentication then
        local valid = false
        while (not vaild) and timeout > 0 do
            os.sleep(0.01)
            timeout = timeout - 0.01
            local cert = table.remove(received[name], 1)
            if validateCert(cert, name, remotePub) then
                valid = true
            end
        end
        if not valid then
            keylist[name] = nil
            received[name] = nil
            send[name] = nil
            return false
        end
    end
    local fullKey = PRF(32, dataCard.ecdh(pri, remotePub))
    local splitKey = split(fullKey, 16)
    keylist[name].aes = table.remove(splitKey, 1)
    keylist[name].HMAC = table.remove(splitKey, 1)
    return true
end
return network