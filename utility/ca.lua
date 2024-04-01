local caPubPath = "/home/caPub.txt"
local caPriPath = "/home/caPri.txt"
local certPath = "/home/cert.txt"
local pubPath = "/home/pub.txt"
local component = require("component")
local dataCard = component.data
local serialization = require("serialization")

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
local function store(var,file) --var = string to save; file = name of file
	local filed = assert(io.open(file, "w"))
	filed:write(var)
	filed:close()
	return true --pretty much will always return true unless it errors, so not important
end

local data = read(caPubPath)
local pub, pri
if data then
	pub = dataCard.deserializeKey(data, "ec-public")
	local pri = dataCard.deserializeKey(read(caPriPath), "ec-private")
else
	if io.read() ~= "yes" then
		error("no certificate found")
	end
	pub, pri = dataCard.generateKeyPair(384)
	store(pub.serialize(), caPubPath)
	store(pri.serialize(), caPriPath)
end
local function handle(path, mode, name)
	if not path then
		error("no path provided")
	end
	if mode == "sign" then
		if not name then
			error("no name provided")
		end
		local input = read(path..pubPath)
		data = serialization.serialize({pub = input, name = name})
		store(serialization.serialize({data = data, sign = dataCard.ecdsa(data, pri)}), path..certPath)
	else
		store(pub.serialize(), path..caPubPath)
	end
end
handle(...)