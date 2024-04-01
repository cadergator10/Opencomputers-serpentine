local component = require("component")
local modem = require("component").modem
local event = require("event")
local serialization = require("serialization")
local thread = require("thread")
local threadCount = 1
local name = "test1"

local port = 13675
modem.open(port)
send = {}
received = {}
local function receive(_, _, _, _, _, packet, receiver, sender)
	local data = serialization.unserialize(packet)
	if not data then
		return
	end
	if receiver == name then
		if not received[sender] then
			received[sender] = {}
		end
		table.insert(received[sender], data)
	end
end
event.listen("modem_message", receive)
for i=1, threadCount do
	thread.create(function()
		while true do
			for i, v in pairs(send) do
				while #v > 0 do
					modem.broadcast(port, serialization.serialize(table.remove(v, 1)), i, name)
				end
			end
			os.sleep()
		end
	end):detach()
end