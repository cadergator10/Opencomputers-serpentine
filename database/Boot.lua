--The startup which checks for updates and whether it's using OpenOS or MineOS
local status, compat = pcall(require,"Compat")
if not status then --auto assume system is OpenOS because MineOS should autoinstall it
    print("Installing Compatability layer")
    os.execute("wget -f https://raw.githubusercontent.com/cadergator10/Opencomputers-serpentine/main/database/Compat.lua Compat.lua")
    compat = require("Compat")
end
local download = "https://cadespc.com/servertine/modules/getservertine"
local config = compat.loadTable("bootconfig.txt")
local term = not compat.isMine and require("term") or nil

local openOSReq = {["JSON.lua"]="https://github.com/IgorTimofeev/MineOS/raw/master/Libraries/JSON.lua",["GUI.lua"]="https://github.com/IgorTimofeev/GUI/raw/master/GUI.lua",["advancedLua.lua"]="https://github.com/IgorTimofeev/AdvancedLua/raw/master/AdvancedLua.lua",["color.lua"]="https://github.com/IgorTimofeev/Color/raw/master/Color.lua",["doubleBuffering.lua"]="https://github.com/IgorTimofeev/DoubleBuffering/raw/master/DoubleBuffering.lua",["image.lua"]="https://github.com/IgorTimofeev/Image/raw/master/Image.lua",["OCIF.lua"]="https://github.com/IgorTimofeev/Image/raw/master/OCIF.lua"}

if not compat.isMine then --Should, if OpenOS, install all dependencies.
    local status, _ = pcall(require,"GUI")
    if not status then
        for key,value in pairs(openOSReq) do
            os.execute("wget -f " .. value .. " /lib/" .. key)
        end
        os.execute("mkdir /lib/FileFormat")
        print("Installing OCIF in FormatModules folder")
        compat.internet.download("https://github.com/IgorTimofeev/Image/raw/master/OCIF.lua","/lib/FormatModules/OCIF.lua")
    end
end

local GUI = require("GUI")
local JSON = require("JSON")

local arg = ...

local function split(s, delimiter)
    local result = {};
    for match in (s..delimiter):gmatch("(.-)"..delimiter) do
      table.insert(result, match);
    end
    return result;
  end

local function installer(version)
    if compat.isMine then
        --TODO: Debug if OpenOS version works, then create MineOS one
        --compat.system.addWindow(0xE1E1E1)
    else
        term.clear()
        local install = false
        local isConfig = config == nil
        if config == nil then
            config = {["version"] = -1,["checkVersion"]=true,["lang"]="English"}
            compat.saveTable(config,"bootconfig.txt")
            print("New system: Installing servertine")
            install = true
        else
            print("New version for the Servertine Database is available!")
            print(config.version .. " -> " .. version)
            print("Would you like to install this version? yes or no\nSome modules may require the new version")
            local text = term.read():sub(1,-2)
            while text ~= "yes" and text ~= "no" do
                print("Invalid input")
                text = term.read():sub(1,-2)
            end
            if text == "yes" then
                install = true
            else
                print("Do you want the system to remember your decision?")
                local text = term.read():sub(1,-2)
                while text ~= "yes" and text ~= "no" do
                    print("Invalid input")
                    text = term.read():sub(1,-2)
                end
                if text == "yes" then
                    config.checkVersion = false
                    compat.saveTable(config,"bootconfig.txt")
                end
            end
        end
        if install then
            local worked, errored = compat.internet.request(download .. "files",nil,{["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.119 Safari/537.36"})
            if worked then
                local tempTable = JSON.decode(worked) --TODO: Make sure this matches json sent by the server
                local aRD = compat.fs.path(compat.system.getCurrentScript())

                local folders = split(tempTable.folders,",") --prep folders?
                for _,value in folders do
                    if compat.fs.isDirectory(aRD .. value) then
                        compat.fs.remove(aRD .. value)
                    end
                    compat.fs.makeDirectory(aRD .. value)
                end

                for _, value in pairs(tempTable.files) do
                    if value.type == "db" then
                        print("Installing to " .. value.path .. " file from URL: " .. value.url)
                        compat.internet.download(value.url,aRD .. value.path)
                    end
                end
                config.version = tempTable.version
                compat.saveTable(config,"bootconfig.txt")
            else
                error("Failed to download files. Server may be down")
            end
            --perform install
            return true
        elseif not isConfig then
            return true
        else
            return false
        end
    end
end

local function erHandle(er)
    error("Something went wrong:\n" .. er .. "\nError reporting will be available in the future")
end


if config == nil then
    installer()
end
compat.lang = config.lang
local result, reason = loadfile(compat.fs.path(compat.system.getCurrentScript()) .. "/Database.lua")
if result then
    if config.checkVersion then
        local worked, errored = compat.internet.request(download .. "version",nil,{["User-Agent"] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/64.0.3282.119 Safari/537.36"})
        if worked then
            local tempTable = JSON.decode(worked)
            if tempTable.success == true and tempTable.version ~= config.version then
                local goodToRun = installer(tempTable.version)
                if goodToRun then
                    local success, result = xpcall(result,erHandle)
                end
            end
        else
            GUI.alert("Error getting version from website")
            local success, result = xpcall(result,erHandle)
        end
    else
        local success, result = xpcall(result,erHandle)
    end
else
    local goodToRun = installer()
    if goodToRun then
        result, reason = loadfile(compat.fs.path(compat.system.getCurrentScript()) .. "/Database.lua")
        if result then
            local success, result = xpcall(result,erHandle)
        else
            error("Failed to run installed program. It'sa makea no sensea")
        end
    end
end