-- Wireshark dissector for Zephyr
-- Place in ~/.local/lib/wireshark/plugins/2.6/

zephyr_protocol = Proto("Zephyr",  "Zephyr IM Protocol")

local kind_names = {
   [0] = "UNSAFE",
   [1] = "UNACKED",
   [2] = "ACKED",
   [3] = "HMACK",
   [4] = "HMCTL",
   [5] = "SERVACK",
   [6] = "SERVNAK",
   [7] = "CLIENTACK",
   [8] = "STAT"
}
zephyr_protocol.fields.version = ProtoField.stringz("zephyr.version", "Version")
zephyr_protocol.fields.numfields = ProtoField.uint32("zephyr.fields", "Field Count")
zephyr_protocol.fields.z_kind = ProtoField.uint32("zephyr.z_kind", "Kind", base.DEC, kind_names)
zephyr_protocol.fields.z_uid = ProtoField.stringz("zephyr.z_uid", "UID")
zephyr_protocol.fields.z_uid_addr = ProtoField.ipv4("zephyr.z_uid.zuid_addr", "Address")
zephyr_protocol.fields.z_uid_tv = ProtoField.absolute_time("zephyr.z_uid.tv", "Time")
zephyr_protocol.fields.z_port = ProtoField.uint16("zephyr.z_port", "Port")
zephyr_protocol.fields.z_auth = ProtoField.uint32("zephyr.z_auth", "Auth")
zephyr_protocol.fields.z_authent_len = ProtoField.uint32("zephyr.z_authent_len", "Authenticator Length")
zephyr_protocol.fields.z_ascii_authent = ProtoField.stringz("zephyr.z_ascii_authent", "Authenticator")
zephyr_protocol.fields.z_class = ProtoField.stringz("zephyr.z_class", "Class")
zephyr_protocol.fields.z_class_inst = ProtoField.stringz("zephyr.z_class_inst", "Instance")
zephyr_protocol.fields.z_opcode = ProtoField.stringz("zephyr.z_opcode", "Opcode")
zephyr_protocol.fields.z_sender = ProtoField.stringz("zephyr.z_sender", "Sender")
zephyr_protocol.fields.z_recipient = ProtoField.stringz("zephyr.z_recipient", "Recipient")
zephyr_protocol.fields.z_default_format = ProtoField.stringz("zephyr.z_default_format", "Default Format")
zephyr_protocol.fields.z_ascii_checksum = ProtoField.stringz("zephyr.z_ascii_checksum", "ASCII Checksum")
zephyr_protocol.fields.z_checksum = ProtoField.uint32("zephyr.z_checksum", "Checksum")
zephyr_protocol.fields.z_multinotice = ProtoField.stringz("zephyr.z_multinotice", "Multinotice")
zephyr_protocol.fields.z_multiuid = ProtoField.stringz("zephyr.z_multiuid", "MultiUID")
zephyr_protocol.fields.z_multiuid_addr = ProtoField.ipv4("zephyr.z_multiuid.zuid_addr", "Address")
zephyr_protocol.fields.z_multiuid_tv = ProtoField.absolute_time("zephyr.z_multiuid.tv", "Time")
zephyr_protocol.fields.z_sender_sockaddr = ProtoField.ipv4("zephyr.z_sender_sockaddr", "Sender sockaddr")
zephyr_protocol.fields.z_charset = ProtoField.uint16("zephyr.z_charset", "Character Set")
zephyr_protocol.fields.z_message = ProtoField.string("zephyr.z_message", "Message")
zephyr_protocol.fields.z_message_len = ProtoField.uint32("zephyr.z_message_len", "Message Length")

function parse_ascii(range)
   local v = range(2):string()
   return tonumber(string.match(v, "[0-9A-F]+"), 16)
end

function parse_ascii_ip(range)
   local ip = "" .. tonumber(range(2, 2):string(), 16) .. "." .. tonumber(range(4, 2):string(), 16) .. "." .. tonumber(range(6, 2):string(), 16) .. "." .. tonumber(range(8, 2):string(), 16)
   return Address.ip(ip)
end

function parse_zcode_ip(range)
   local bytes = {}
   local str = range(1,range:len()-2):bytes()
   local i = 0
   while i < str:len() do
      local byte = str:get_index(i)
      info(i .. ": " .. byte)
      if (byte == 0xFF) then
	 if (str:get_index(i+1) == 0xF0) then
	    table.insert(bytes, 0)
	 elseif (str:get_index(i+1) == 0xF1) then
	    table.insert(bytes, 0xFF)
	 end
	 i = i + 2
      else
	 table.insert(bytes, byte)
	 i = i + 1
      end
   end
   info(bytes[1])
   info(table.concat(bytes, "."))
   return Address.ip(table.concat(bytes, "."))
end

function parse_ascii_tv(range)
   info(range:string())
   local seconds = parse_ascii(range)
   local microseconds = parse_ascii(range(11))
   return NSTime.new(seconds, microseconds*1000)
end

function zephyr_protocol.dissector(buffer, pinfo, tree)
  length = buffer:len()
  if length == 0 then return end

  pinfo.cols.protocol = zephyr_protocol.name

  local subtree = tree:add(zephyr_protocol, buffer(), "Zephyr")

  local range = buffer()
  local length = range:strsize()
  local v = range:stringz()
  subtree:add(zephyr_protocol.fields.version, range)
  
  if v == "ZEPH0.2" then
     range = buffer(range:offset()+range:len())
     range = range(0, range:strsize())
     local numfields = parse_ascii(range)
     subtree:add(zephyr_protocol.fields.numfields, range, numfields)
     numfields = numfields - 2

     range = buffer(range:offset()+range:len())
     range = range(0, range:strsize())
     local kind = parse_ascii(range)
     subtree:add(zephyr_protocol.fields.z_kind, range, kind)
     numfields = numfields - 1

     range = buffer(range:offset()+range:len())
     range = range(0, range:strsize())
     local z_uid = subtree:add(zephyr_protocol.fields.z_uid, range)

     local addr = parse_ascii_ip(range)
     local tv = parse_ascii_tv(range(11))
     z_uid:add(zephyr_protocol.fields.z_uid_addr, range(0, 11), addr)
     z_uid:add(zephyr_protocol.fields.z_uid_tv, range(11), tv)
     z_uid:set_text("UID: " .. tostring(addr) .. " " .. tostring(tv))
     
     numfields = numfields - 1

     range = buffer(range:offset()+range:len())
     range = range(0, range:strsize())
     subtree:add(zephyr_protocol.fields.z_port, range, parse_ascii(range))
     numfields = numfields - 1

     range = buffer(range:offset()+range:len())
     range = range(0, range:strsize())
     subtree:add(zephyr_protocol.fields.z_auth, range, parse_ascii(range))
     numfields = numfields - 1

     range = buffer(range:offset()+range:len())
     range = range(0, range:strsize())
     local authent_length = parse_ascii(range)
     subtree:add(zephyr_protocol.fields.z_authent_len, range, authent_length)
     numfields = numfields - 1

     function add(field)
	range = buffer(range:offset()+range:len())
	subtree:add(field, range)
	numfields = numfields - 1
     end

     add(zephyr_protocol.fields.z_ascii_authent)
     add(zephyr_protocol.fields.z_class)
     local class = range:stringz()
     add(zephyr_protocol.fields.z_class_inst)
     local instance = range:stringz()
     add(zephyr_protocol.fields.z_opcode)
     local opcode = range:stringz()
     add(zephyr_protocol.fields.z_sender)
     add(zephyr_protocol.fields.z_recipient)
     add(zephyr_protocol.fields.z_default_format)

     if (numfields > 0) then
	range = buffer(range:offset()+range:len())
	range = range(0, range:strsize())
	subtree:add(zephyr_protocol.fields.z_ascii_checksum, range)
	local status, value = pcall(function() return parse_ascii(range) end)
	if status then
	   subtree:add(zephyr_protocol.fields.z_checksum, range, value)
	end
	numfields = numfields - 1
	-- TODO: validate checksum and flag if wrong
     end

     if (numfields > 0) then
	range = buffer(range:offset()+range:len())
	subtree:add(zephyr_protocol.fields.z_multinotice, range)
	numfields = numfields - 1
     end

     if (numfields > 0) then
	range = buffer(range:offset()+range:len())
	range = range(0, range:strsize())
	local z_multiuid = subtree:add(zephyr_protocol.fields.z_multiuid, range)

	local addr = parse_ascii_ip(range)
	local tv = parse_ascii_tv(range(11))
	z_multiuid:add(zephyr_protocol.fields.z_multiuid_addr, range(0, 11), addr)
	z_multiuid:add(zephyr_protocol.fields.z_multiuid_tv, range(11), tv)
	z_multiuid:set_text("MultiUID: " .. tostring(addr) .. " " .. tostring(tv))
	numfields = numfields - 1
	-- else z_multiuid = z_uid
     end

     if (numfields > 0) then
	range = buffer(range:offset()+range:len())
	range = range(0, range:strsize())
	if (range:string():byte(1) == 90) then
	   -- TODO: parse Zcode address for real
	   subtree:add(zephyr_protocol.fields.z_sender_sockaddr, range, parse_zcode_ip(range)):append_text(" (Zcode)")
	else
	   subtree:add(zephyr_protocol.fields.z_sender_sockaddr, range, parse_ascii_ip(range)):append_text(" (NetASCII)")
	end
	numfields = numfields - 1
     end

     if (numfields > 0) then
	range = buffer(range:offset()+range:len())
	range = range(0, range:strsize())
	subtree:add(zephyr_protocol.fields.z_charset, range, parse_ascii(range))
	numfields = numfields - 1
     end

     if (numfields > 0) then
	local otherfields = subtree:add("Other Fields")
	for i = 1,numfields do
	   range = buffer(range:offset()+range:len())
	   range = range(0, range:strsize())
	   otherfields:add(range)
	   numfields = numfields - 1
	end
     end

     range = buffer(range:offset()+range:len())
     if (range:len() > 0) then
	subtree:add(zephyr_protocol.fields.z_message_len, range:len())
	subtree:add(zephyr_protocol.fields.z_message, range)
     end
     local info = kind_names[kind] .. " " .. class .. " " .. instance .. " " .. opcode
     pinfo.columns.info = info
     subtree.text = "Zephyr, " .. info
  end
end



local udp_port = DissectorTable.get("udp.port")
udp_port:add(2102, zephyr_protocol)
udp_port:add(2103, zephyr_protocol)
udp_port:add(2104, zephyr_protocol)
