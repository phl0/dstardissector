local dstar_frame_types = {
   [0x10] = "Configuration Frame",
   [0x20] = "Voice Frame"
};

local dstar_stream_types = {
   [0x20] = "Voice Stream"
};

--- Declare the protocol
dstar_proto = Proto("D-Star","D-Star Protocol")

local dstar_proto_fields = dstar_proto.fields
dstar_proto_fields.frame_type = ProtoField.uint16("dstar_proto_fields.frame_type", "Frame Type", base.HEX)
dstar_proto_fields.stream_type = ProtoField.uint16("dstar_proto_fields.stream_type", "Stream Type", base.HEX)

-- Convert hex to ascii
function string.fromhex(str)
  return (str:gsub('..', function (cc)
    return string.char(tonumber(cc, 16))
  end))
end

-- create a function to dissect it
function dstar_proto.dissector(buffer,pinfo,tree)

    if buffer:len() < 9 then return end

    pinfo.cols.protocol = "D-Star"
    local dstar_tree = tree:add(dstar_proto,buffer(),"D-Star Protocol Data (", buffer:len(), "bytes)")

    local ascii = ""
    for index = 0, 3 do
       local c = buffer(index,1):uint()
       -- append printable characters
       if c >= 0x20 and c <= 0x7E then
          ascii = ascii .. string.format("%c", c)
       else
          -- use a dot for the others bytes
          ascii = ascii .. "."
       end
    end

    if ascii == "DSVT" then

       dstar_tree:add(buffer(0, 4),"D-Star Identifier: " .. ascii)

       local dstar_frame_type = buffer(4, 1)
       local frame_type = "unknown"
       if dstar_frame_types[dstar_frame_type:uint()] ~= nil then
          frame_type = dstar_frame_types[dstar_frame_type:uint()]
       end
       local frametype = dstar_tree:add(dstar_proto_fields.frame_type, dstar_frame_type)
       frametype:set_text("Frame Type: " .. frame_type .. " (0x" .. dstar_frame_type .. ")")

       local some_dstar_flags = buffer(5, 3)

       local dstar_stream_type = buffer(8, 1)
       local stream_type = "unknown"
       if dstar_stream_types[dstar_stream_type:uint()] ~= nil then
          stream_type = dstar_stream_types[dstar_stream_type:uint()]
       end
       local streamtype = dstar_tree:add(dstar_proto_fields.stream_type, dstar_stream_type)
       streamtype:set_text("Stream Type: " .. stream_type .. " (0x" .. dstar_stream_type .. ")")

       local more_dstar_flags = buffer(9, 3)

       local dstar_stream_id = buffer(12, 2)
       dstar_tree:add(dstar_stream_id, "Stream ID: " .. dstar_stream_id:uint() .. " (0x" .. dstar_stream_id .. ")")

       local dstar_frame_counter = buffer(14, 1)
       dstar_tree:add(dstar_frame_counter, "Frame Counter: " .. dstar_frame_counter:uint() .. " (0x" .. dstar_frame_counter .. ")")

       if frame_type == "Configuration Frame" then
          local dstar_flags = buffer(15, 3)

          local dstar_destination_repeater = buffer(18, 8)
          local destination = tostring(dstar_destination_repeater)
          dstar_tree:add(dstar_destination_repeater, "Destination Repeater: " .. string.fromhex(destination))

          local dstar_source_repeater = buffer(26, 8)
          local source = tostring(dstar_source_repeater)
          dstar_tree:add(dstar_source_repeater, "Source Repeater: " .. string.fromhex(source))

          local dstar_your_call = buffer(34, 8)
          local urcall = tostring(dstar_your_call)
          dstar_tree:add(dstar_your_call, "Your Call: " .. string.fromhex(urcall))

          local dstar_my_call = buffer(42, 8)
          local mycall = tostring(dstar_my_call)
          local dstar_my_suffix = buffer(50, 4)
          local mysuffix = tostring(dstar_my_suffix)
          dstar_tree:add(buffer(42, 12), "My Call: " .. string.fromhex(mycall) .. "/" .. string.fromhex(mysuffix))

          local dstar_checksum = buffer(54, 2)
          dstar_tree:add(dstar_checksum, "Checksum: 0x" .. dstar_checksum)

       elseif frame_type == "Voice Frame" then
          local dstar_ambe_data = buffer(15, 9)
          local ambe_data = tostring(dstar_ambe_data)
          dstar_tree:add(dstar_ambe_data, "AMBE Data: " .. ambe_data)

          local dstar_slow_data = buffer(24,3)
          local slow_data = tostring(dstar_slow_data)
          dstar_tree:add(dstar_slow_data, "Slow Data: " .. slow_data)

       end


    end

end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 10002
udp_table:add(10002,dstar_proto)
