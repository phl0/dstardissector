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

    if buffer:len() == 9 then
       local xlx_keepalive = buffer(0, 8)
       dstar_tree:add(xlx_keepalive, "XLX keepalive from: " .. string.fromhex(tostring(xlx_keepalive)))
    end

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
          local dstar_flag1 = buffer(15, 1)
          local flag1_tree = dstar_tree:add(dstar_flag1, "Flag 1: 0x" .. tostring(dstar_flag1))
          if dstar_flag1:bitfield(0,1) == 0 then
             flag1_tree:add(dstar_flag1, string.format('%u... .... = Ignored: Not set', dstar_flag1:bitfield(0,1)))
          else
             flag1_tree:add(dstar_flag1, string.format('%u... .... = Ignored: Set', dstar_flag1:bitfield(0,1)))
          end
          if dstar_flag1:bitfield(1,1) == 0 then
             flag1_tree:add(dstar_flag1, string.format('.%u.. .... = Voice communication', dstar_flag1:bitfield(1,1)))
          else
             flag1_tree:add(dstar_flag1, string.format('.%u.. .... = Data communication', dstar_flag1:bitfield(1,1)))
          end
          if dstar_flag1:bitfield(2,1) == 0 then
             flag1_tree:add(dstar_flag1, string.format('..%u. .... = Communication between terminals', dstar_flag1:bitfield(2,1)))
          else
             flag1_tree:add(dstar_flag1, string.format('..%u. .... = Communication through repeater', dstar_flag1:bitfield(2,1)))
          end
          if dstar_flag1:bitfield(3,1) == 0 then
             flag1_tree:add(dstar_flag1, string.format('...%u .... = Communication interruption: Not set', dstar_flag1:bitfield(3,1)))
          else
             flag1_tree:add(dstar_flag1, string.format('...%u .... = Communication interruption: Set', dstar_flag1:bitfield(3,1)))
          end
          if dstar_flag1:bitfield(4,1) == 0 then
             flag1_tree:add(dstar_flag1, string.format('.... %u... = Urgent priority signal: Not set', dstar_flag1:bitfield(4,1)))
          else
             flag1_tree:add(dstar_flag1, string.format('.... %u... = Urgent priority signal: Set', dstar_flag1:bitfield(4,1)))
          end
          if dstar_flag1:bitfield(5,3) == 0 then
             flag1_tree:add(dstar_flag1, string.format('.... .%u%u%u = Control Flag: No information', dstar_flag1:bitfield(5,1), dstar_flag1:bitfield(6,1), dstar_flag1:bitfield(7,1)))
          elseif dstar_flag1:bitfield(5,3) == 1 then
             flag1_tree:add(dstar_flag1, string.format('.... .%u%u%u = Control Flag: Relay unavailable', dstar_flag1:bitfield(5,1), dstar_flag1:bitfield(6,1), dstar_flag1:bitfield(7,1)))
          elseif dstar_flag1:bitfield(5,3) == 2 then
             flag1_tree:add(dstar_flag1, string.format('.... .%u%u%u = Control Flag: No reply', dstar_flag1:bitfield(5,1), dstar_flag1:bitfield(6,1), dstar_flag1:bitfield(7,1)))
          elseif dstar_flag1:bitfield(5,3) == 3 then
             flag1_tree:add(dstar_flag1, string.format('.... .%u%u%u = Control Flag: ACK', dstar_flag1:bitfield(5,1), dstar_flag1:bitfield(6,1), dstar_flag1:bitfield(7,1)))
          elseif dstar_flag1:bitfield(5,3) == 4 then
             flag1_tree:add(dstar_flag1, string.format('.... .%u%u%u = Control Flag: Resend', dstar_flag1:bitfield(5,1), dstar_flag1:bitfield(6,1), dstar_flag1:bitfield(7,1)))
          elseif dstar_flag1:bitfield(5,3) == 5 then
             flag1_tree:add(dstar_flag1, string.format('.... .%u%u%u = Control Flag: Unused', dstar_flag1:bitfield(5,1), dstar_flag1:bitfield(6,1), dstar_flag1:bitfield(7,1)))
          elseif dstar_flag1:bitfield(5,3) == 6 then
             flag1_tree:add(dstar_flag1, string.format('.... .%u%u%u = Control Flag: Auto reply', dstar_flag1:bitfield(5,1), dstar_flag1:bitfield(6,1), dstar_flag1:bitfield(7,1)))
          elseif dstar_flag1:bitfield(5,3) == 7 then
             flag1_tree:add(dstar_flag1, string.format('.... .%u%u%u = Control Flag: Repeater station control', dstar_flag1:bitfield(5,1), dstar_flag1:bitfield(6,1), dstar_flag1:bitfield(7,1)))
          end

          local dstar_flag2 = buffer(16, 1)
          dstar_tree:add(dstar_flag2, "Flag 2: 0x" .. tostring(dstar_flag2))

          local dstar_flag3 = buffer(17, 1)
          dstar_tree:add(dstar_flag3, "Flag 3: 0x" .. tostring(dstar_flag3))

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
          local first_byte = bit.bxor(buffer(24,1):uint(), 0x70)
          local second_byte = bit.bxor(buffer(25,1):uint(), 0x4f)
          local third_byte = bit.bxor(buffer(26,1):uint(), 0x93)
          local slow_data_tree = dstar_tree:add(dstar_slow_data, "Slow data: 0x" .. tostring(dstar_slow_data) .. " scrambled / 0x" .. string.format("%02x%02x%02x", first_byte, second_byte, third_byte) .. " descrambled")
          if first_byte >= 0x31 and first_byte <= 0x35 then
             slow_data_tree:add(dstar_slow_data, "Type: GPS information")
             slow_data_tree:add(dstar_slow_data, "Length: " .. string.format("%u", first_byte-0x30) .. " octets")
             slow_data_tree:add(dstar_slow_data, "Text: " .. string.format("%c%c", second_byte, third_byte))
          elseif first_byte >= 0x40 and first_byte <= 0x43 then
             slow_data_tree:add(dstar_slow_data, "Type: Text message")
             slow_data_tree:add(dstar_slow_data, "Sequence No: " .. string.format("%u", first_byte-0x40))
             slow_data_tree:add(dstar_slow_data, "Text: " .. string.format("%c%c", second_byte, third_byte))
          elseif first_byte == 0xc2 then
             slow_data_tree:add(dstar_slow_data, "Type: Code Squelch Data")
             slow_data_tree:add(dstar_slow_data, "ID: " .. string.format("%c", second_byte))
          else
             slow_data_tree:add(dstar_slow_data, "Text: " .. string.format("%c%c%c", first_byte, second_byte, third_byte))
          end

       end


    end

end
-- load the udp.port table
udp_table = DissectorTable.get("udp.port")
-- register our protocol to handle udp port 10002
for i,port in ipairs{10002, 20001, 30001} do
    udp_table:add(port, dstar_proto)
end
