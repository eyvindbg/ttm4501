
-- Fields
tcpsyn = Field.new('tcp.flags.syn')
tcpack = Field.new('tcp.flags.ack')
tcpws = Field.new('tcp.window_size')

-- Function to be called from main window
function main()

    local filter = "http"

    local tap = Listener.new()

    local prev_syn = {nil, 0, nil}
    local bursts = {}
    
    function count_syn(dst, rel_ts)
        local syn = nil
        local ack = nil
        local ws = nil

        if tcpsyn() then syn = tostring(tcpsyn()) end

        if tcpack() then ack = tostring(tcpack()) end

        if tcpws() then ws = tcpws().value end

        if syn == '1' and ack ~= '1'  then
            local delta = rel_ts - prev_syn[2]

            if #bursts == 0 then
                bursts[1] = {1, dst, "Yes"}
            elseif dst == prev_syn[1] and delta < 0.01 then
                bursts[#bursts][1] = bursts[#bursts][1] + 1
            else
                bursts[#bursts+1] = {1, dst, "Yes"}
                prev_syn = {nil, 0, nil}
            end

            -- Check if window size is equal for all packets in the burst
            if prev_syn[3] ~= nil and ws ~= prev_syn[3] then
                bursts[#bursts][3] = "No"
            end

            -- Set for next frame
            prev_syn[1] = dst
            prev_syn[2] = rel_ts
            prev_syn[3] = ws
        end
    end

    function print_result()
        local text = "Burst\tPackets\tTarget Address\tEq. Win. Size\n"
        for i = 1, #bursts do
            if bursts[i][1] > 1000 then
                text = text .. i .. "\t" .. bursts[i][1] .. "\t" .. bursts[i][2] .. "\t" .. bursts[i][3] .. "\n"
            end
        end
        do return text end
    end

    function tap.packet(pinfo, tvb, tapdata)
        count_syn(tostring(pinfo.dst), pinfo.rel_ts)
    end


    function tap.draw()
    end

    function tap.reset(userdata)
    end

    function remove_tap() 
        if tap and tap.remove then 
            tap:remove()   
        end 
    end

    retap_packets()

    do return {print_result(), filter} end
end

--register_tap("TCP SYN Flood Detection", main)