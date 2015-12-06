local MIN_DELTA = 0.1
local MIN_BURST_SIZE = 5000

function main()
    -- Get statistics from tap framework
    local stats = get_statistics()

    local analysis = {}

    local empty_burst = {['count'] = 1, ['ws'] = {}, ['ttl'] = {}}
    
    for i = 1, #stats do
        local prev_syn = 0
        local bursts = {}
        
        for i, packets in ipairs(stats[i]['packets']['in']) do
            -- CHECK IF PACKET IS A TCP SYN PACKET, ELSE DISCARD
            if packets['values']['tcp.connection.syn'] ~= nil then
                local time = packets['time']

                local ws = tonumber(packets['values']['tcp.window_size'])
                local ttl = tonumber(packets['values']['ip.ttl'])
                
                if #bursts == 0 then
                    bursts[1] = empty_burst
                elseif time - prev_syn < MIN_DELTA then
                    bursts[#bursts]['count'] = bursts[#bursts]['count'] + 1
                else
                    bursts[#bursts+1] = empty_burst
                    prev_syn = 0
                end

                -- Add window size and ttl
                if not table_contains(bursts[#bursts]['ws'], ws) then table.insert(bursts[#bursts]['ws'], ws) end
                if not table_contains(bursts[#bursts]['ttl'], ttl) then table.insert(bursts[#bursts]['ttl'], ttl) end

                -- Set for next packet
                prev_syn = time
            end
        end

        analysis[i] = bursts
    end

    -- AGGREGATE RESULTS, PER NODE
    for i = 1, #analysis do
        local aggr = ""

        for burst, data in pairs(analysis[i]) do
            if data['count'] > MIN_BURST_SIZE then
                local same_ws = (#data['ws'] == 1)
                local same_ttl = (#data['ttl'] == 1)

                aggr = aggr .. "Burst: " .. data['count'] .. " packets." 
                aggr = aggr .. "<ul>"
                aggr = aggr .. "<li>Same Window Size: " .. tostring(same_ws) .. "</li>"
                aggr = aggr .. "<li>Same Time-to-Live: " .. tostring(same_ttl) .. "</li>"
                aggr = aggr .. "</ul>"
            end
        end

        if aggr ~= "" then
            add_analysis_result(i, "TCP SYN Burst", aggr, "Detection of TCP SYN Flood DoS Attack.", false)
        end
    end
end


fields = {
    'tcp.connection.syn',
    'tcp.window_size',
    'ip.ttl'
}

register_script("TCP SYN Flood Detection", main, fields)