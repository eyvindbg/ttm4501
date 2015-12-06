local MIN_RATE = 50
local MIN_SIZE = 50
local MAX_DUR = 15

local EQUAL_SEGMENT_SIZE_LIMIT = 90
local SMALL_SEGMENT_SIZE_LIMIT = 90

local BURST_DELTA = 1
local BURST_SIZE = 200

function main()
    -- Get statistics from framework, indexed by node
    local stats = get_statistics()
    
    -- To be filled with analysis results
    local analysis = {}

    -- TOTAL CAPTURE TIME
    local caplen = 0

    -- FOR EVERY NODE
    for i = 1, #stats do

        -- ALL STREAMS FOR NODE i
        local streams = {}

        -- FOR EVERY INBOUND PACKET TO NODE i, GATHER STREAM DATA
        for i, packets in ipairs(stats[i]['packets']['in']) do
            -- AFTER THE LAST PACKET, THIS WILL EQUAL THE TOTAL CAPTURE TIME
            caplen = tonumber(packets['time'])
            
            if packets['values']['tcp.stream'] ~= nil then

                local stream = tonumber(packets['values']['tcp.stream'])
                local size = tonumber(packets['values']['tcp.len'])
                local time = tonumber(packets['time'])

                local syn = packets['values']['tcp.connection.syn']
                local fin = packets['values']['tcp.connection.fin']

                -- INITIALIZE STREAM
                if streams[stream] == nil then
                    streams[stream] = {['start'] = 0, ['end'] = 0, ['dur'] = 0, ['pcount'] = 0, ['bytes'] = 0, ['sizes'] = {}, ['small'] = 0}
                end

                -- FIND STREAM START AND END
                if syn ~= nil then
                    streams[stream]['start'] = time
                elseif fin ~= nil then
                    streams[stream]['end'] = time
                    streams[stream]['dur'] = streams[stream]['end'] - streams[stream]['start']
                end

                -- COUNT PACKETS (WITH PAYLOAD) IN STREAM
                if size > 0 then
                    streams[stream]['pcount'] = streams[stream]['pcount'] + 1
                end

                -- COUNT TOTAL BYTES IN STREAM
                streams[stream]['bytes'] = streams[stream]['bytes'] + size

                -- TRACK SEGMENT SIZES
                if not table_contains(streams[stream]['sizes'], size) then
                    table.insert(streams[stream]['sizes'], size)
                end

                -- COUNT SMALL PACKETS
                if size < MIN_SIZE then
                    streams[stream]['small'] = streams[stream]['small'] + 1
                end
            end
        end

        -- SORT STREAMS

        sorted = {}

        for n, data in pairs(streams) do
            table.insert(sorted, n)
        end

        table.sort(sorted)

        for i = 1, #sorted do
            sorted[i] = streams[sorted[i]]
        end

        analysis[i] = sorted

    end

    function incr_burst(current_burst, data)
        local burst = copy(current_burst)

        burst['streams'] = burst['streams'] + 1

        -- COUNT STREAMS WITH ONLY ONE PACKET --> Slow headers attack
        if data['pcount'] == 1 then burst['one_packet'] = burst['one_packet'] + 1 end
    
        -- DETECTING EQUAL PACKET SIZES ACCORDING TO STATIC VARIABLE: EQUAL_SEGMENT_SIZE_LIMIT
        if round((data['pcount'] - #data['sizes']) / data['pcount'] * 100, 2) > EQUAL_SEGMENT_SIZE_LIMIT then burst['equal_sizes'] = burst['equal_sizes'] + 1 end

        -- DETECTING LONG CONNECTION DURATION
        if data['dur'] > MAX_DUR then burst['long_dur'] = burst['long_dur'] + 1 end

        -- DETECTING SMALL PACKET SIZES
        if round((data['pcount'] - data['small']) / data['pcount'] * 100, 2) > SMALL_SEGMENT_SIZE_LIMIT then burst['small_sizes'] = burst['small_sizes'] + 1 end

        return burst
    end

    -- FOR EVERY NODE, AGGREGATE RESULTS AND DETECT BURSTS
    for i = 1, #analysis do
        local new_burst = {['streams'] = 1, ['equal_sizes'] = 0, ['small_sizes'] = 0, ['one_packet'] = 0, ['long_dur'] = 0}

        local bursts = {}
        local prev_stream_start = 0

        for snum, data in ipairs(analysis[i]) do
            --if data['start'] == 0 then
            --    data['dur'] = data['end']
            if data['end'] == 0 then
                data['dur'] = caplen - data['start']
            end

            -- STREAMS WITHOUT START _AND_ END ARE NOT CONSIDERED
            if data['start'] ~= 0 and data['dur'] ~= 0 then
                local avg_bps = round(data['bytes'] / data['dur'], 2)
                
                -- ASSUMING LOW PACKET RATE IS A PREREQUISITE ATTACK SIGNATURE
                if avg_bps < MIN_RATE then

                    -- FIRST STREAM, NEW BURST
                    if #bursts == 0 then
                        bursts[1] = incr_burst(new_burst, data)
                    
                    -- CURRENT BURST
                    elseif data['start'] < prev_stream_start + BURST_DELTA then
                        bursts[#bursts] = incr_burst(bursts[#bursts], data)

                    -- NEW BURST
                    else
                        bursts[#bursts+1] = incr_burst(new_burst, data)
                        prev_stream_start = 0
                    end

                    prev_stream_start = data['start']
                end
            end
        end

        -- ADD RELEVANT BURSTS TO ANALYSIS RESUTLS
        local aggr = ""
        local normal = true

        for j = 1, #bursts do
            if bursts[j]['streams'] > BURST_SIZE then
                normal = false

                aggr = aggr .. "Burst: " .. bursts[j]['streams'] .. " slow TCP connections."
                aggr = aggr .. "<ul>"
                if bursts[j]['long_dur'] > 0 then aggr = aggr .. "<li>Long duration: " .. bursts[j]['long_dur'] .. "</li>" end
                if bursts[j]['one_packet'] > 0 then aggr = aggr .. "<li>Only one packet: " .. bursts[j]['one_packet'] .. "</li>" end
                if bursts[j]['equal_sizes'] > 0 then aggr = aggr .. "<li>Equal packet sizes: " .. bursts[j]['equal_sizes'] .. "</li>" end
                if bursts[j]['small_sizes'] > 0 then aggr = aggr .. "<li>Small packet sizes: " .. bursts[j]['small_sizes'] .. "</li>" end
                aggr = aggr .. "</ul>"
            end
        end
        
        if not normal then
            add_analysis_result(i, "Slow TCP Connections", aggr, "Detection of Slow HTTP Request DoS Attack.", false)
        end

    end
end

fields = {
    'tcp.stream',
    'tcp.connection.syn',
    'tcp.connection.fin',
    'tcp.len'
}

register_script("DoS Detection/Slow HTTP Headers", main, fields)