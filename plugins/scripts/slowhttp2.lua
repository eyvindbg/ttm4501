
function main()

    local MIN_RATE = 50
    local MIN_SIZE = 50
    local MAX_DUR = 15

    -- Get statistics from framework, indexed by node
    local stats = get_statistics()
    
    -- To be filled with analysis results
    local analysis = {}

    -- TOTAL CAPTURE TIME
    local caplen = 0

    for i = 1, #stats do

        -- ALL STREAMS FOR NODE i
        local streams = {}

        for io, packets in pairs(stats[i]['packets']) do
            for j = 1, #packets do

                -- AFTER THE LAST PACKET, THIS WILL EQUAL THE TOTAL CAPTURE TIME
                caplen = tonumber(packets[j]['time'])
                
                if packets[j]['values']['tcp.stream'] ~= nil then

                    local stream = packets[j]['values']['tcp.stream']

                    if streams[stream] == nil then
                        streams[stream] = {['start'] = 0, ['end'] = 0, ['dur'] = 0, ['packets'] = 0, ['bytes'] = 0, ['sizes'] = {}}
                    end

                    -- FIND STREAM START AND END
                    if packets[j]['values']['tcp.connection.syn'] ~= nil then
                        streams[stream]['start'] = tonumber(packets[j]['time'])
                    elseif packets[j]['values']['tcp.connection.fin'] ~= nil then
                        streams[stream]['end'] = tonumber(packets[j]['time'])
                        streams[stream]['dur'] = streams[stream]['end'] - streams[stream]['start']
                    end

                    -- COUNT PACKETS (WITH PAYLOAD) IN STREAM
                    if tonumber(packets[j]['values']['tcp.len']) > 0 then
                        streams[stream]['packets'] = streams[stream]['packets'] + 1
                    end

                    -- COUNT TOTAL BYTES IN STREAM
                    streams[stream]['bytes'] = streams[stream]['bytes'] + tonumber(packets[j]['values']['tcp.len'])

                    -- TRACK SEGMENT SIZES
                    if not table_contains(streams[stream]['sizes'], tonumber(packets[j]['values']['tcp.len'])) then
                        table.insert(streams[stream]['sizes'], tonumber(packets[j]['values']['tcp.len']))
                    end

                end
            end
        end

        analysis[i] = streams

    end

    local html = ""

    -- FOR EVERY NODE
    for i = 1, #analysis do

        local slow_streams = {}

        for snum, data in pairs(analysis[i]) do
            if data['start'] == 0 then
                data['dur'] = caplen
            elseif data['end'] == 0 then
                data['dur'] = caplen - data['start']
            end

            -- STREAMS WITHOUT START AND END ARE NOT CONSIDERED
            if data['dur'] ~= 0 then
                local avg_bps = round(data['bytes'] / data['dur'], 2)
                
                -- ASSUMING LOW PACKET RATE IS A FUNDAMENTAL ATTACK SIGNATURE
                if avg_bps < MIN_RATE then
                    slow_streams[snum] = {['small_sizes'] = false, ['equal_sizes'] = false, ['long_dur'] = false}
                
                    -- DETECTING EQUAL PACKET SIZES
                    if #data['sizes'] == 1 then slow_streams[snum]['equal_sizes'] = true end

                    -- DETECTING LONG CONNECTION DURATION
                    if data['dur'] > MAX_DUR then slow_streams[snum]['long_dur'] = true end

                    -- DETECTING SMALL PACKET SIZES
                    for j = 1, #data['sizes'] do if data['sizes'][j] < MIN_SIZE then slow_streams[snum]['small_sizes'] = true end end
                end
            end
        end

        -- THE HTML STRING TO BE RETURNED TO THE FRAMEWORK

        if #slow_streams > 0 then
            html = html .. #slow_streams .. " slow streams were found."
        end

    end
    
    return {html, ""}
end

fields = {
    'tcp.stream',
    'tcp.connection.syn',
    'tcp.connection.fin',
    'tcp.len'
}

--register_tap("Slow HTTP Headers", main, fields)