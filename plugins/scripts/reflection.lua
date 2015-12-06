local DEVIATION_LIMIT_DNS = 1
local DEVIATION_LIMIT_TCP = 1


-- Main function
function main()
    -- Get statistics from framework, indexed by node
    local stats = get_statistics()
    
    local results = {}

    for i = 1, #stats do

        local unrequested = {
            ['dns'] = 0,
            ['tcp'] = 0
        }

        for io, packets in pairs(stats[i]['packets']['in']) do
                
                -- DNS
                if packets['values']['dns.flags.response'] == '1' and packets['values']['dns.response_to'] == nil then
                    unrequested['dns'] = unrequested['dns'] + 1
                end

                -- TCP
                if packets['values']['tcp.connection.sack'] ~= nil and packets['values']['tcp.analysis.acks_frame'] == nil then
                    unrequested['tcp'] = unrequested['tcp'] + 1
                end
            
        end

        results[i] = unrequested
    end

    for i = 1, #results do

        if results[i]['dns'] > 0 then
            add_analysis_result(i, "Unrequested DNS Responses", results[i]['dns'], "Detection of DoS Reflection-Amplification Attack using DNS.", results[i]['dns'] > DEVIATION_LIMIT_DNS)
        end

        if results[i]['tcp'] > 0 then
            add_analysis_result(i, "Unrequested TCP SYN_ACKs", results[i]['tcp'], "Detection of DoS Reflection-Amplification Attack using TCP.", results[i]['tcp'] > DEVIATION_LIMIT_TCP)
        end
    end
end

fields = {
    'dns.flags.response',
    'dns.response_to',
    'tcp.connection.sack',
    'tcp.analysis.acks_frame'
}

register_script("DoS Reflection-Amplification Detection", main, fields)