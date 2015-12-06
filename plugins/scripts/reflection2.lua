local NORMAL_RATIO_DNS = 1
local NORMAL_RATIO_NTP = 1
local NORMAL_RATIO_TCP = 1

local DEVIATION_LIMIT_DNS = 0.1
local DEVIATION_LIMIT_NTP = 0.1
local DEVIATION_LIMIT_TCP = 0.1

-- Main function
function main()
    -- Get statistics from framework, indexed by node
    local stats = get_statistics()
    
    local results = {}

    for i = 1, #stats do
        dns = 0
        -- ntp = {['req'] = 0, ['res'] = 0}
        tcp = 0

        for io, packets in pairs(stats[i]['packets']) do
            for j = 1, #packets do
                
                -- DNS
                if packets[j]['values']['dns.reponse_to'] ~= nil then
                    dns['res'] = dns['res'] + 1
                elseif packets[j]['values']['dns.reponse_in'] ~= nil then
                    dns['req'] = dns['req'] + 1
                end

                -- NTP
                if tonumber(packets[j]['values']['ntp.flags.mode']) == 2 then
                    ntp['res'] = ntp['res'] + 1
                elseif tonumber(packets[j]['values']['ntp.flags.mode']) == 1 then
                    ntp['req'] = ntp['req'] + 1
                end

                -- TCP
                if packets[j]['values']['tcp.connection.sack'] ~= nil then
                    tcp['synack'] = tcp['synack'] + 1
                elseif packets[j]['values']['tcp.connection.syn'] ~= nil then
                    tcp['syn'] = tcp['syn'] + 1
                end
            end
        end

        results[i] = {['dns'] = dns, ['ntp'] = ntp, ['tcp'] = tcp}
    end

    for i = 1, #results do
        local count_dns_req = tonumber(results[i]['dns']['req'])
        local count_dns_res = tonumber(results[i]['dns']['res'])

        local count_ntp_req = tonumber(results[i]['ntp']['req'])
        local count_ntp_res = tonumber(results[i]['ntp']['res'])

        local count_tcp_ack = tonumber(results[i]['tcp']['syn'])
        local count_tcp_sack = tonumber(results[i]['tcp']['synack'])

        local ratio_dns = round(count_dns_req / count_dns_res, 2)
        local ratio_ntp = round(count_ntp_req / count_ntp_res, 2)
        local ratio_tcp = round(count_tcp_ack / count_tcp_sack, 2)

        if count_dns_res > count_dns_req then
            add_analysis_result(i, "DNS Request/Response Ratio", count_dns_req .. "/" .. count_dns_res, "Detection of DoS Reflection-Amplification Attack using DNS", math.abs(NORMAL_RATIO_DNS - ratio_dns) < DEVIATION_LIMIT_DNS)
        end

        if count_ntp_res > count_ntp_req then
            add_analysis_result(i, "NTP Request/Response Ratio", count_ntp_req .. "/" .. count_ntp_res, "Detection of DoS Reflection-Amplification Attack using NTP", math.abs(NORMAL_RATIO_NTP - ratio_ntp) < DEVIATION_LIMIT_NTP)
        end

        if count_tcp_sack > count_tcp_ack then
            add_analysis_result(i, "TCP SYN/SYNACK Ratio", count_tcp_ack .. "/" .. count_tcp_sack, "Detection of DoS Reflection-Amplification Attack using TCP", math.abs(NORMAL_RATIO_TCP - ratio_tcp) < DEVIATION_LIMIT_TCP)
        end
    end
end

fields = {
    'dns.response_in',
    'dns.response_to',
    'ntp.flags.mode',
    'tcp.connection.syn',
    'tcp.connection.sack'
}

--register_script("DoS Reflection-Amplification", main, fields)