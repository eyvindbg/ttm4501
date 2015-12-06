
local nodes = {}

function get_statistics()
    calc_real_percent()
    return nodes
end

function add_analysis_result(node, name, result, description, normal)
    table.insert(nodes[node]['fields'], {['name'] = name, ['result'] = result, ['description'] = description, ['normal'] = normal})
end

function match_node(src, dst)
    for i = 1, #nodes do
        local ipv4 = nodes[i]['addr']['ipv4']
        local ipv6 = nodes[i]['addr']['ipv6']
        local mac = nodes[i]['addr']['mac']

        if src == ipv4 or src == ipv6 or src == mac then
            return {['num'] = i, ['io'] = 'out'}
        elseif dst == ipv4 or dst == ipv6 or dst == mac then
            return {['num'] = i, ['io'] = 'in'}
        end
    end
    return nil
end

function incr_node_proto(node, protocol, io)
    if io == "in" then nodes[node]['protocols'][protocol]['in']['count'] = nodes[node]['protocols'][protocol]['in']['count'] + 1     
    else nodes[node]['protocols'][protocol]['out']['count'] = nodes[node]['protocols'][protocol]['out']['count'] + 1
    end
end

function incr_node_other(node, io)
    if io == "in" then nodes[node]['protocols']['Other']['in']['count'] = nodes[node]['protocols']['Other']['in']['count'] + 1
    else nodes[node]['protocols']['Other']['out']['count'] = nodes[node]['protocols']['Other']['out']['count'] + 1
    end
end

function calc_real_percent()
    for i = 1, #nodes do
        local node_total_frames_in = #nodes[i]['packets']['in']

        for proto, stat in pairs(nodes[i]['protocols']) do
            stat['in']['real'] = round((stat['in']['count'] / node_total_frames_in) * 100, 2)
        end

        local node_total_frames_out = #nodes[i]['packets']['out']

        for proto, stat in pairs(nodes[i]['protocols']) do
            stat['out']['real'] = round((stat['out']['count'] / node_total_frames_out) * 100, 2)
        end
    end
end

function match_protocol(node, protocol)
    for proto, stat in pairs(nodes[node]['protocols']) do
        if proto == protocol then
            return true
        end
    end
    return false
end

function sort_protocols(node)
    local sorted = {}
    
    for k, v in pairs(nodes[node]['protocols']) do
        if k ~= "Other" then
            table.insert(sorted, k)
        end
    end 

    table.sort(sorted)
    table.insert(sorted, 'Other')

    do return sorted end
end

function add_node_packet(node, io, pnum, src, dst, protocol, time, values)
    table.insert(nodes[node]['packets'][io], {['pnum'] = pnum, ['src'] = src, ['dst'] = dst, ['protocol'] = protocol, ['time'] = time, ['values'] = values})
end

function count_node(node, protocol)
    local match = false
    
    -- Increment counter for matching protocol
    if match_protocol(node['num'], protocol) then
        incr_node_proto(node['num'], protocol, node['io'])
        match = true
    end

    -- If the frame does not match any of the input protocols, it is marked as "other"
    if not match then
        incr_node_other(node['num'], node['io'])
    end
end

function new_node(ipv4, ipv6, mac, type, proto)
    local protocols = {}

    for i = 1, #proto do
        local split = proto[i]:split('-')
        local protocol = split[1]
        local exp_in = split[2]
        local exp_out = split[3]

        protocols[protocol] = {
            ['in'] = {['count'] = 0, ['real'] = 0, ['exp'] = exp_in},
            ['out'] = {['count'] = 0, ['real'] = 0, ['exp'] = exp_out}
        }
    end

    protocols['Other'] = {
        ['in'] = {['count'] = 0, ['real'] = 0, ['exp'] = 0},
        ['out'] = {['count'] = 0, ['real'] = 0, ['exp'] = 0}
        }

    local node = {
        ['addr'] = {['ipv4'] = ipv4, ['ipv6'] = ipv6, ['mac'] = mac},
        ['type'] = type, 
        ['protocols'] = protocols,
        ['packets'] = {['in'] = {}, ['out'] = {}},
        ['fields'] = {}
    }
    
    table.insert(nodes, node)
end

-- Read nodes.conf file
function read_nodes(path)
    for line in io.lines(path) do
        if string.sub(line, 1, 1) ~= '#' and line ~= "" then
            local cols = line:split('\t')

            local iaddr = cols[1]:split(' ')
            local s_type = cols[2]:split(' ')
            local proto = cols[3]:split(' ')

            new_node(iaddr[1], iaddr[2], iaddr[3], s_type, proto)
        end
    end
end

read_nodes(FW_PATH .. 'nodes.conf')