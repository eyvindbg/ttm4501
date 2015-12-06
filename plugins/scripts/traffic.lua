local MAX_DELTA_IN = 10
local MAX_DELTA_OUT = 10

function check_delta(real, expected, delta)
    if real > (expected + delta) or real < (expected - delta) then
        return "<td style='background-color:#ffaaaa'>" .. real .. "</td><td style='background-color:#ffaaaa'>" .. expected .. "</td>"
    else 
        return "<td>" .. real .. "</td><td>" .. expected .. "</td>"
    end
end

function generate_report()
    local head = io.open(PLUGINS_PATH .. "head.html", "r")
    local html = "<!doctype html><html>" .. head:read() .. "<body>"
    head:close()

    html = html .. "<h2>Summary Report</h2>"
    html = html .. "<p>Generated: " .. os.date("%Y-%m-%d %H:%M") .. "</p><hr>"

    local nodes = get_statistics()

    local html = ""

    for i = 1, #nodes do
        html = html .. "<table>"
        html = html .. "<tr style='background-color:#dddddd'><td>Node</td><td colspan='6'>" .. i .. "</td></tr>"
        
        html = html .. "<tr><td>Type</td><td colspan='6'>"

        for j = 1, #nodes[i]['type'] do
            html = html .. nodes[i]['type'][j]
            if j ~= #nodes[i]['type'] then html = html .. ", " end
        end

        html = html .. "</td></tr>"
        
        html = html .. "<tr><td>IPv4</td><td colspan='6'>" .. nodes[i]['addr']['ipv4'] .. "</td></tr>"
        html = html .. "<tr><td>IPv6</td><td colspan='6'>" .. nodes[i]['addr']['ipv6'] .. "</td></tr>"
        html = html .. "<tr><td>MAC</td><td colspan='6'>" .. nodes[i]['addr']['mac'] .. "</td></tr>"

        html = html .. "<tr style='background-color:#dddddd'>"
        html = html .. "<td>Traffic</td>"
        html = html .. "<td colspan='3'>Inbound</td>"
        html = html .. "<td colspan='3'>Outbound</td>"
        html = html .. "</tr>"

        html = html .. "<tr>"
        html = html .. "<td><b>Protocol</b></td>"
        html = html .. "<td><b>Frames</b></td>"
        html = html .. "<td><b>% Real</b></td>"
        html = html .. "<td><b>% Expected</b></td>"
        html = html .. "<td><b>Frames</b></td>"
        html = html .. "<td><b>% Real</b></td>"
        html = html .. "<td><b>% Expected</b></td>"
        html = html .. "</tr>"

        local sorted_proto = sort_protocols(i)

        for k, proto in ipairs(sorted_proto) do

            local in_frame_count = nodes[i]['protocols'][proto]['in']['count']
            local in_real_percent = nodes[i]['protocols'][proto]['in']['real']
            local in_exp_percent = nodes[i]['protocols'][proto]['in']['exp']

            local out_frame_count = nodes[i]['protocols'][proto]['out']['count']
            local out_real_percent = nodes[i]['protocols'][proto]['out']['real']
            local out_exp_percent = nodes[i]['protocols'][proto]['out']['exp']

            html = html .. "<tr>"
            html = html .. "<td>" .. proto .. "</td>"
            html = html .. "<td>" .. in_frame_count .. "</td>"
            
            html = html .. check_delta(in_real_percent, in_exp_percent, MAX_DELTA_IN)
            
            html = html .. "<td>" .. out_frame_count .. "</td>"

            html = html .. check_delta(out_real_percent, out_exp_percent, MAX_DELTA_OUT)

            html = html .. "</tr>"
        end

        html = html .. "<tr style='background-color:#aaddff'>"
        html = html .. "<td><b>Total</b></td>"
        html = html .. "<td><b>" .. #nodes[i]['packets']['in'] .. "</b></td>"
        html = html .. "<td></td>"
        html = html .. "<td></td>"
        html = html .. "<td><b>" .. #nodes[i]['packets']['out'] .. "</b></td>"
        html = html .. "<td></td>"
        html = html .. "<td></td>"
        html = html .. "</tr>"

        html = html .. "<tr style='background-color:#dddddd'>"
        html = html .. "<td colspan='7'>Fields</td>"
        html = html .. "</tr>"

        html = html .. "<tr>"
        html = html .. "<td colspan='2'><b>Name</b></td>"
        html = html .. "<td colspan='2'><b>Value</b></td>"
        html = html .. "<td colspan='3'><b>Comment</b></td>"
        html = html .. "</tr>"
        
        for j = 1, #nodes[i]['fields'] do
            html = html .. "<tr>"
            html = html .. "<td colspan='2'>" .. nodes[i]['fields'][j]['name'] .. "</td>"
            html = html .. "<td colspan='2'>" .. nodes[i]['fields'][j]['value'] .. "</td>"
            html = html .. "<td colspan='3'>" .. nodes[i]['fields'][j]['comment'] .. "</td>"
            html = html .. "</tr>"
        end

        html = html .. "</table>"
        html = html .. "</body></html>"

        local outfile = io.open(PLUGINS_PATH .. "report.html", "w")
        outfile:write(html)
        outfile:close()

    end
end
