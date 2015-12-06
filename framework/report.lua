local MAX_DELTA_IN = 5
local MAX_DELTA_OUT = 5

function check_delta(real, expected, delta)
    if math.abs(expected - real) > delta then
        return "<td style='background-color:#ff9854'>" .. real .. "</td><td style='background-color:#ff9854'>" .. expected .. "</td>"
    else 
        return "<td>" .. real .. "</td><td>" .. expected .. "</td>"
    end
end

function generate_report()
    local head = io.open(HTML_PATH .. "head.html", "r")
    local html = "<!doctype html><html>" .. head:read() .. "<body>"
    head:close()

    html = html .. "<h2>Summary Report</h2>"
    html = html .. "<p>Generated: " .. os.date("%Y-%m-%d %H:%M") .. "</p><hr>"

    local nodes = get_statistics()

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
        html = html .. "<td><b>Real</b> (%)</td>"
        html = html .. "<td><b>Expected</b> (%)</td>"
        html = html .. "<td><b>Frames</b></td>"
        html = html .. "<td><b>Real</b> (%)</td>"
        html = html .. "<td><b>Expected</b> (%)</td>"
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
            
            html = html .. check_delta(tonumber(in_real_percent), tonumber(in_exp_percent), MAX_DELTA_IN)
            
            html = html .. "<td>" .. out_frame_count .. "</td>"

            html = html .. check_delta(tonumber(out_real_percent), tonumber(out_exp_percent), MAX_DELTA_OUT)

            html = html .. "</tr>"
        end

        html = html .. "<tr style='background-color:#daffaf'>"
        html = html .. "<td><b>Total</b></td>"
        html = html .. "<td><b>" .. #nodes[i]['packets']['in'] .. "</b></td>"
        html = html .. "<td colspan=2></td>"
        html = html .. "<td><b>" .. #nodes[i]['packets']['out'] .. "</b></td>"
        html = html .. "<td colspan=2></td>"
        html = html .. "</tr>"

        html = html .. "<tr style='background-color:#dddddd'>"
        html = html .. "<td colspan='7'>Analysis Results</td>"
        html = html .. "</tr>"

        html = html .. "<tr>"
        html = html .. "<td colspan='2'><b>Name</b></td>"
        html = html .. "<td colspan='2'><b>Result</b></td>"
        html = html .. "<td colspan='3'><b>Description</b></td>"
        html = html .. "</tr>"
        
        for j = 1, #nodes[i]['fields'] do
            if not nodes[i]['fields'][j]['normal'] then
                html = html .. "<tr style='background-color:#ff9854'>"
            else
                html = html .. "<tr>"
            end

            html = html .. "<td colspan='2'>" .. nodes[i]['fields'][j]['name'] .. "</td>"
            html = html .. "<td colspan='2'>" .. nodes[i]['fields'][j]['result'] .. "</td>"
            html = html .. "<td colspan='3'>" .. nodes[i]['fields'][j]['description'] .. "</td>"
            html = html .. "</tr>"
        end

        html = html .. "</table>"

    end

    html = html .. "</body></html>"

    local outfile = io.open(HTML_PATH .. "report.html", "w")
    outfile:write(html)
    outfile:close()
end
