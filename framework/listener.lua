
local protocols = Field.new('frame.protocols')

local fields = {}

function add_field(field)
    if fields[field] == nil then
        fields[field] = Field.new(field)
    end
end

function get_packet_protocol()
    local stack = tostring(protocols())

    -- Special cases
    if string.match(stack, 'http') then return 'http'
    elseif string.match(stack, 'ssl') then return 'ssl'
    elseif string.match(stack, 'tcp:data') then return 'tcp'
    elseif string.match(stack, 'udp:data') then return 'udp'
    elseif string.match(stack, "mdns") then return 'mdns'
    
    -- Normal case
    else
        local split = stack:split(':')
        return split[#split]
    end 
end

local scripts = {}

function register_script(name, main, filters)
	scripts[name] = main

    for i = 1, #filters do
        add_field(filters[i])
    end
end

function menu()

    local tap = Listener.new()
    local tw = TextWindow.new("Wireshark Security Plug-in")

    function tap.packet(pinfo, tvb, tapdata)
        local src = tostring(pinfo.src)
        local dst = tostring(pinfo.dst)
        
        local node = match_node(src, dst)
        
        if node ~= nil then
            local pnum = pinfo.number
            local time = pinfo.rel_ts
            local protocol = get_packet_protocol()

            local values = {}

            for name, field in pairs(fields) do
                if field() then
                    values[name] = tostring(field())
                else
                    values[name] = nil
                end
            end

            count_node(node, protocol)
            add_node_packet(node['num'], node['io'], pnum, src, dst, protocol, time, values)
        end 
    end

    function tap.draw()
    end

    function tap.reset(userdata)
    end

    function remove_tap() 
        if tap and tap.remove then tap:remove() end 
    end

    tw:add_button("Extract\nRaw Data", function()
        local stopwatch = os.time()
        tw:append("\n[-] Rescanning...\n")
        retap_packets()
        tw:append("\n[-] Raw data was successfully extracted. Time: " .. os.time() - stopwatch ..  " seconds.\n") 
        end
    )
    
    tw:add_button("Run\nAnalysis", 
        function() 
            run_scripts() 
        end
    )
    
    tw:add_button("Generate\nReport", 
        function() 
            generate_report() 
            tw:append("\n[-] Report generated.\n") 
        end
    )

    tw:append("Registered Data Analysis Scripts: ")
    tw:append("\n---------------------------------\n")
    for name, main in pairs(scripts) do tw:append("[+] " .. name .. "\n") end

    function run_scripts()
        local stopwatch = os.time()
        
        tw:append("\n\nScript Execution Status: ")
        tw:append("\n---------------------------------\n")
        
        for name, exec in pairs(scripts) do
            local result = exec()
            tw:append("[*] " .. name .. " was successfully executed. Time: "  .. os.time() - stopwatch .. " seconds.\n")
        end

        tw:append("\nAll scripts executed successfully. Total time: " .. os.time() - stopwatch .. " seconds.\n")
    end

end

register_menu("Wireshark Security Plug-in", menu, MENU_TOOLS_UNSORTED) 