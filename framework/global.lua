FW_PATH = 'C:\\Users\\eyvin\\AppData\\Roaming\\Wireshark\\framework\\'
HTML_PATH = 'C:\\Users\\eyvin\\AppData\\Roaming\\Wireshark\\framework\\html\\'
PLUGINS_PATH = 'C:\\Users\\eyvin\\AppData\\Roaming\\Wireshark\\plugins\\'
P_CONF_PATH = 'C:\\Users\\eyvin\\AppData\\Roaming\\Wireshark\\'

function string:split(separator)
    local separator, fields = separator or ":", {}
    local pattern = string.format("([^%s]+)", separator)
    self:gsub(pattern, function(c) fields[#fields+1] = c end)
    return fields
end

function round(num, idp)
    local mult = 10^(idp or 0)
    return math.floor(num * mult + 0.5) / mult
end

function string:upper_case(str)
    return str:gsub("%l", string.upper)
end

function table_contains(table, value)
    for i = 1, #table do
        if table[i] == value then
            return true
        end
    end
    return false
end

function copy(orig)
    local orig_type = type(orig)
    local copy
    if orig_type == 'table' then
        copy = {}
        for orig_key, orig_value in pairs(orig) do
            copy[orig_key] = orig_value
        end
    else -- number, string, boolean, etc
        copy = orig
    end
    return copy
end