PATH = 'C:\\Users\\eyvin\\AppData\\Roaming\\Wireshark\\framework\\'

if (file_exists(PATH .. 'global.lua')) then
    dofile(PATH .. 'global.lua')
end

if (file_exists(PATH .. 'stat.lua')) then
    dofile(PATH .. 'stat.lua')
end

if (file_exists(PATH .. 'listener.lua')) then
    dofile(PATH .. 'listener.lua')
end

if (file_exists(PATH .. 'report.lua')) then
    dofile(PATH .. 'report.lua')
end