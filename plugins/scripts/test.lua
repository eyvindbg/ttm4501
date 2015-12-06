function main()

	local tw = TextWindow.new("Test")
	tw:set("---\n")

	local nodes = get_statistics()

	--tw:set("Node\tIO\tPnum\tProtocol\tTime\tSYN\tACK\n")


	for i = 1, #nodes do
		for io, packets in pairs(nodes[i]['packets']) do
			for j = 1, #packets do
				--tw:append(i .. "\t" .. io .. "\t" .. packets[j]['pnum'] .. "\t" .. packets[j]['protocol'] .. "\t" .. packets[j]['time'] .. "\t" .. tostring(packets[j]['values']['tcp.flags.syn']) .. "\t" .. tostring(packets[j]['values']['tcp.flags.ack']) .. "\n")
				tw:append(i .. "\t" .. io .. "\t" .. packets[j]['pnum'] .. "\t" .. tostring(packets[j]['values']['tcp.len']) .. "\n")
			end
		end
	end

	return {"", ""}
end

fields = {
    'tcp.len'
}

--register_tap("Test", main, fields)