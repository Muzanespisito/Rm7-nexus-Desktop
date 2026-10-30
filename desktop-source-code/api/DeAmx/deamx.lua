--[[

	DeAMX, trc_'s .amx -> .pwn decompiler
	  (2008)
	Updated by iAmir (C) 2018

  Licence
	
	You may:
	- Use this program free of charge
	- Modify it
	- Redistribute it with your changes, provided you keep
	  the name of the original author (i.e. don't pretend you
	  made it all by yourself) and this licence, and mention
	  that you changed it (plus eventually what changes you made).
	- Use parts of this program in your own scripts, again
	  provided you mention that you used code from DeAMX and
	  name its author.
	  
	You are not allowed to:
	- Distribute this program, with or without changes, with the
	  name of the author and/or this licence removed, and/or with
	  the claim that you or someone else than the original author
	  made it, because you didn't.
	- Sell this program or a derivation of it.
	
  Disclaimer:

	The author is in no way responsible for what you do with this
	decompiler. You are not allowed to decompile someone else's
	script and re-release it as your own script, unless explicitely
	approved by the script's author.

                                                                ]]--

function include(file)
	assert(loadfile(file))()
end

-- Diagnostics: every failure met while decompiling is collected in g_DeamxLog
-- and reported to the host application, so a broken .amx always comes back
-- with a readable reason instead of a silent crash.
g_DeamxLog = {}
g_DeamxFnOk = 0
g_DeamxFnFail = 0

function dlog(level, msg)
	msg = tostring(msg)
	table.insert(g_DeamxLog, { level = level, msg = msg })
	print(('[DeAMX %s] %s'):format(level:upper(), msg))
end

include('deamx_util.lua')
include('deamx_opcodes.lua')
include('deamx_events.lua')
include('deamx_syscalls.lua')

g_ParamTypeToName = { p = 'playerid', o = 'objectid', v = 'vehicleid'}
g_TypeTags = {
	f = 'Float',
	h = 'File',
	n = 'Menu',
	x = 'Text',
	xp = 'PlayerText',
	d = 'Text3D',
	dp = 'PlayerText3D'
}

sortDescending = function(a, b) return b < a end
function collectNewFrameVars(amx, onlyIfDefined)
	local newFrameVars
	for offset,framevar in pairs(amx.frameVars) do
		if offset < 0 and framevar.new and (not onlyIfDefined or framevar.value) then
			if not newFrameVars then
				newFrameVars = {}
			end
			newFrameVars[#newFrameVars+1] = offset
		end
		framevar.incremented = nil
		framevar.decremented = nil
	end
	if newFrameVars then
		amx.statement = 'new '
		table.sort(newFrameVars, sortDescending)
		local framevar, simpletype
		for i,offset in ipairs(newFrameVars) do
			if i > 1 then
				amx.statement = amx.statement .. ', '
			end
			framevar = amx.frameVars[offset]
			simpletype = framevar.type and (#framevar.type == 1 and framevar.type or framevar.type:sub(1, 1))
			if simpletype and g_TypeTags[simpletype] then
				amx.statement = amx.statement .. g_TypeTags[simpletype] .. ':'
			end
			amx.statement = amx.statement .. framevar[1]
			if framevar.dimensions then
				amx.statement = amx.statement .. dimensionsToString(framevar.dimensions)
			end
			if framevar.value then
				amx.statement = amx.statement .. ' = ' .. framevar.value
			end
			framevar.new = nil
		end
	end
end

function collectRetVal(amx)
	local ret = amx.PRI
	if amx.curPass == 1 then
		if not amx.returnVals[amx.curProcStart] then
			amx.returnVals[amx.curProcStart] = {}
		end
		local retlist = amx.returnVals[amx.curProcStart]
		if ret.globvar then
			retlist[amx.CIP] = { ret.globvar.addr, isglobvar = true }
		elseif ret.outercall then
			retlist[amx.CIP] = { ret.outercall, iscall = true }
		elseif ret.framevar then
			if ret.framevar.stk >= 12 then
				retlist[amx.CIP] = { idiv(ret.framevar.stk-12, 4)+1, isargvar = true }
			else
				retlist[amx.CIP] = { ret.framevar.definedat, islocalvar = true }
			end
		end
	elseif type(ret[1]) == 'number' and amx.learnedFunctionPrototypes[amx.curProcStart] and amx.learnedFunctionPrototypes[amx.curProcStart].returntype == 'f' then
		amx.PRI[1] = cell2float(ret[1])
		local ipart, fpart = math.modf(amx.PRI[1])
		if fpart == 0 then
			-- Lua 5.4 already stringifies integral floats as `60.0`, so do not
			-- append a second suffix (which produced `60.0.0`).
			amx.PRI[1] = tostring(ipart) .. '.0'
		end
	end
end

function removePastOpcodeAddrs(amx)
	while #amx.fnJumps > 0 and amx.CIP > amx.fnJumps[1] do
		table.remove(amx.fnJumps, 1)
	end
	while #amx.fnBreaks > 0 and amx.CIP > amx.fnBreaks[1] do
		table.remove(amx.fnBreaks, 1)
	end
end

function decompileBlock(amx, from, to, indent, catchAllStatements, elseIfAddr)
	--print(('Decompiling from %X to %X'):format(from, to))
	local result = ''
	local indentstr
	if indent then
		amx.indent = indent
		indentstr = ('\t'):rep(indent)
		if not elseIfAddr then
			result = result .. ('\t'):rep(indent-1) .. '{\n'
		end
	else
		indentstr = ''
	end
	
	local stkBkp = amx.STK
	local frameVarsBkp = {}
	for offset,val in pairs(amx.frameVars) do
		if offset < 0 then
			frameVarsBkp[offset] = table.shallowcopy(val)
		end
	end
	
	local g_AMXOpcodes = g_AMXOpcodes
	amx.CIP = from
	local opcode, numArgs
	local args = {}
	while to and amx.CIP < to do
		removePastOpcodeAddrs(amx)
		opcode = amx.memCOD[amx.CIP]
		--print(('%d %X (%d)'):format(indent or 0, amx.CIP, opcode))
		if opcode == 47 or opcode == 48 or opcode == 137 or catchAllStatements then
			-- ret/retn/break
			-- While reconstructing a statement-by-statement block (for-loop
			-- initialisers), don't flush a slot as soon as it appears: the
			-- following store still carries its initial value. Flushing here
			-- produced `new var0, var0 = 0` instead of `new var0 = 0`.
			collectNewFrameVars(amx, catchAllStatements and opcode ~= 47 and opcode ~= 48 and opcode ~= 137)
			if opcode == 47 or opcode == 48 then
				collectRetVal(amx)
			end
			table.clear(amx.incrementedGlobalVars)
			table.clear(amx.decrementedGlobalVars)
			if amx.statement and #amx.condnodes == 0 and not ((opcode == 47 or opcode == 48) and amx.PRI[1] ~= 0) then
				result = result .. indentstr .. amx.statement .. (indent and ';\n' or '; ')
			end
			amx.statement = nil
			if (opcode == 47 or opcode == 48) and amx.STK > stkBkp then
				for offset,val in pairs(frameVarsBkp) do
					amx.frameVars[offset] = frameVarsBkp[offset]
				end
				amx.STK = stkBkp
			end
		end
		if opcode == 129 then
			-- switch
			result = result .. indentstr .. 'switch(' .. amx.PRI[1] .. ') {\n'
			local indentstr1 = ('\t'):rep(indent + 1)
			local casetbl = amx.memCOD[amx.CIP+4]+4
			local numCases = amx.memCOD[casetbl]
			local defaultCase = amx.memCOD[casetbl+4]
			local cases = {}
			for i=1,numCases do
				cases[i] = { value = amx.memCOD[casetbl + i*8], addr = amx.memCOD[casetbl + i*8 + 4] }
			end
			table.sort(cases, function(a, b) return a.addr < b.addr end)
			for i,case in ipairs(cases) do
				result = result .. indentstr1 .. 'case ' .. case.value .. ':\n' .. decompileBlock(amx, case.addr, i < numCases and cases[i+1].addr or defaultCase, indent+2, false, true)
			end
			if defaultCase < casetbl + (numCases+1)*8 then
				result = result .. indentstr1 .. 'default:\n' .. decompileBlock(amx, defaultCase, casetbl-4, indent+2, false, true)
			end
			result = result .. indentstr .. '}\n'
		end
		while (opcode == 137 or (amx.forloop and amx.CIP == amx.forloop.loopend or amx.whileloop and amx.CIP == amx.whileloop.loopend)) and amx.CIP < to do
			--print(('%d %X (%d)'):format(indent or 0, amx.CIP, opcode))
			if #amx.condnodes == 0 then
				local loopEnd
				if #amx.fnBreaks >= 2 and #amx.fnJumps >= 2 and amx.fnJumps[1] == amx.fnBreaks[2]-8 and amx.memCOD[amx.fnJumps[1]+4] < amx.fnJumps[2] then
					for i,jmpaddr in ipairs(amx.fnJumps) do
						if amx.memCOD[jmpaddr+4] == amx.fnBreaks[2] then
							loopEnd = jmpaddr + 8
							break
						end
					end
					if loopEnd and isCondOpcode(amx.memCOD[(#amx.fnBreaks >= 3 and amx.fnBreaks[3] < loopEnd and amx.fnBreaks[3] or loopEnd-8)-8]) then
						-- for loop
						--print(('%X Found a for loop'):format(amx.CIP))
						amx.forloop = {}
						amx.forloop.init = decompileBlock(amx, amx.CIP+4, amx.fnBreaks[2]-8, false, true):gsub(';', ',')
						amx.forloop.step = decompileBlock(amx, amx.fnBreaks[1]+4, amx.memCOD[amx.CIP+4], false)
						amx.forloop.loopend = loopEnd
					end
				elseif #amx.fnJumps >= 1 then
					for i,jmpaddr in ipairs(amx.fnJumps) do
						if amx.memCOD[jmpaddr+4] == amx.CIP then
							loopEnd = jmpaddr + 8
							break
						end
					end
					if loopEnd and isCondOpcode(amx.memCOD[(#amx.fnBreaks >= 2 and amx.fnBreaks[2] < loopEnd and amx.fnBreaks[2] or loopEnd-8)-8]) then
						-- while loop
						--print(('%X Found a while loop'):format(amx.CIP))
						amx.whileloop = { loopend = loopEnd }
					end
				end
				break
			else
				amx.statement = nil
				local node = table.remove(amx.condnodes)
				
				if amx.forloop then
					--print(('%X Writing for loop'):format(amx.CIP))
					local forloop = amx.forloop
					amx.forloop = nil
					result = result .. indentstr .. 'for(' .. forloop.init .. '; ' .. node[1] .. '; ' .. forloop.step .. ')\n' .. decompileBlock(amx, amx.CIP, forloop.loopend, indent+1)
				elseif amx.whileloop then
					-- while loop
					--print(('%X Writing while loop'):format(amx.CIP))
					local whileloop = amx.whileloop
					amx.whileloop = nil
					result = result .. indentstr .. 'while(' .. node[1] .. ')\n' .. decompileBlock(amx, amx.CIP, whileloop.loopend, indent+1)
				else
					-- if/else
					if node.endpoint and amx.memCOD[node.endpoint-8] == 51 then
						--print('Writing if/else')
						local upcomingBreak = findClosestInstrsAfter(amx, 137, amx.memCOD[node.endpoint] == 137 and node.endpoint+4 or node.endpoint, amx.memCOD[node.endpoint-4], 1)
						local isElseif = #upcomingBreak == 1 and isCondOpcode(amx.memCOD[upcomingBreak[1]-8]) and
							(
								amx.memCOD[upcomingBreak[1]-4] == amx.memCOD[node.endpoint-4]
								or
								(amx.memCOD[amx.memCOD[upcomingBreak[1]-4]-8] == 51 and amx.memCOD[amx.memCOD[upcomingBreak[1]-4]-4] == amx.memCOD[node.endpoint-4])
							)
						result = result .. (elseIfAddr == amx.CIP and ' ' or indentstr) .. 'if(' .. node[1] .. ')\n' .. decompileBlock(amx, amx.CIP+4, node.endpoint-8, indent+1) .. indentstr .. 'else'
						if not isElseif then
							result = result .. '\n'
						end
						result = result .. decompileBlock(amx, node.endpoint, amx.memCOD[node.endpoint-4], isElseif and indent or (indent+1), false, isElseif and upcomingBreak[1])
					else
						--print('Writing if (endpoint = ' .. ('%X'):format(node.endpoint) .. ')')
						result = result .. (elseIfAddr == amx.CIP and ' ' or indentstr) .. 'if(' .. node[1] .. ')\n' .. decompileBlock(amx, amx.CIP+4, node.endpoint, indent+1)
					end
				end
			end
			opcode = amx.memCOD[amx.CIP]
			removePastOpcodeAddrs(amx)
		end
		if amx.CIP < to then
			opcode = amx.memCOD[amx.CIP]
			local opinfo = g_AMXOpcodes[opcode]
			if not opinfo then
				error(opcodeErrorText(opcode), 0)
			end
			numArgs = opinfo[1]
			for i=1,numArgs do
				args[i] = amx.memCOD[amx.CIP + i*4]
			end
			for i=numArgs+1,#args do
				args[i] = nil
			end
			amx.CIP = amx.CIP + 4 + 4*numArgs
			local okOp, errOp = pcall(opinfo[2], amx, unpack(args))
			if not okOp then
				error(('opcode %d at 0x%X: %s'):format(opcode, amx.CIP - 4 - 4*numArgs, tostring(errOp)), 0)
			end
		end
	end
	collectNewFrameVars(amx, true)
	collectRetVal(amx)
	table.clear(amx.incrementedGlobalVars)
	table.clear(amx.decrementedGlobalVars)
	if amx.statement then
		result = result .. indentstr .. amx.statement .. (indent and ';\n' or '')
		amx.statement = nil
	end
	if indent and not elseIfAddr then
		result = result .. ('\t'):rep(indent-1) .. '}\n'
	end
	
	if amx.STK > stkBkp then
		for offset,val in pairs(frameVarsBkp) do
			amx.frameVars[offset] = frameVarsBkp[offset]
		end
		amx.STK = stkBkp
	end
	
	if indent then
		amx.indent = indent - 1
	end
	return result
end

globalVarMT = {
	__index = function(t, k)
		if type(k) ~= 'number' then
			return nil
		end
		t[k] = { ('glob%X'):format(k), addr = k }
		return t[k]
	end
}

frameVarMT = {
	__index = function(t, k)
		if k >= 12 then
			for i=12,k,4 do
				if not rawget(t, i) then
					t[i] = { 'arg' .. idiv(i-12, 4), stk = i }
					t[i].framevar = t[i]
				end
			end
			local value = rawget(t, k)
			if value then
				return value
			end
			-- Non-cell-aligned or otherwise unexpected frame offset. Do not
			-- recurse through __index; synthesize a local slot instead.
			local name = 'var' .. tostring(k)
			t[k] = { name, stk = k, new = true, definedat = k }
			t[k].framevar = t[k]
			return t[k]
		elseif k < 12 then
			-- A frame slot can be referenced before the stack tracking has
			-- seen its allocation (common in packed or partially decoded AMX
			-- files). Keep going with a synthetic local instead of aborting
			-- the whole function.
			local name = 'var' .. tostring(k < 0 and -k or k)
			t[k] = { name, stk = k, new = true, definedat = k }
			t[k].framevar = t[k]
			return t[k]
		end
	end
}

function listGlobalVars(amx)
	local result = ''
	local sortedGlobalVars = {}
	for addr,glob in pairs(amx.globalVars) do
		table.insert(sortedGlobalVars, { addr = addr, glob = glob })
	end
	table.sort(sortedGlobalVars, function(a, b) return a.addr < b.addr end)
	local addr, glob, name, data
	for i,sortedglob in pairs(sortedGlobalVars) do
		addr, glob = sortedglob.addr, sortedglob.glob
		if not glob.immediate then
			name = (g_TypeTags[glob.type] and (g_TypeTags[glob.type] .. ':') or '') .. glob[1]
			if not glob.dimensions then
				local length = i < #sortedGlobalVars and idiv(sortedGlobalVars[i+1].addr - addr, 4)
				if not length or length == 1 then
					data = sgn(amx.memDAT[addr])
					if not data then data = 0 end
					result = result .. 'new ' .. name .. (data == 0 and '' or (' = ' .. data)) .. ';\n\n'
				else
					glob.dimensions = { length }
					result = result .. 'new ' .. name .. '[' .. length .. '];\n\n'
				end
			else
				result = result .. 'new ' .. name .. dimensionsToString(glob.dimensions)
				if isGlobalArrayInitialized(amx, addr, glob.dimensions) then
					result = result .. ' = ' .. dumpGlobalArray(amx, addr, glob.type, glob.dimensions):gsub('\n$', '')
				end
				result = result .. ';\n\n'
			end
		end
	end
	return result
end

function isGlobalArrayInitialized(amx, addr, dimensions, curdim)
	if not curdim then
		curdim = 1
	end
	if curdim < #dimensions then
		for i=0,dimensions[curdim] do
			if isGlobalArrayInitialized(amx, addr + i*4 + amx.memDAT[addr + i*4], dimensions, curdim + 1) then
				return true
			end
		end
	else
		for i=0,(dimensions[curdim] or 0) do
			if amx.memDAT[addr + i*4] ~= 0 then
				return true
			end
		end
	end
	return false
end

function dumpGlobalArray(amx, addr, type, dimensions, curdim, baseindent)
	if not curdim then
		curdim = 1
	end
	local indent = ('\t'):rep((baseindent or 0) + curdim-1)
	local result
	if curdim < #dimensions then
		result = indent .. '{'
		for i=0,dimensions[curdim] do
			if i > 0 then
				result = result:gsub('\n$', '') .. ','
			end
			result = result .. '\n' .. indent .. dumpGlobalArray(amx, addr + i*4 + amx.memDAT[addr + i*4], type, dimensions, curdim + 1)
		end
		return result .. '\n' .. indent .. '}\n'
	elseif type == 's' then
		return '\t"' .. readMemString(amx, addr) .. '"'
	else
		result = indent .. '{ '
		local val
		for i=0,(dimensions[curdim] or 0) do
			if i > 0 then
				result = result .. ', '
			end
			val = amx.memDAT[addr + i*4]
			if type == 'f' then
				val = tostring(cell2float(val))
			else
				val = sgn(val)
			end
			if val then
				result = result .. val
			end
		end
		return result .. ' }'
	end
end

do
	local amx, opcode, procStart, procEnd
	local fnName
	local step = step
	for _,file in ipairs(arg) do
		-- fresh diagnostics for every file
		table.clear(g_DeamxLog)
		g_DeamxFnOk = 0
		g_DeamxFnFail = 0

		local loadErr
		amx, loadErr = loadAMX(file)
		if not amx then
			dlog('error', ('%s: %s'):format(file:gsub('^.*/', ''), loadErr or 'unknown error'))
		end
		if amx then
			local mainOffset = amx.CIP
			local isReplaced
			amx.globalVars = setmetatable({}, globalVarMT)
			amx.incrementedGlobalVars = {}
			amx.decrementedGlobalVars = {}
			amx.condnodes = {}
			amx.learnedFunctionPrototypes = {}		-- { fnAddr = { type, type, ... } }
			amx.learnedFrameVarTypes = {}			-- { definitionAddr = type }
			amx.callVars = {}						-- { call addr = { argNum1 = argSpec, argNum2 = argSpec, ... } }
													--   with argSpec one of: { memAddr, isglobvar = true }
													--                        { definitionAddr, islocalvar = true }
													--                        { argNum, isargvar = true, procaddr = procAddr }
			amx.returnVals = {}						-- { fnAddr = { retAddr1 = retSpec, retAddr2 = retSpec, ... } }
													--   with retSpec like argSpec, plus: { fnAddr, iscall = true }
			local output = {}
			local globalsText
			
			local okPasses, errPasses = pcall(function()
			for pass=1,2 do
				amx.curPass = pass
				-- Legacy DeAMX starts scanning at address 8, which fails for
				-- scripts whose whole code section is smaller than ~12 bytes
				-- (the loop would run zero iterations). For those tiny files,
				-- anchor on the entry point or the first PROC marker instead;
				-- otherwise keep the proven legacy behaviour untouched.
				procStart = 8
				if amx.sizeCOD < 16 then
					local anchor
					if amx.CIP and amx.CIP % 4 == 0 and amx.CIP < amx.sizeCOD - 4 and amx.memCOD[amx.CIP] == 46 then
						anchor = amx.CIP
					else
						local probe = 0
						while probe < amx.sizeCOD - 4 do
							if amx.memCOD[probe] == 46 then
								anchor = probe
								break
							end
							probe = probe + 4
						end
					end
					if anchor then
						procStart = anchor
					elseif amx.sizeCOD > 4 then
						-- no PROC found at all: still attempt one scan from the
						-- start so the failure carries a real reason instead of
						-- silently reporting "no functions"
						procStart = 0
					end
				end
				procEnd = procStart + 4
				while procEnd < amx.sizeCOD do
					procEnd = procStart + 4
					opcode = amx.memCOD[procEnd]
					while procEnd < amx.sizeCOD and opcode ~= 46 do
						local okStep, newEnd = pcall(step, amx, procEnd, opcode)
						if not okStep then
							-- Undecodable bytes while looking for the next PROC:
							-- skip them cell-by-cell instead of losing the rest
							-- of the script. The affected function(s) will fail
							-- later with their own recorded reason.
							dlog('warn', ('skipping undecodable code at 0x%X (%s)'):format(procEnd, tostring(newEnd)))
							repeat
								procEnd = procEnd + 4
							until procEnd >= amx.sizeCOD or amx.memCOD[procEnd] == 46
							break
						end
						procEnd = newEnd
						opcode = amx.memCOD[procEnd]
					end
					isReplaced = false
					for fn,replacer in pairs(g_FunctionReplace) do
						if fn.addr == procStart then
							isReplaced = true
							break
						end
					end
					if not isReplaced then
						fnName = amx.publics[procStart]
						if not fnName then
							if procStart == mainOffset then
								fnName = 'main'
							else
								fnName = ('function%X'):format(procStart)
							end
						end
						-- Everything below can fail on packed/corrupt code;
						-- catch it per function so one bad function does not
						-- kill the whole decompilation, and record the reason.
						local okFn, errFn = pcall(function()
						local funcBody, argList
						amx.frameVars = setmetatable({}, frameVarMT)
						amx.heapVars = {}
						argList = g_SAMPEventParamNames[fnName]
						if not argList and amx.learnedFunctionPrototypes[procStart] then
							argList = {}
							local name
							local nameUsageNum = {}
							for i,type in pairs(amx.learnedFunctionPrototypes[procStart]) do
								name = g_ParamTypeToName[type]
								if name then
									if nameUsageNum[name] then
										nameUsageNum[name] = nameUsageNum[name] + 1
										name = name .. nameUsageNum[name]
									else
										nameUsageNum[name] = 1
									end
									argList[i] = name
								end
							end
						end
						if argList then
							local stk
							for i,argname in pairs(argList) do
								if type(i) == 'number' then
									stk = 12 + (i-1)*4
									if(string.find(argname, "Text:") ~= nil) then argname = string.gsub(argname,"Text:","") end
									if(string.find(argname, "Playertext:") ~= nil) then argname = string.gsub(argname,"PlayerText:","") end
									if(string.find(argname, "Float:") ~= nil) then argname = string.gsub(argname,"Float:","") end
									if(string.find(argname, "%[%]") ~= nil) then argname = string.gsub(argname,"%[%]","") end
									if(string.find(argname, "Menu:") ~= nil) then argname = string.gsub(argname,"Menu:","") end
									if(string.find(argname, "File:") ~= nil) then argname = string.gsub(argname,"File:","") end
									amx.frameVars[stk] = { argname, stk = stk }
								end
							end
						end
						
						amx.STK = 0
						amx.HEA = 0
						amx.fnJumps, amx.fnBreaks = getOpcodeAddrs(amx, procStart, procEnd, 51, 137)
						amx.curProcStart = procStart
						funcBody = decompileBlock(amx, procStart+4, procEnd, 1)

						if pass == 2 then
							if not argList then
								argList = {}
							end
							if not g_SAMPEventParamNames[fnName] then
								local i = 1
								local framevar, framevarType
								while true do
									framevar = rawget(amx.frameVars, 12 + (i-1)*4)
									if not framevar then
										break
									end
									if not argList[i] then
										argList[i] = framevar[1]
									end
									framevarType = amx.learnedFunctionPrototypes[procStart] and amx.learnedFunctionPrototypes[procStart][i]
									if framevarType and g_TypeTags[(#framevarType > 1 and framevarType:sub(1, 1) or framevarType)] then
										argList[i] = g_TypeTags[(#framevarType > 1 and framevarType:sub(1, 1) or framevarType)] .. ':' .. argList[i]
									end
									if framevar.ref then
										argList[i] = '&' .. argList[i]
									end
									if framevar.dimensions or framevar.type == 's' then
										argList[i] = argList[i] .. ('[]'):rep(not framevar.dimensions and 1 or #framevar.dimensions)
									end
									i = i + 1
								end
							end
							if amx.learnedFunctionPrototypes[procStart] and amx.learnedFunctionPrototypes[procStart].returntype and g_TypeTags[amx.learnedFunctionPrototypes[procStart].returntype] then
								fnName = fnName
							end
							if amx.publics[procStart] then
								fnName = 'public ' .. fnName
							end

							fnOutput = fnName .. '(' .. table.concat(argList, ', ') .. ')\n' .. funcBody .. '\n'
						end
						end)	-- end of per-function pcall

						if okFn then
							if pass == 2 then
								table.insert(output, fnOutput)
								g_DeamxFnOk = g_DeamxFnOk + 1
							end
						else
							if pass == 2 then
								g_DeamxFnFail = g_DeamxFnFail + 1
								dlog('error', ('could not decompile %s (address 0x%X): %s'):format(fnName, procStart, tostring(errFn)))
							end
						end
					end
					procStart = procEnd
				end
				if pass == 1 then
					local syscallName
					local prototype
					local newTypeInfoFound
					local scanNum = 1
					repeat
						newTypeInfoFound = false
						for callAddr,argInfo in pairs(amx.callVars) do
							if amx.memCOD[callAddr] == 123 then
								syscallName = amx.natives[amx.memCOD[callAddr+4]]
								prototype = g_SAMPSyscallPrototypes[syscallName]
							else
								prototype = amx.learnedFunctionPrototypes[amx.memCOD[callAddr+4]]
							end
							if prototype then
								--print(('Prototype found for call at %X'):format(callAddr))
								for argNum,argSpec in pairs(argInfo) do
									if argSpec.isglobvar then
										local globvar = amx.globalVars[argSpec[1]]
										if not globvar.type then
											local globtype = prototype[argNum] or 's'
											if globtype == 's' and globvar.dimensions then
												local addr = zeroIndexToDimension(amx, globvar.addr, #globvar.dimensions)
												if not readMemString(amx, addr) then
													if not amx.memDAT[addr] or not readMemString(amx, addr+amx.memDAT[addr]) then
														globtype = 'i'
													else
														table.insert(globvar.dimensions, 0)
													end
												end
											end
											globvar.type = globtype
											--print(('Globvar at %X is now of type %s'):format(argSpec[1], globtype))
											newTypeInfoFound = true
										end
									elseif argSpec.islocalvar then
										if not amx.learnedFrameVarTypes[argSpec[1]] then
											amx.learnedFrameVarTypes[argSpec[1]] = prototype[argNum]
											--print(('Framevar defined at %X is now of type %s'):format(argSpec[1], prototype[argNum]))
											newTypeInfoFound = true
										end
									elseif argSpec.isargvar then
										if not amx.learnedFunctionPrototypes[argSpec.procaddr] then
											amx.learnedFunctionPrototypes[argSpec.procaddr] = {}
										end
										if not amx.learnedFunctionPrototypes[argSpec.procaddr][argSpec[1]] then
											amx.learnedFunctionPrototypes[argSpec.procaddr][argSpec[1]] = prototype[argNum]
											--print(('Arg %d of function %X is now of type %s'):format(argSpec[1], argSpec.procaddr, prototype[argNum]))
											newTypeInfoFound = true
										end
									end
								end
							--else
								--print(('No prototype for call at %X'):format(callAddr))
							end
						end
						for fnAddr,returns in pairs(amx.returnVals) do
							if not amx.learnedFunctionPrototypes[fnAddr] then
								amx.learnedFunctionPrototypes[fnAddr] = {}
							end
							if not amx.learnedFunctionPrototypes[fnAddr].returntype then
								for retAddr,retSpec in pairs(returns) do
									if retSpec.isglobvar then
										local globvar = amx.globalVars[retSpec[1]]
										if globvar.type then
											amx.learnedFunctionPrototypes[fnAddr].returntype = globvar.type
											newTypeInfoFound = true
										end
									elseif retSpec.islocalvar then
										if amx.learnedFrameVarTypes[retSpec[1]] then
											amx.learnedFunctionPrototypes[fnAddr].returntype = amx.learnedFrameVarTypes[retSpec[1]]
											newTypeInfoFound = true
										end
									elseif retSpec.isargvar then
										if amx.learnedFunctionPrototypes[fnAddr][retSpec[1]] then
											amx.learnedFunctionPrototypes[fnAddr].returntype = amx.learnedFunctionPrototypes[fnAddr][retSpec[1]]
											newTypeInfoFound = true
										end
									elseif retSpec.iscall then
										if type(retSpec[1]) == 'number' then
											prototype = amx.learnedFunctionPrototypes[retSpec[1]]
										else
											prototype = g_SAMPSyscallPrototypes[retSpec[1]]
										end
										if prototype and prototype.returntype then
											amx.learnedFunctionPrototypes[fnAddr].returntype = prototype.returntype
											newTypeInfoFound = true
										end
									end
								end
							end
						end
					scanNum = scanNum + 1
				until not newTypeInfoFound or scanNum == 20

				globalsText = listGlobalVars(amx) .. '\n'
			end
			end	-- for pass = 1,2
			end)	-- end of two-pass safety net
			if not okPasses then
				dlog('error', ('fatal error while decompiling: %s'):format(tostring(errPasses)))
			end

			-- Summarise the run and diagnose the "nothing recovered" case so
			-- the host application always has a meaningful reason to show.
			if g_DeamxFnOk > 0 or g_DeamxFnFail > 0 then
				dlog('info', ('done: %d function(s) decompiled, %d failed'):format(g_DeamxFnOk, g_DeamxFnFail))
				if g_DeamxFnOk == 0 and (amx.sizeCOD or 0) <= 16 then
					dlog('error', ('the code section is only %d bytes and contains no valid Pawn code - this .amx is most likely packed/protected; its real bytecode is rebuilt in memory at runtime and cannot be recovered from the file')
						:format(amx.sizeCOD))
				end
			else
				local numPublics = 0
				for _ in pairs(amx.publics or {}) do numPublics = numPublics + 1 end
				local hint = ('no Pawn functions were found in the code section (COD=%d, DAT=%d, code size=%d bytes, flags=0x%X, %d publics)')
					:format(amx.COD, amx.DAT, amx.sizeCOD or 0, amx.flags or 0, numPublics)
				if amx.isCompacted == false then
					hint = hint .. ' (this .amx is not compacted, which DeAMX does not fully support)'
				elseif (amx.sizeCOD or 0) <= 16 then
					hint = hint .. ' (the header declares an almost empty code section - this file is probably packed/protected)'
				else
					hint = hint .. ' (file may use an unsupported compiler or non-standard layout)'
				end
				dlog('error', hint)
			end

			-- Assemble the .pwn: diagnostics report first (as Pawn comments),
			-- then includes, globals, and every function that decompiled.
			local content = {}
			if #g_DeamxLog > 0 then
				table.insert(content, '// ================= DeAMX report =================\n')
				for _,entry in ipairs(g_DeamxLog) do
					table.insert(content, ('// [%s] %s\n'):format(entry.level, entry.msg))
				end
				table.insert(content, '// ===============================================\n\n')
			end
			table.insert(content, '#include <a_samp>\n#include <core>\n#include <float>\n\n')
			if globalsText then
				table.insert(content, globalsText)
			end
			for _,chunk in ipairs(output) do
				table.insert(content, chunk)
			end

			-- Safety net: some cell-address arithmetic is only fully visible
			-- after the statement has been assembled. Pawn has no pointer
			-- lvalues, so fold what we can and explicitly preserve anything
			-- that still cannot be represented instead of emitting invalid
			-- syntax silently.
			local function addCellOffset(suffix, step)
				if step == 0 then return suffix end
				local head, index = suffix:match('^(.-)%[(%d+)%]$')
				if head then
					return head .. '[' .. (tonumber(index) + step) .. ']'
				end
				return suffix .. '[' .. step .. ']'
			end

			local globalAddressByName = {}
			for address, global in pairs(amx.globalVars or {}) do
				if global[1] then globalAddressByName[global[1]] = address end
			end

			local function foldAddressExpressions(text)
				-- Normalise increment/decrement spelling first: the decompiler uses
				-- prefixes internally, but Pawn output reads better (and stays
				-- valid inside an index) as a postfix.
				text = text:gsub('++(%a[%w_%.]*)%+%+', '%1++')
				text = text:gsub('%-%-(%a[%w_%.]*)%-%-', '%1--')
				text = text:gsub('++(%a[%w_%.]*)([%s<>=+%-%*/%%)%,;])', '%1++%2')
				text = text:gsub('%-%-(%a[%w_%.]*)([%s<>=+%-%*/%%)%,;])', '%1--%2')
				text = text:gsub('(%b())%+%+', function(paren)
					if paren:find('<< 2', 1, true) then return paren end
					return paren .. '++'
				end)
				text = text:gsub('(%b())%-%-', function(paren)
					if paren:find('<< 2', 1, true) then return paren end
					return paren .. '--'
				end)

				-- `A[i] + (j << 2) + A[i][j]` is one cell, not three terms.
				text = text:gsub('(%w+)%[([^%]]+)%] %+ %(([^()]+) << 2%) %+ %1%[%2%]%[%3%]', '%1[%2][%3]')
				-- Same shape when the index itself contains a nested expression or
				-- function call: `32861900 + ((i - 1) << 2) + glob[(i - 1)]`.
				text = text:gsub('(%d+) %+ (%b()) %+ (%w+)%[(%b())%]', function(address, scaled, name, indexParen)
					local expression = scaled:sub(2, -2)
					local index = expression:match('^(.-)%s*<<%s*2$')
					if not index or index ~= indexParen then return nil end
					local number = tonumber(address)
					local known = globalAddressByName[name]
					if known and number == known then
						return name .. '[' .. index .. ']'
					end
					if number and number % 4 == 0 and (not known or number < 4096) then
						return name .. '[' .. index .. ']' .. addCellOffset('', idiv(number, 4))
					end
					return nil
				end)
				-- Numeric base address followed by a scaled index and its named
				-- row access: `11447760 + (i << 2) + glob[i]` -> `glob[i]`.
				text = text:gsub('(%d+) %+ %(([^()]+) << 2%) %+ (%w+)%[%2%]', function(address, index, name)
					local number = tonumber(address)
					local known = globalAddressByName[name]
					if known and number == known then
						return name .. '[' .. index .. ']'
					end
					if number and number % 4 == 0 and (not known or number < 4096) then
						return name .. '[' .. index .. ']' .. addCellOffset('', idiv(number, 4))
					end
					return nil
				end)
				-- Plain numeric global cell address plus a scaled index.
				text = text:gsub('(%d+) %+ %(([^()]+) << 2%)', function(address, index)
					local global = amx.globalVars[tonumber(address)]
					if global then return global[1] .. '[' .. index .. ']' end
					return nil
				end)
				-- A constant plus two spellings of the same cell base.
				text = text:gsub('(%d+) %+ (%w+%[[^%]]+%]) %+ %2', function(address, expression)
					local number = tonumber(address)
					if number and number % 4 == 0 then
						return expression .. addCellOffset('', idiv(number, 4))
					end
					return nil
				end)
				-- Remaining trailing scaled access: `A[i] + (j << 2)` -> `A[i][j]`.
				text = text:gsub('(%w+%[[^%]]+%]) %+ %(([^()]+) << 2%)', '%1[%2]')
				return text
			end

			local function sanitizeGeneratedSource(text)
				local lines = {}
				local unresolved = 0
				text = text:gsub('var(%d+)%.0', 'var%1'):gsub('arg(%d+)%.0', 'arg%1')
				for line in (text .. '\n'):gmatch('(.-)\n') do
					line = foldAddressExpressions(line)
					local indent, lhs, rhs = line:match('^(%s*)([^=;]-) = (.+;)%s*$')
					local rawLhs = line:match('^%s*([^=;]-) = ')
					local controlFlow = false
					if rawLhs then
						local head = rawLhs:match('^%s*%(?%s*([%a_]+)')
						controlFlow = head == 'if' or head == 'for' or head == 'while' or head == 'else' or head == 'return' or head == 'do' or head == 'switch'
					end
					if rawLhs and not controlFlow and (rawLhs:find('<<', 1, true) or rawLhs:match('^%s*%(')) then
						line = indent .. '// [DeAMX] unresolved address write: ' .. line:gsub('^%s+', '')
						unresolved = unresolved + 1
					elseif lhs and lhs:match('^[%w_%.%[]') and not lhs:find('[()]') then
						local fake = { lhs }
						normalizeAddressExpression(fake, amx)
						if fake[1] ~= lhs then
							line = indent .. fake[1] .. ' = ' .. rhs
						end
						if line:match('^%s*[%w_%.%[]+%s*%+[^=]-=') or line:find('%w[%w_%]] %+ [^;]- = ') or line:match('^%s*[^=]-<<[^=]-=') then
							line = indent .. '// [DeAMX] unresolved address write: ' .. line:gsub('^%s+', '')
							unresolved = unresolved + 1
						end
					end
					lines[#lines + 1] = line
				end
				if unresolved > 0 then
					print(('[DeAMX WARN] preserved %d unresolved address write(s) as comments'):format(unresolved))
				end
				return table.concat(lines, '\n')
			end

			-- Only write an output file if at least one function was
			-- recovered. Includes-only or totally failed runs leave no .pwn
			-- behind so the host application reports the reasons from
			-- g_DeamxLog instead of a file that cannot compile.
			if g_DeamxFnOk > 0 then
				local outFile = io.open(file:gsub('%.[aA][mM][xX]$', '.pwn'), 'w+')
				if outFile then
					outFile:write(sanitizeGeneratedSource(table.concat(content)))
					outFile:close()
				else
					dlog('error', 'could not write output file ' .. file:gsub('^.*/', ''))
				end
			end
		end
	end
end
