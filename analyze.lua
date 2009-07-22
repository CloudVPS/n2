-- DO NOT CUSTOMIZE THIS FILE
-- Extra code can be put in /etc/n2/analyzer-user.lua, which will be safe
-- from upgrades.
n2analyze = {}

-- Analyzes data for peaky behavior in the rtt
function netflutter (ctx,env)
	local avg = ctx.rtt.average()
	local count = ctx.rtt.countmin((avg * 1.5) + 8)
	if count > 8 then return true end
	return false
end

-- Looks for signs of bad hacks
function pwnage (ctx,env)
	local count = 0
	count = count + ctx.proc.pcount("nobody","perl",90)
	count = count + ctx.proc.pcount("apache","perl",90)
	count = count + ctx.proc.pcount("www-data","perl",90)
	count = count + ctx.proc.pcount("www","perl",90)
	if count > 24 then return true end
	return false
end

-- Detect a potential memory leak
function leak (ctx,env)
	local avg1, avg2, avg3, avg4
	avg1 = ctx.totalmem.average (600)
	avg2 = ctx.totalmem.average (600, 600)
	avg3 = ctx.totalmem.average (600, 1200)
	avg4 = ctx.totalmem.average (600, 1800)
	
	if avg1 < avg2 and avg2 < avg3 and avg3 < avg4 then return true end
	return false
end

-- Detect overall high loadaverage
function loadavg (ctx,env)
	if ctx.loadavg.average() > 4 then return true end
	return false
end

-- Detect peaky loadaverages
function loadpeak (ctx,env)
	if env.loadavg then return false end
	if ctx.loadavg.countmin(20) > 8 then return true end
	return false
end

-- Detect overall high diskio
function ioavg (ctx,env)
	if ctx.diskio.average() > 4000 then return true end
	return false
end

-- Detect peaky diskio not related to swap pressure
function iopeaks (ctx,env)
	if env.ioavg then return false end
	local count = 0
	ctx.diskio.loopmin(10000,
		function(sample)
			if sample.memfree > 64 then count = count + 1 end
		end)
	if count > 8 then return true end
	return false
end

-- Detect an overabundance of free RAM
function toomuchmem (ctx,env)
	if env.ioavg then return false end
	if ctx.memfree.countmax(2048) == 0 then return true end
	return false
end

-- Extra inspection on who's to blame for outofmemory/outofram.
function checkramculprits (ctx,env,loopvar,maxval)
	culprits = {}
	
	loopvar.loopmax(maxval,
		function(sample)
			for k,v in pairs(sample.procs) do
				if culprits[v.title] == nil then
					culprits[v.title] = 0
				end
				culprits[v.title] = culprits[v.title] + v.pmem
			end
		end)
	
	local maxtitle = ""
	local maxmem = 0
	
	for k,v in pairs(culprits) do
		if v > maxmem then
			maxmem = v
			maxtitle = k
		end
	end

	env.blamememory = maxtitle
end

-- Detect a complete memory blowout
function outofmemory (ctx,env)
	if env.toomuchmem then return false end
	if ctx.totalmem.countmax(64) < 4 then return false end
	checkramculprits(ctx, env, ctx.totalmem, 64)
	return true
end

-- See if we recently ran completely out of RAM
function outofram (ctx,env)
	if env.toomuchmem then return false end
	if env.outofmemory then return false end
	if ctx.memfree.countmax(32) < 5 then return false end
	checkramculprits(ctx, env, ctx.memfree, 32)
	return true
end

-- Determine a low absolute level of RAM
function lowram (ctx,env)
	if env.toomuchmem then return false end
	if env.outofram or env.outofmemory then return false end
	if ctx.memfree.countmax(64) > 500 then return true end
	return false
end

-- Detect irc-related madness
function ircbot (ctx,env)
	local count = 0
	count = count + ctx.proc.pcount("*","eggdrop",0)
	count = count + ctx.proc.pcount("*","psybnc",0)
	if count > 0 then return true end
	return false
end

-- Detect cpu-hogging php scripts
function phphog (ctx, env)
	local count = 0
	count = count + ctx.proc.pcount("*","php",60)
	count = count + ctx.proc.pcount("*","httpd",60)
	count = count + ctx.proc.pcount("*","apache",60)
	count = count + ctx.proc.pcount("*","apache2",60)
	if count > 32 then return true end
	return false
end

-- Determine cpu-hogging by mysql
function mysqlhog (ctx, env)
	if ctx.proc.pcount("*","mysql",80) > 60 then return true end
	return false
end

-- Determine other forms of cpu-hogging
function cpuhog (ctx, env)
	if env.phphog then return false end
	if env.pwnage then return false end
	if env.mysqlhog then return false end
	if ctx.cpu.average() < 70 then return false end
	
	culprits = {}

	ctx.cpu.loopmin(50,
		function (sample)
			for k,v in pairs(sample.procs) do
				if culprits[v.title] == nil then
					culprits[v.title] = 0
				end
				culprits[v.title] = culprits[v.title] + v.pcpu
			end
		end)

	local maxtitle = ""
	local maxcpu = 0
	
	for k,v in pairs(culprits) do
		if v > maxcpu then
			maxcpu = v
			maxtitle = k
		end
	end
	
	env.cpuhogger = maxtitle
	return true
end

function cpupeaks (ctx, env)
	if env.phphog then return false end
	if env.pwnage then return false end
	if env.mysqlhog then return false end
	if env.cpuhog then return false end
	
	if ctx.cpu.countmin (95) < 60 then return false end
	
	culprits = {}

	ctx.cpu.loopmin(95,
		function (sample)
			for k,v in pairs(sample.procs) do
				if culprits[v.title] == nil then
					culprits[v.title] = 0
				end
				culprits[v.title] = culprits[v.title] + v.pcpu
			end
		end)

	local maxtitle = ""
	local maxcpu = 0
	
	for k,v in pairs(culprits) do
		if v > maxcpu then
			maxcpu = v
			maxtitle = k
		end
	end
	
	env.cpuhogger = maxtitle
	return true
end

-- Report on lots of reboots in a day
function reboots (ctx,env)
	local count = ctx.uptime.countmax(120)
	if count > 6 then return true end
	return false
end

-- This will be called by n2analyze. The ctx structure is a lua
-- object with fields like rtt, loadavg, ram, swap, totalmem, proc
-- that have a number of magic functions under them:
--
--    average([count]): Obvious
--    max([count]): Duh
--    min([count]): Uhuh
--    countmin(x[,count]): Count number of times where value >= x
--    countmax(x[,count]): Count number of times where value <= x
--    correlate(otherval[,count]): Calculates a correlation co-efficient
--    loopmin(x,func[,count]): Call function for each sample where value >= x
--    loopmax(x,func[,count]): Call function for each sample where value <= x
--
-- The optional count argument assumes a default of 1440
-- Process functions that want to go completely mad can also use
-- ctx.loop(func[,count]) to just bluntly call a function for every sample
-- in the set. It's best to avoid doing this unless other analytic steps
-- have been used to make sure it is necessary.
-- 
-- The functions behind values can be 'lazy'. If we ever move to a
-- database-backed storage system, these can be implemented mostly as
-- queries. In our current setup, we will probably just load an array
-- array of 1440 n2stat records and calculate+cache the average, minimum
-- and maximum values whenever the need arises.
-- 
-- The result is used as an input for a web template that generates
-- a bit of static html for n2view to show in a tab.
function analyze (ctx)
	local f = loadfile ("/etc/n2/analyze-user.lua")
	if f ~= nil then f() end
	
	local res = {}
	res.netflutter = netflutter(ctx, res)
	res.pwnage = pwnage(ctx, res)
	res.leak = leak(ctx, res)
	res.loadavg = loadavg(ctx, res)
	res.loadpeak = loadpeak(ctx, res)
	res.ioavg = ioavg(ctx,res)
	res.iopeaks = iopeaks(ctx, res)
	res.toomuchmem = toomuchmem(ctx, res)
	res.outofmemory = outofmemory(ctx, res)
	res.outofram = outofram(ctx, res)
	res.lowram = lowram(ctx, res)
	res.ircbot = ircbot(ctx, res)
	res.phphog = phphog(ctx, res)
	res.mysqlhog = mysqlhog(ctx, res)
	res.cpuhog = cpuhog(ctx, res)
	res.cpupeaks = cpupeaks(ctx, res)
	res.reboots = reboots(ctx, res)

	if n2analyze ~= nil then	
		for k,v in pairs(n2analyze) do
			res[k] = v(ctx, res)
		end
	end
	
	return res
end
