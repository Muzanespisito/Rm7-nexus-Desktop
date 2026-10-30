const fs = require('node:fs');
const { readFile } = require('node:fs/promises');
const path = require('node:path');
const { LuaFactory } = require('wasmoon');

const DEAMX_DIR = path.join(__dirname, '../api/DeAmx');
const LUA_SOURCES = [
	'deamx.lua',
	'deamx_util.lua',
	'deamx_opcodes.lua',
	'deamx_events.lua',
	'deamx_syscalls.lua',
];

const TIMEOUT_MS = Number.parseInt(process.env.DEAMX_TIMEOUT_MS || '180000', 10) || 180 * 1000;

class DeAmxError extends Error {}

function withTimeout(promise, ms) {
	let timer;
	const timeout = new Promise((_, reject) => {
		timer = setTimeout(() => reject(new DeAmxError('Decompilation timed out (file too complex or malformed).')), ms);
	});
	return Promise.race([promise, timeout]).finally(() => clearTimeout(timer));
}

function clip(text, max) {
	text = String(text ?? '');
	return text.length > max ? `${text.slice(0, max)}...` : text;
}

function cleanLuaError(error) {
	const raw = String(error?.message ?? error).replace(/\s+/g, ' ').trim();
	// Strip wasmoon chunk prefixes like [string "/deamx.lua"]:123:
	return clip(raw.replace(/\[string "[^"]*"\]:\d+:\s*/g, ''), 300);
}

// Pull the diagnostics collected by deamx.lua (g_DeamxLog) out of the VM.
async function readLuaLog(lua) {
	try {
		const log = await lua.doString(`
			if type(g_DeamxLog) ~= 'table' then return '' end
			local parts = {}
			for _, entry in ipairs(g_DeamxLog) do
				parts[#parts + 1] = ('[%s] %s'):format(entry.level, entry.msg)
			end
			return table.concat(parts, '\\n')
		`);
		return typeof log === 'string' ? log : '';
	} catch {
		return '';
	}
}

async function decompileAmx(buffer, fileName = 'script.amx') {
	if (!Buffer.isBuffer(buffer) || buffer.length === 0) {
		throw new DeAmxError('Empty or unreadable file.');
	}

	const baseName = path
		.basename(fileName || 'script.amx')
		.replace(/\.[^.]*$/, '')
		.replace(/[^A-Za-z0-9_-]/g, '_')
		.slice(0, 64) || 'script';

	const inputPath = `/${baseName}_in.amx`;
	const outputPath = `/${baseName}_in.pwn`;

	// On Vercel the wasmoon wasm is bundled inside api/glue.wasm (copied from
	// node_modules/wasmoon/dist/glue.wasm). Passing an explicit path avoids
	// the ENOENT at /var/task/node_modules/wasmoon/dist/glue.wasm.
	const bundledWasm = path.join(__dirname, "../api/glue.wasm");
	const factory = fs.existsSync(bundledWasm)
		? new LuaFactory(bundledWasm)
		: new LuaFactory();
	await factory.mountFile(inputPath, buffer);
	for (const file of LUA_SOURCES) {
		await factory.mountFile(`/${file}`, await readFile(path.join(DEAMX_DIR, file)));
	}

	const lua = await factory.createEngine();

	async function run() {
		lua.global.set('DEAMX_INPUT', inputPath);

		// Compatibility shims: DeAMX targets Lua 5.1 ("unpack"), while the embedded VM is 5.4.
		// Also make loadfile() resolve scripts mounted at the virtual root ("/deamx_util.lua", ...).
		await lua.doString(
			`
			unpack = unpack or table.unpack
			package.path = '/?.lua;' .. package.path
			arg = { [0] = 'deamx.lua', DEAMX_INPUT }
			`,
		);

		try {
			await lua.doFile('/deamx.lua');
		} catch (error) {
			const log = await readLuaLog(lua);
			const reason = log ? ` Reason: ${clip(log, 500)}` : '';
			throw new DeAmxError(`The decompiler crashed while processing this file: ${cleanLuaError(error)}.${reason}`);
		}

		let source;
		try {
			source = await lua.doString(`
				local f = assert(io.open(DEAMX_OUTPUT, 'rb'))
				local data = f:read('*a')
				f:close()
				return data
			`);
		} catch {
			// No output file: the decompiler refused the input. The Lua-side
			// diagnostics log holds the actual reason(s).
			const log = await readLuaLog(lua);
			throw new DeAmxError(log ? `Could not decompile this .amx.\n${clip(log, 800)}` : 'Not a valid .amx file (missing or corrupt AMX header).');
		}

		if (!source || source.length === 0) {
			const log = await readLuaLog(lua);
			throw new DeAmxError(log ? clip(log, 800) : 'The decompiler produced empty output.');
		}

		return {
			name: `${baseName}.pwn`,
			source,
			failCount: Number(lua.global.get('g_DeamxFnFail')) || 0,
			log: await readLuaLog(lua),
		};
	}

	lua.global.set('DEAMX_OUTPUT', outputPath);
	return withTimeout(run(), TIMEOUT_MS);
}

module.exports = { decompileAmx, DeAmxError };
