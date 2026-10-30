local capture = __capture
local capture_metadata = __capture_metadata
local now_ms = __now_ms
local max_requests = tonumber(__max_requests) or 200
local max_body = tonumber(__max_body) or 8192
local lua_budget_ms = tonumber(__rm7_lua_budget_ms) or 2500
local event_budget_ms = tonumber(__rm7_event_budget_ms) or 500
local simulation_budget_ms = tonumber(__rm7_simulation_budget_ms) or 3000
local max_instructions = tonumber(__rm7_max_instructions) or 5000000
local max_wait_calls = tonumber(__rm7_max_wait_calls) or 400
local max_virtual_ms = tonumber(__rm7_max_virtual_ms) or 5000
local read_local_module = __rm7_read_module
local local_module_error = __rm7_module_error
__capture = nil
__capture_metadata = nil
__now_ms = nil
__max_requests = nil
__max_body = nil
__rm7_lua_budget_ms = nil
__rm7_event_budget_ms = nil
__rm7_simulation_budget_ms = nil
__rm7_max_instructions = nil
__rm7_max_wait_calls = nil
__rm7_max_virtual_ms = nil
__rm7_read_module = nil
__rm7_module_error = nil

local _pcall = pcall
local _type = type
local _tostring = tostring
local _tonumber = tonumber
local _next = next
local _string = string
local _math = math
local _table = table
local _select = select
local _error = error
local _debug = debug
local _os_clock = os.clock

local OBSERVATION_WINDOW = "__rm7_observation_window__"
local INSTRUCTION_LIMIT = "__rm7_instruction_limit__"
local LUA_TIMEOUT = "__rm7_lua_timeout__"
local HOOK_INTERVAL = 10000

local active_phase = nil

local function clock_ms()
  if _type(now_ms) == "function" then
    local ok, value = _pcall(now_ms)
    if ok and _type(value) == "number" then return value end
  end
  return _math.floor((_os_clock or os.clock)() * 1000)
end

local function reason_for(err)
  if err == OBSERVATION_WINDOW then return "observation_window" end
  if err == INSTRUCTION_LIMIT then return "instruction_limit" end
  if err == LUA_TIMEOUT then return "lua_timeout" end
  return "error"
end

local function guarded_call(callback, deadline, instruction_limit, ...)
  local phase = {
    deadline = deadline,
    waits = 0,
    virtual_ms = 0,
    max_waits = max_wait_calls,
    max_virtual_ms = max_virtual_ms,
    ticks = 0,
    max_ticks = _math.max(1, _math.floor(instruction_limit / HOOK_INTERVAL))
  }
  active_phase = phase
  local function hook()
    phase.ticks = phase.ticks + 1
    if phase.ticks > phase.max_ticks then
      _error(INSTRUCTION_LIMIT, 0)
    end
    if phase.ticks % 4 == 0 and clock_ms() >= phase.deadline then
      _error(LUA_TIMEOUT, 0)
    end
  end
  if _debug and _debug.sethook then
    _pcall(_debug.sethook, hook, "", HOOK_INTERVAL)
  end
  local ok, err = _pcall(callback, ...)
  if _debug and _debug.sethook then
    _pcall(_debug.sethook)
  end
  active_phase = nil
  return ok, err
end

local function wait_impl(milliseconds)
  local phase = active_phase
  if not phase then return end
  phase.waits = phase.waits + 1
  local delay = _tonumber(milliseconds) or 0
  if delay > 0 then phase.virtual_ms = phase.virtual_ms + delay end
  if phase.waits >= phase.max_waits or phase.virtual_ms >= phase.max_virtual_ms or clock_ms() >= phase.deadline then
    _error(OBSERVATION_WINDOW, 0)
  end
end


local captured = 0
local truncated = false

local function safe_string(value, limit)
  local ok, text = _pcall(_tostring, value)
  if not ok then return "" end
  text = _string.gsub(text, "[\r\n\t]", " ")
  if #text > limit then
    text = _string.sub(text, 1, limit)
  end
  return text
end

local function safe_table(value, depth, limit)
  if depth > 4 then return "[depth]" end
  local per_value = _math.min(limit, 2048)
  local out = {}
  local count = 0
  local key, item = _next(value)
  while key ~= nil do
    count = count + 1
    if count > 80 then
      out[#out + 1] = "\"...\":\"[truncated]\""
      break
    end
    local k = safe_string(key, 80)
    local v
    local kind = _type(item)
    if kind == "table" then
      v = safe_table(item, depth + 1, per_value)
    elseif kind == "string" or kind == "number" or kind == "boolean" then
      v = safe_string(item, per_value)
    else
      v = "[" .. kind .. "]"
    end
    out[#out + 1] = _string.format("%q:%q", k, v)
    key, item = _next(value, key)
  end
  local text = "{" .. _table.concat(out, ",") .. "}"
  if #text > per_value then
    text = _string.sub(text, 1, per_value)
  end
  return text
end

local metadata = {}

local function metadata_value(value)
  local kind = _type(value)
  if kind == "table" then
    return safe_table(value, 0, 1000)
  end
  if kind == "string" or kind == "number" or kind == "boolean" then
    return safe_string(value, 500)
  end
  return nil
end

local function record_metadata(key, ...)
  local parts = {}
  for index = 1, _select("#", ...) do
    local item = metadata_value(_select(index, ...))
    if item ~= nil then parts[#parts + 1] = item end
  end
  local text = _table.concat(parts, ", ")
  metadata[key] = text
  if _type(capture_metadata) == "function" then
    _pcall(capture_metadata, key, text)
  end
  return true
end

local function metadata_function(key)
  return function(...)
    if _select("#", ...) == 0 then return metadata[key] end
    return record_metadata(key, ...)
  end
end

for _, name in ipairs({
  "script_name",
  "script_author",
  "script_authors",
  "script_version",
  "script_version_number",
  "script_description",
  "script_moonloader",
  "script_dependencies",
  "script_url",
  "script_properties"
}) do
  _G[name] = metadata_function(name)
end

local function json_escape(value)
  local text = _string.gsub(_tostring(value), "[%c\\\"]", function(ch)
    if ch == '"' then return '\\"' end
    if ch == "\\" then return "\\\\" end
    if ch == "\b" then return "\\b" end
    if ch == "\f" then return "\\f" end
    if ch == "\n" then return "\\n" end
    if ch == "\r" then return "\\r" end
    if ch == "\t" then return "\\t" end
    return _string.format("\\u%04x", _string.byte(ch))
  end)
  return '"' .. text .. '"'
end

local function encode_json(value, seen, depth)
  depth = depth or 0
  seen = seen or {}
  if depth > 8 then return '"[depth]"' end
  local kind = _type(value)
  if value == nil then return "null" end
  if kind == "boolean" then return value and "true" or "false" end
  if kind == "number" then
    if value ~= value or value == _math.huge or value == -_math.huge then return "null" end
    return _tostring(value)
  end
  if kind == "string" then return json_escape(value) end
  if kind ~= "table" then return "null" end
  if seen[value] then return '"[cycle]"' end
  seen[value] = true
  local max_key = 0
  local count = 0
  local is_array = true
  for key in _next, value do
    count = count + 1
    if _type(key) ~= "number" or key < 1 or key % 1 ~= 0 then
      is_array = false
    elseif key > max_key then
      max_key = key
    end
  end
  local out = {}
  if is_array and count == max_key then
    for index = 1, max_key do
      out[#out + 1] = encode_json(value[index], seen, depth + 1)
    end
    seen[value] = nil
    return "[" .. _table.concat(out, ",") .. "]"
  end
  local keys = {}
  for key in _next, value do
    if _type(key) == "string" or _type(key) == "number" then keys[#keys + 1] = key end
  end
  _table.sort(keys, function(a, b) return _tostring(a) < _tostring(b) end)
  for _, key in ipairs(keys) do
    out[#out + 1] = json_escape(_tostring(key)) .. ":" .. encode_json(value[key], seen, depth + 1)
  end
  seen[value] = nil
  return "{" .. _table.concat(out, ",") .. "}"
end

local function body_text(value)
  if value == nil then return nil end
  local kind = _type(value)
  if kind == "table" then
    local text = safe_table(value, 0, max_body)
    if #text >= max_body then truncated = true end
    return text
  end
  if kind == "function" then
    local ok, result = _pcall(value)
    if ok and result ~= nil then return body_text(result) end
    return nil
  end
  if kind ~= "string" and kind ~= "number" and kind ~= "boolean" then return nil end
  local text = safe_string(value, max_body + 1)
  if #text > max_body then
    truncated = true
    return _string.sub(text, 1, max_body)
  end
  return text
end

local function headers_text(value)
  if _type(value) ~= "table" then return {} end
  local out = {}
  local count = 0
  local key, item = _next(value)
  while key ~= nil and count < 20 do
    if _type(key) == "string" and _type(item) ~= "table" and _type(item) ~= "function" then
      out[safe_string(key, 100)] = safe_string(item, 600)
    end
    count = count + 1
    key, item = _next(value, key)
  end
  return out
end

local current_event = nil

local function lua_caller()
  if not _debug or not _debug.getinfo then return nil end
  for level = 2, 8 do
    local ok, info = _pcall(_debug.getinfo, level, "Sn")
    if not ok or not info then break end
    local source = _tostring(info.source or info.short_src or "")
    local is_prelude = _string.find(source, "local capture = __capture", 1, true) ~= nil
    if not is_prelude and source ~= "=[C]" then
      if info.name then return safe_string(info.name, 120) end
      return "<top-level>"
    end
  end
  return nil
end

local function record(method, url, body, headers, api)
  if captured >= max_requests then
    truncated = true
    return
  end
  captured = captured + 1
  local entry = {
    method = safe_string(method or "GET", 16),
    url = safe_string(url or "", 4000),
    body = body_text(body),
    headers = headers_text(headers),
    api = safe_string(api or "unknown", 80),
    source = lua_caller(),
    event = current_event,
    intercepted = true,
    blocked = true,
    sent = false
  }
  _pcall(capture, entry)
end

local function arg_url(value)
  if _type(value) == "table" then
    return value.url or value[1] or value.link or value.address
  end
  return value
end

local function arg_body(value)
  if _type(value) == "table" then
    if value.__rm7_body ~= nil then return value.__rm7_body end
    return value.source or value.body or value.data or value.json or value[2]
  end
  return value
end

local function is_method(value)
  if _type(value) ~= "string" then return false end
  local upper = _string.upper(value)
  return upper == "GET" or upper == "POST" or upper == "PUT" or upper == "PATCH" or
    upper == "DELETE" or upper == "HEAD" or upper == "OPTIONS"
end

local response_headers = { ["content-type"] = "text/plain", ["content-length"] = "0" }
local response_body = ""

local function request(method, url, body, headers, api)
  record(method, url, body, headers, api)
  if _string.upper(method or "GET") == "HEAD" then
    return 1, 200, response_headers, ""
  end
  return 1, 200, response_headers, response_body
end

local function flexible_request(api, default_method)
  return function(a, b, c, d)
    local url, body, headers, method
    if _type(a) == "table" then
      url = arg_url(a)
      body = arg_body(a)
      headers = a.headers
      method = a.method
    else
      url = a
      if is_method(b) then
        method = b
        body = c
        headers = d
      else
        body = b
        headers = c
      end
    end
    method = _string.upper(method or default_method or (body ~= nil and "POST" or "GET"))
    return request(method, url, body, headers, api)
  end
end

local http = {}
http.request = flexible_request("http.request", nil)
http.get = flexible_request("http.get", "GET")
http.post = flexible_request("http.post", "POST")
http.put = flexible_request("http.put", "PUT")
http.patch = flexible_request("http.patch", "PATCH")
http.delete = flexible_request("http.delete", "DELETE")

local socket = {}
socket.http = {}
socket.http.request = flexible_request("socket.http.request", nil)
socket.http.get = flexible_request("socket.http.get", "GET")
socket.http.request_uri = function(url, body, headers)
  return flexible_request("socket.http.request_uri", nil)(url, body, headers)
end
socket.http.generic_request = function(url, method, body, headers)
  return request(method, url, body, headers, "socket.http.generic_request")
end

local client = {}
function client:send(data) record("POST", self.url, data, nil, "socket.send"); return 1 end
function client:receive() return nil end
function client:close() return 1 end
function client:settimeout() return 1 end
function socket.connect(host, port)
  local url = "tcp://" .. safe_string(host, 255) .. ":" .. safe_string(port or 0, 8)
  record("CONNECT", url, nil, nil, "socket.connect")
  return { url = url, send = client.send, receive = client.receive, close = client.close, settimeout = client.settimeout }
end
socket.tcp = socket
socket.tcp.connect = socket.connect
socket.skip = function() end

local ssl = {}
ssl.https = {}
ssl.https.request = flexible_request("ssl.https.request", nil)
ssl.https.generic_request = socket.http.generic_request
ssl.https.request_uri = socket.http.request_uri

local function response_table(url)
  local response = {
    status = 200,
    status_code = 200,
    statusCode = 200,
    responseCode = 200,
    ok = true,
    success = true,
    body = response_body,
    text = response_body,
    responseText = response_body,
    headers = response_headers,
    json = function() return {} end,
    raise_for_status = function() return true end
  }
  if url ~= nil then response.url = url; response.request_url = url end
  return response
end

local function requests_parts(first, second, third)
  if _type(first) == "table" then
    return arg_url(first), arg_body(first), first.headers
  end
  if third ~= nil then
    return first, third, second
  end
  if _type(second) == "table" then
    return first, arg_body(second), second.headers
  end
  return first, second, nil
end

local function requests_call(method, api, first, second, third)
  local url, body, headers = requests_parts(first, second, third)
  record(method, url, body, headers, api)
  return response_table(url)
end

local requests = {}
requests.request = function(method, url, options)
  if _type(method) == "table" then
    return requests_call(_string.upper(method.method or "GET"), "requests.request", method)
  end
  if _type(url) == "table" then
    return requests_call(_string.upper(method or "GET"), "requests.request", url)
  end
  return requests_call(_string.upper(method or "GET"), "requests.request", url, options)
end
requests.get = function(first, second, third) return requests_call("GET", "requests.get", first, second, third) end
requests.post = function(first, second, third) return requests_call("POST", "requests.post", first, second, third) end
requests.put = function(first, second, third) return requests_call("PUT", "requests.put", first, second, third) end
requests.patch = function(first, second, third) return requests_call("PATCH", "requests.patch", first, second, third) end
requests.delete = function(first, second, third) return requests_call("DELETE", "requests.delete", first, second, third) end

local http_module = http

local function safe_callback(callback, status, body, headers)
  if _type(callback) == "function" then
    _pcall(callback, status or 200, body or "", headers or response_headers)
  end
end

local function perform_http(url, callback, method, data, headers)
  record(method or "GET", url, data, headers, "performHttpRequest")
  safe_callback(callback, 200, "", response_headers)
  return { status = 200, statusCode = 200, responseCode = 200, success = true, request_url = url }
end

local function create_http_request(method, url, callback)
  local obj = { method = method or "GET", url = url, headers = {}, callback = callback }
  function obj:SetHeader(key, value) self.headers[key] = value end
  function obj:Send(data)
    record(self.method, self.url, data, self.headers, "CreateHttpRequest")
    safe_callback(self.callback, 200, "", response_headers)
    return true
  end
  function obj:SetData(data) self.data = data end
  function obj:SendSync(data) return self:Send(data) end
  return obj
end

local function download_url(url, path)
  record("GET", url, nil, nil, "downloadUrlToFile")
  return true
end

local monet = {}
monet.httpRequest = flexible_request("monet.httpRequest", nil)
monet.request = flexible_request("monet.request", nil)
monet.downloadUrlToFile = download_url

local function noop() return true end
local function false_value() return false end
local function nil_value() return nil end
local function zero_value() return 0 end
local function three_zeros() return 0, 0, 0 end

local moonloader = {}
local this_script = {
  load = noop,
  name = function() return "grab-detector" end,
  path = function() return "" end,
  filename = function() return "script.lua" end,
  log = function() end,
  registry = { read = nil_value, write = noop }
}
moonloader.script = this_script
moonloader.print = function() end
moonloader.log = function() end
moonloader.getGameVersion = zero_value
moonloader.isSampLoaded = function() return true end
moonloader.isSampfuncsLoaded = function() return true end
moonloader.find_pattern = nil_value
moonloader.registerEvent = noop
moonloader.createThread = noop

local samp

local event_handlers = {}
local event_current = {}

local function register_event(name, callback)
  if _type(name) ~= "string" or _type(callback) ~= "function" then return end
  local list = event_handlers[name]
  if not list then
    list = {}
    event_handlers[name] = list
  end
  local previous = event_current[name]
  if previous ~= nil then
    for index = #list, 1, -1 do
      if list[index] == previous then _table.remove(list, index) end
    end
  end
  list[#list + 1] = callback
  event_current[name] = callback
end

samp = { events = setmetatable({}, {
  __newindex = function(_, name, callback)
    register_event(name, callback)
  end,
  __index = function(_, name)
    return event_current[name]
  end
}), funcs = {} }
local monetloader = { httpRequest = monet.httpRequest }

local vkeys = {
  VK_LBUTTON = 1, VK_RBUTTON = 2, VK_CANCEL = 3, VK_MBUTTON = 4,
  VK_BACK = 8, VK_TAB = 9, VK_RETURN = 13, VK_SHIFT = 16,
  VK_CONTROL = 17, VK_MENU = 18, VK_PAUSE = 19, VK_ESCAPE = 27,
  VK_SPACE = 32, VK_PRIOR = 33, VK_NEXT = 34, VK_END = 35,
  VK_HOME = 36, VK_LEFT = 37, VK_UP = 38, VK_RIGHT = 39, VK_DOWN = 40,
  VK_INSERT = 45, VK_DELETE = 46, VK_F1 = 112, VK_F2 = 113, VK_F3 = 114,
  VK_F4 = 115, VK_F5 = 116, VK_F6 = 117, VK_F7 = 118, VK_F8 = 119,
  VK_F9 = 120, VK_F10 = 121, VK_F11 = 122, VK_F12 = 123
}

local encoding = { default = "UTF-8", UTF8 = "UTF-8", ANSI = "ANSI" }
encoding.convert = function(value) return value end

local function bit_u32(value)
  return (_tonumber(value) or 0) % 4294967296
end
local function bit_tobit(value)
  local number = (_tonumber(value) or 0) % 4294967296
  if number >= 2147483648 then number = number - 4294967296 end
  return _math.floor(number)
end
local bit = {}
bit.tobit = bit_tobit
bit.band = function(...)
  local result = 0xffffffff
  for index = 1, _select("#", ...) do
    result = result & bit_u32(_select(index, ...))
  end
  return bit_tobit(result)
end
bit.bor = function(...)
  local result = 0
  for index = 1, _select("#", ...) do
    result = result | bit_u32(_select(index, ...))
  end
  return bit_tobit(result)
end
bit.bxor = function(...)
  local result = 0
  for index = 1, _select("#", ...) do
    result = result ~ bit_u32(_select(index, ...))
  end
  return bit_tobit(result)
end
bit.bnot = function(value) return bit_tobit(~bit_u32(value)) end
bit.lshift = function(value, shift)
  local amount = (_tonumber(shift) or 0) % 32
  return bit_tobit(bit_u32(value) << amount)
end
bit.rshift = function(value, shift)
  local amount = (_tonumber(shift) or 0) % 32
  return bit_tobit(bit_u32(value) >> amount)
end
bit.arshift = function(value, shift)
  local amount = (_tonumber(shift) or 0) % 32
  local signed = bit_tobit(value)
  if amount == 0 then return signed end
  if signed >= 0 then return bit_tobit(signed >> amount) end
  local result = (bit_u32(signed) >> amount) | (0xffffffff << (32 - amount))
  return bit_tobit(result)
end
bit.rol = function(value, shift)
  local amount = (_tonumber(shift) or 0) % 32
  if amount == 0 then return bit_tobit(value) end
  return bit_tobit((bit_u32(value) << amount) | (bit_u32(value) >> (32 - amount)))
end
bit.ror = function(value, shift)
  local amount = (_tonumber(shift) or 0) % 32
  if amount == 0 then return bit_tobit(value) end
  return bit_tobit((bit_u32(value) >> amount) | (bit_u32(value) << (32 - amount)))
end
bit.bswap = function(value)
  local number = bit_u32(value)
  local a = number % 256
  local b = _math.floor(number / 256) % 256
  local c = _math.floor(number / 65536) % 256
  local d = _math.floor(number / 16777216) % 256
  return bit_tobit(a * 16777216 + b * 65536 + c * 256 + d)
end
bit.tohex = function(value, digits)
  local text = _string.format("%08x", bit_u32(value))
  local width = _tonumber(digits)
  if width and width ~= 0 then
    local count = _math.min(8, _math.abs(width))
    if width > 0 then text = _string.sub(text, 9 - count)
    else text = _string.upper(_string.sub(text, 1, count)) end
  end
  return text
end

local memory = {
  read = function() return 0 end,
  write = noop,
  allocate = zero_value,
  free = noop,
  getInt32 = zero_value,
  setInt32 = noop,
  getFloat = zero_value,
  setFloat = noop
}

local json = {
  decode = nil_value,
  encode = function(value)
    local ok, encoded = _pcall(encode_json, value)
    if ok then return encoded end
    return "{}"
  end
}

local b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local function b64_encode(value)
  local data = _tostring(value)
  local out = {}
  local index = 1
  while index <= #data do
    local a, b, c = _string.byte(data, index, index + 2)
    local n = (a or 0) * 65536 + (b or 0) * 256 + (c or 0)
    local c1 = _math.floor(n / 262144) % 64
    local c2 = _math.floor(n / 4096) % 64
    local c3 = b and _math.floor(n / 64) % 64 or 64
    local c4 = c and n % 64 or 64
    out[#out + 1] = _string.sub(b64chars, c1 + 1, c1 + 1)
    out[#out + 1] = _string.sub(b64chars, c2 + 1, c2 + 1)
    out[#out + 1] = c3 == 64 and "=" or _string.sub(b64chars, c3 + 1, c3 + 1)
    out[#out + 1] = c4 == 64 and "=" or _string.sub(b64chars, c4 + 1, c4 + 1)
    index = index + 3
  end
  return _table.concat(out)
end
local function b64_decode(value)
  local data = _string.gsub(_tostring(value), "[^" .. b64chars .. "=]", "")
  local out = {}
  for pos = 1, #data, 4 do
    local chunk = _string.sub(data, pos, pos + 3)
    if #chunk == 4 then
      local a = _string.find(b64chars, _string.sub(chunk, 1, 1), 1, true) or 1
      local b = _string.find(b64chars, _string.sub(chunk, 2, 2), 1, true) or 1
      local c = _string.find(b64chars, _string.sub(chunk, 3, 3), 1, true)
      local d = _string.find(b64chars, _string.sub(chunk, 4, 4), 1, true)
      local n = (a - 1) * 262144 + (b - 1) * 4096 + ((c or 1) - 1) * 64 + ((d or 1) - 1)
      out[#out + 1] = _string.char(_math.floor(n / 65536) % 256)
      if c then out[#out + 1] = _string.char(_math.floor(n / 256) % 256) end
      if d then out[#out + 1] = _string.char(n % 256) end
    end
  end
  return _table.concat(out)
end
local base64 = { encode = b64_encode, decode = b64_decode, url_encode = b64_encode, url_decode = b64_decode }

local function url_escape(text)
  local value = _tostring(text or "")
  return _string.gsub(value, "([^%w%-%.%_%~])", function(ch)
    return _string.format("%%%02X", _string.byte(ch))
  end)
end

local function url_unescape(text)
  local value = _tostring(text or "")
  return _string.gsub(value, "+", " ")
end

local socket_url = {
  escape = url_escape,
  unescape = url_unescape,
  build = function(parts)
    if _type(parts) ~= "table" then return "" end
    local scheme = parts.scheme and (parts.scheme .. "://") or ""
    local host = parts.host or ""
    local path = parts.path or ""
    local query = parts.query and ("?" .. tostring(parts.query)) or ""
    local fragment = parts.fragment and ("#" .. tostring(parts.fragment)) or ""
    return scheme .. host .. path .. query .. fragment
  end,
  parse = function(raw)
    local text = _tostring(raw or "")
    local scheme, rest = _string.match(text, "^([a-zA-Z]+)://(.+)$")
    local host = rest or text
    local path = ""
    local query = ""
    local fragment = ""
    if rest then
      local target = rest
      local hash_pos = _string.find(target, "#", 1, true)
      if hash_pos then
        fragment = _string.sub(target, hash_pos + 1)
        target = _string.sub(target, 1, hash_pos - 1)
      end
      local query_pos = _string.find(target, "?", 1, true)
      if query_pos then
        path = _string.sub(target, 1, query_pos - 1)
        query = _string.sub(target, query_pos + 1)
      else
        path = target
      end
      host = _string.match(path, "^([^/]+)") or host
      path = _string.sub(path, #host + 1)
    end
    return {
      scheme = scheme,
      host = host,
      path = path,
      query = query,
      fragment = fragment,
      authority = host,
    }
  end,
  absolute = function(base, relative)
    if relative == nil or relative == "" then return _tostring(base or "") end
    return _tostring(base or "") .. _tostring(relative)
  end,
}

local ltn12 = {
  source = {
    string = function(value)
      return { kind = "string", value = _tostring(value or "") }
    end,
    file = function(value)
      return { kind = "file", value = _tostring(value or "") }
    end,
  },
  sink = {
    table = function(target)
      target = target or {}
      return function(chunk)
        if chunk ~= nil then
          target[#target + 1] = chunk
        end
        return 1
      end
    end,
    file = function()
      return function(chunk)
        return chunk == nil and 0 or #_tostring(chunk)
      end
    end,
  },
  filter = {
    chain = function(...)
      local filters = { ... }
      return function(chunk)
        local value = chunk
        for _, filter in ipairs(filters) do
          if _type(filter) == "function" then
            value = filter(value)
          end
        end
        return value
      end
    end,
  },
}

local mime = {
  b64 = base64.encode,
  unb64 = base64.decode,
  encode = base64.encode,
  decode = base64.decode,
  version = "compat",
}

local socket_headers = {
  new = function() return {} end,
  canonic = function(value)
    local text = _tostring(value or "")
    if text == "" then return text end
    return _string.gsub(text, "^(%w)", function(ch) return _string.upper(ch) end)
  end,
  from_table = function(value) return value or {} end,
  to_table = function(value) return value or {} end,
}

local function bit32_table()
  local table32 = {}
  for key, value in pairs(bit) do
    table32[key] = value
  end
  table32.bxor = bit.bxor
  table32.bor = bit.bor
  table32.band = bit.band
  table32.bnot = bit.bnot
  table32.lshift = bit.lshift
  table32.rshift = bit.rshift
  table32.arshift = bit.arshift
  table32.rol = bit.rol
  table32.ror = bit.ror
  table32.bswap = bit.bswap
  table32.tohex = bit.tohex
  table32.extract = function(value, offset, width)
    local total = bit_u32(value)
    local start = (_tonumber(offset) or 0) % 32
    local count = _tonumber(width) or 1
    if count <= 0 then return 0 end
    local mask = (1 << _math.min(31, count)) - 1
    return (total >> start) & mask
  end
  table32.replace = function(value, replace, offset, width)
    local total = bit_u32(value)
    local start = (_tonumber(offset) or 0) % 32
    local count = _tonumber(width) or 1
    local mask = ((1 << _math.min(31, count)) - 1) << start
    return bit_tobit((total & (~mask)) | ((bit_u32(replace) & ((1 << _math.min(31, count)) - 1)) << start))
  end
  return table32
end

local bit32 = bit32_table()

local xml = {
  load = function(value)
    return {
      text = _tostring(value or ""),
      find = function(self, pattern)
        return _string.find(self.text, pattern)
      end,
    }
  end,
}

local cjson = {
  encode = json.encode,
  decode = function(value)
    local text = _tostring(value or "")
    if text == "" then return nil end
    local ok, result = _pcall(function()
      return load("return " .. text, "@json", "t", {})()
    end)
    if ok then return result end
    return nil
  end,
  safe = {
    encode = json.encode,
    decode = function(value)
      local text = _tostring(value or "")
      if text == "" then return nil end
      local ok, result = _pcall(function()
        return load("return " .. text, "@json.safe", "t", {})()
      end)
      if ok then return result end
      return nil
    end,
  },
}

local md5 = {
  sumhexa = function(value)
    return "md5:" .. _string.gsub(_tostring(value or ""), "[\r\n]", "")
  end,
}

local modules = {
  ["socket"] = socket,
  ["socket.http"] = socket.http,
  ["socket.url"] = socket_url,
  ["socket.headers"] = socket_headers,
  ["ssl"] = ssl,
  ["ssl.https"] = ssl.https,
  ["ssl.core"] = ssl,
  ["ssl.context"] = ssl,
  ["ssl.x509"] = ssl,
  ["ltn12"] = ltn12,
  ["http"] = http_module,
  ["requests"] = requests,
  ["moonloader"] = moonloader,
  ["lib.moonloader"] = moonloader,
  ["samp.events"] = samp.events,
  ["lib.samp.events"] = samp.events,
  ["sampfuncs"] = samp.funcs,
  ["monet"] = monet,
  ["monetloader"] = monetloader,
  ["vkeys"] = vkeys,
  ["encoding"] = encoding,
  ["memory"] = memory,
  ["bit32"] = bit32,
  ["json"] = json,
  ["bit"] = bit,
  ["base64"] = base64,
  ["mime"] = mime,
  ["mime.core"] = mime,
  ["lfs"] = { attributes = function() return nil end, currentdir = function() return "." end, mkdir = function() return true end, rmdir = function() return true end },
  ["cjson"] = cjson,
  ["cjson.safe"] = cjson.safe,
  ["xml"] = xml,
  ["md5"] = md5,
}

local loaded = {}
function require(name)
  if _type(name) ~= "string" then
    _error("bad argument #1 to 'require' (string expected)", 2)
  end
  name = safe_string(name, 120)
  if modules[name] ~= nil then
    loaded[name] = modules[name]
    return modules[name]
  end
  if loaded[name] ~= nil then return loaded[name] end
  local source = _type(read_local_module) == "function" and read_local_module(name) or nil
  if _type(source) ~= "string" then
    local detail = _type(local_module_error) == "function" and local_module_error(name) or "module was not found"
    _error("module '" .. name .. "' not found: " .. safe_string(detail, 200), 2)
  end
  local chunk, compile_error = load(source, "@local-libraries/" .. name .. ".lua", "t", _G)
  if not chunk then
    _error("module '" .. name .. "' compile error: " .. safe_string(compile_error, 200), 2)
  end
  loaded[name] = true
  local ok, result = _pcall(chunk)
  if not ok then
    loaded[name] = nil
    _error("module '" .. name .. "' failed: " .. safe_string(result, 200), 2)
  end
  if result ~= nil then loaded[name] = result end
  return loaded[name]
end

local function environment_upvalue(fn)
  if _type(fn) ~= "function" or not _debug or not _debug.getupvalue then return nil end
  for index = 1, 64 do
    local ok, name, value = _pcall(_debug.getupvalue, fn, index)
    if not ok or name == nil then break end
    if name == "_ENV" then return index, value end
  end
  return nil
end

function getfenv(fn)
  if fn == nil or fn == 0 or _type(fn) == "number" then return _G end
  local _, environment = environment_upvalue(fn)
  return environment or _G
end

function setfenv(fn, environment)
  if _type(environment) ~= "table" then
    _error("bad argument #2 to 'setfenv' (table expected)")
  end
  if _type(fn) == "number" then return fn end
  if _type(fn) ~= "function" then
    _error("bad argument #1 to 'setfenv' (function or level expected)")
  end
  local index = environment_upvalue(fn)
  if not index then return fn end
  if index == 1 and _string.dump and _debug and _debug.upvaluejoin then
    local ok, dumped = _pcall(_string.dump, fn)
    if ok and _type(dumped) == "string" then
      local loaded = load(dumped, "=setfenv", "b", environment)
      if loaded then
        local upvalue = 2
        while true do
          local has, name = _pcall(_debug.getupvalue, fn, upvalue)
          if not has or name == nil then break end
          _pcall(_debug.upvaluejoin, loaded, upvalue, fn, upvalue)
          upvalue = upvalue + 1
        end
        return loaded
      end
    end
  end
  return fn
end

function newproxy(proxy)
  local object = {}
  if proxy ~= nil and proxy ~= false then
    local metatable = getmetatable(proxy)
    if _type(metatable) == "table" then setmetatable(object, metatable) end
  end
  return object
end

_string.gfind = _string.gfind or _string.gmatch
_math.mod = _math.mod or _math.fmod
_math.pow = _math.pow or function(a, b) return a ^ b end
_math.atan2 = _math.atan2 or _math.atan
_math.ldexp = _math.ldexp or function(value, exponent)
  return value * 2.0 ^ (exponent or 0)
end
_math.frexp = _math.frexp or function(value)
  if value ~= value or value == _math.huge or value == -_math.huge or value == 0 then return value, 0 end
  local exponent = _math.floor(_math.log(_math.abs(value)) / _math.log(2)) + 1
  local mantissa = value / 2.0 ^ exponent
  if _math.abs(mantissa) >= 1 then
    mantissa = mantissa / 2
    exponent = exponent + 1
  elseif _math.abs(mantissa) < 0.5 then
    mantissa = mantissa * 2
    exponent = exponent - 1
  end
  return mantissa, exponent
end
_math.log10 = _math.log10 or function(value) return _math.log(value) / _math.log(10) end
_math.cosh = _math.cosh or function(value) local e = _math.exp(value); return (e + 1 / e) / 2 end
_math.sinh = _math.sinh or function(value) local e = _math.exp(value); return (e - 1 / e) / 2 end
_math.tanh = _math.tanh or function(value) local e = _math.exp(2 * value); return (e - 1) / (e + 1) end
_table.getn = _table.getn or function(value) return #value end
_table.setn = _table.setn or noop
_table.foreach = _table.foreach or function(value, callback)
  for key, item in _next, value do
    local result = callback(key, item)
    if result ~= nil then return result end
  end
end
_table.foreachi = _table.foreachi or function(value, callback)
  for index = 1, #value do
    local result = callback(index, value[index])
    if result ~= nil then return result end
  end
end
gcinfo = function() return 0 end

package = { loaded = loaded, preload = {}, path = "", cpath = "", loaders = {} }
debug = nil
io = {
  open = function() return nil, "filesystem access is disabled in the sandbox" end,
  write = function() return nil end,
  read = function() return nil end,
  lines = function() return function() return nil end end,
  close = function() return true end,
  stdout = { write = function() return nil end },
  stderr = { write = function() return nil end }
}
os = {
  time = os.time,
  clock = os.clock,
  date = os.date,
  difftime = os.difftime,
  getenv = function() return nil end,
  execute = function() return false end,
  remove = function() return false, "filesystem access is disabled" end,
  rename = function() return false, "filesystem access is disabled" end,
  tmpname = function() return nil end,
  exit = function() _error("process exit is disabled in the sandbox") end
}
loadstring = load
loadfile = function() return nil, "filesystem access is disabled in the sandbox" end
dofile = function() return nil, "filesystem access is disabled in the sandbox" end
unpack = table.unpack
jit = {
  version = "LuaJIT 2.1 compatibility",
  version_num = 20100,
  os = "Windows",
  arch = "x86",
  status = function() return true end,
  on = function() end,
  off = function() end,
  flush = function() end
}
arg = arg or {}
script = moonloader.script
performHttpRequest = perform_http
CreateHttpRequest = create_http_request
downloadUrlToFile = download_url
httpRequest = perform_http
_G.print = function() end
_G.assert = function(condition, message)
  if not condition then _error(message or "assertion failed", 2) end
  return condition, message
end
_G.monet = monet
_G.monetloader = monetloader
_G.moonloader = moonloader
_G.requests = requests
_G.socket = socket
_G.ssl = ssl
_G.http = http_module
_G.samp = samp
_G.sampfuncs = samp.funcs
_G.vkeys = vkeys
_G.encoding = encoding
_G.memory = memory
_G.json = json
_G.encodeJson = json.encode
_G.bit = bit
_G.base64 = base64
_G.thisScript = moonloader.script
_G.wait = wait_impl

local SYNTHETIC_LOGIN_INPUT = "RM7_FAKE_TEST_PASSWORD"
local sim = {
  player_name = "RM7_TestPlayer",
  player_id = 0,
  server_name = "RM7 Sandbox Server",
  server_ip = "192.0.2.10",
  server_port = 7777
}

local observations = {}
local simulation = { ran = false, truncated = false, events = {} }

local function simulate_event(name, ...)
  local args = { ... }
  current_event = name
  local list = event_handlers[name]
  local ran = false
  if list and #list > 0 then
    for _, callback in ipairs(list) do
      ran = true
      local ok, err = guarded_call(callback, clock_ms() + event_budget_ms, max_instructions, _table.unpack(args))
      if not ok then
        observations[#observations + 1] = {
          event = name,
          reason = reason_for(err),
          error = safe_string(err, 300)
        }
      end
    end
  end
  if not ran and _type(_G[name]) == "function" then
    ran = true
    local ok, err = guarded_call(_G[name], clock_ms() + event_budget_ms, max_instructions, _table.unpack(args))
    if not ok then
      observations[#observations + 1] = {
        event = name,
        reason = reason_for(err),
        error = safe_string(err, 300)
      }
    end
  end
  current_event = nil
  return ran
end

local function simulate_sequence()
  local ran = {}
  local started = clock_ms()
  local function run(name, ...)
    if clock_ms() - started >= simulation_budget_ms then
      simulation.truncated = true
      return
    end
    if simulate_event(name, ...) then ran[#ran + 1] = name end
  end
  run("onScriptLoad")
  run("onShowDialog", 1, 1, "RM7 Sandbox Login", "Enter password", "Login", "Cancel")
  run("onSendDialogResponse", 1, 1, 0, SYNTHETIC_LOGIN_INPUT)
  run("onServerConnect", false, sim.server_ip, sim.server_port, "")
  run("onServerMessage", 0, "sandbox probe")
  run("onServerMessage", 1, "sandbox probe")
  run("onChatMessage", 0, "sandbox probe")
  run("onSetPlayerId", sim.player_id)
  run("onPlayerJoin", sim.player_id, sim.player_name, 0)
  run("onPlayerSpawn", sim.player_id, 0)
  run("onPlayerSync", sim.player_id)
  run("onPlayerSync", sim.player_id)
  run("onPlayerStreamIn", sim.player_id, true)
  run("onPlayerStreamOut", sim.player_id)
  run("onPlayerDisconnect", sim.player_id, 0)
  run("onServerQuit", 0)
  return ran
end

isSampLoaded = function() return true end
isSampfuncsLoaded = function() return true end
isSampFuncsLoaded = isSampfuncsLoaded
isSampAvailable = function() return true end
isPlayerPlaying = function() return true end
isPauseMenuActive = false_value
getGameVersion = zero_value
getScreenResolution = function() return 0, 0 end
getPlayerHandle = zero_value
getPlayerChar = zero_value
getCharCoordinates = three_zeros
getCharHealth = function() return 100 end
getCharArmour = function() return 100 end
isCharOnFoot = function() return true end
isCharInAnyCar = false_value
getCharSpeed = zero_value
isKeyDown = false_value
isKeyJustPressed = false_value
addEventHandler = noop
removeEventHandler = noop

sampRegisterChatCommand = noop
sampShowDialog = noop
sampSendDialogResponse = noop
sampAddChatMessage = noop
sampSendChat = noop
sampAddChatString = noop
sampIsChatInputActive = false_value
sampGetPlayerHealth = function() return 100 end
sampGetPlayerArmor = function() return 100 end
sampGetPlayerArmour = sampGetPlayerArmor
sampGetPlayerMoney = zero_value
sampGetPlayerName = function() return sim.player_name end
sampGetPlayerNickname = function() return sim.player_name end
sampGetPlayerId = function() return sim.player_id end
sampGetPlayerIdByCharHandle = function() return true, sim.player_id end
sampGetCharHandleBySampPlayerId = function() return true, 1 end
sampGetPlayerCount = function() return 1 end
sampGetMaxPlayerId = function() return 0 end
sampGetCurrentServerName = function() return sim.server_name end
sampGetCurrentServerAddress = function() return sim.server_ip, sim.server_port end
PLAYER_PED = PLAYER_PED or 1
sampIsPlayerConnected = function() return true end
sampGetPlayerScore = zero_value
sampGetPlayerPing = function() return 0 end
sampGetPlayerIp = function() return sim.server_ip end
sampGetPlayerState = zero_value
sampGetPlayerPos = three_zeros
sampGetPlayerVelocity = three_zeros
sampGetPlayerVehicleID = zero_value
sampIsPlayerInAnyVehicle = false_value
sampIsPlayerDriver = false_value
sampGetPlayerVehicleSeat = zero_value
sampGetPlayerWeapon = zero_value
sampGetPlayerAmmo = zero_value
sampGetPlayerTeam = zero_value
sampGetPlayerSkin = zero_value
sampGetPlayerColor = zero_value
sampGetPlayerTarget = zero_value
sampGetPlayerCameraMode = zero_value
sampGetPlayerFightingStyle = zero_value
sampGetPlayerSpecialAction = zero_value
sampGetServerName = function() return sim.server_name end
sampGetServerIp = function() return sim.server_ip end
sampGetServerPort = function() return sim.server_port end
sampGetLocalPlayerId = function() return sim.player_id end

local function guarded_result(callback, ...)
  local ok, err = guarded_call(callback, clock_ms() + lua_budget_ms, max_instructions, ...)
  if ok then
    return { ok = true, reason = "", error = "" }
  end
  return { ok = false, reason = reason_for(err), error = safe_string(err, 300) }
end

function _G.__rm7_run_source()
  local source = __rm7_source
  __rm7_source = nil
  if _type(source) ~= "string" then
    return { ok = false, reason = "compile", error = "missing source" }
  end
  local name = safe_string(__rm7_source_name or "script.lua", 120)
  local chunk, compile_error = load(source, "@" .. name, "t", _G)
  if not chunk then
    return { ok = false, reason = "compile", error = safe_string(compile_error, 300) }
  end
  local result = guarded_result(chunk)
  if not result.ok then return result end
  if _type(_G.main) == "function" then
    current_event = "main"
    result = guarded_result(_G.main)
    current_event = nil
  end
  return result
end

function _G.__rm7_run_hook(name)
  name = safe_string(name or "", 80)
  local callback = _G[name]
  if _type(callback) ~= "function" then
    callback = event_current[name]
  end
  if _type(callback) ~= "function" then
    return { ok = true, missing = true, reason = "", error = "" }
  end
  current_event = name
  local result = guarded_result(callback)
  current_event = nil
  return result
end

function _G.__rm7_run_event(name)
  name = safe_string(name or "", 80)
  local ran = simulate_event(name)
  return {
    ok = true,
    ran = ran,
    observations = observations,
    request_cap_reached = truncated
  }
end

function _G.__rm7_simulate()
  local ran = simulate_sequence()
  simulation.ran = true
  for _, name in ipairs(ran) do
    local seen = false
    for _, previous in ipairs(simulation.events) do
      if previous == name then seen = true end
    end
    if not seen then simulation.events[#simulation.events + 1] = name end
  end
  return {
    ok = true,
    events = simulation.events,
    observations = observations,
    simulation_truncated = simulation.truncated,
    request_cap_reached = truncated
  }
end

_G.__rm7_dynamic_report = function()
  return {
    requests_captured = captured,
    request_cap_reached = truncated,
    metadata = metadata,
    observations = observations,
    events_run = simulation.events,
    simulation_ran = simulation.ran,
    simulation_truncated = simulation.truncated
  }
end
