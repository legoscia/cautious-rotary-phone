-- Copyright 2017 Magnus Henoch
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

erlang_term_proto = Proto("erlterm", "Erlang binary term format")

-- The "version number" should always be 131.  It is omitted in the
-- distribution protocol, and in nested terms.
local pf_version_number = ProtoField.uint8("erlterm.version", "Version number")

-- See erl_ext_dist.xml
local ATOM_CACHE_REF = 82
local SMALL_INTEGER_EXT = 97
local INTEGER_EXT = 98
local FLOAT_EXT = 99
local REFERENCE_EXT = 101
local PORT_EXT = 102
local PID_EXT = 103
local SMALL_TUPLE_EXT = 104
local LARGE_TUPLE_EXT = 105
local MAP_EXT = 116
local NIL_EXT = 106
local STRING_EXT = 107
local LIST_EXT = 108
local BINARY_EXT = 109
local SMALL_BIG_EXT = 110
local LARGE_BIG_EXT = 111
local NEW_REFERENCE_EXT = 114
local FUN_EXT = 117
local NEW_FUN_EXT = 112
local EXPORT_EXT = 113
local BIT_BINARY_EXT = 77
local NEW_FLOAT_EXT = 70
local ATOM_UTF8_EXT = 118
local SMALL_ATOM_UTF8_EXT = 119
local ATOM_EXT = 100
local SMALL_ATOM_EXT = 115

local types = {
   [ATOM_CACHE_REF] = "Atom cache reference",
   [SMALL_INTEGER_EXT] = "Small integer",
   [INTEGER_EXT] = "Integer",
   [FLOAT_EXT] = "Float (old)",
   [REFERENCE_EXT] = "Reference (old)",
   [PORT_EXT] = "Port",
   [PID_EXT] = "Process id",
   [SMALL_TUPLE_EXT] = "Small tuple",
   [LARGE_TUPLE_EXT] = "Large tuple",
   [MAP_EXT] = "Map",
   [NIL_EXT] = "Empty list",
   [STRING_EXT] = "String",
   [LIST_EXT] = "List",
   [BINARY_EXT] = "Binary",
   [SMALL_BIG_EXT] = "Small bignum",
   [LARGE_BIG_EXT] = "Large bignum",
   [NEW_REFERENCE_EXT] = "Reference (new)",
   [FUN_EXT] = "Fun (old)",
   [NEW_FUN_EXT] = "Fun (new)",
   [EXPORT_EXT] = "External fun",
   [BIT_BINARY_EXT] = "Bitstring",
   [NEW_FLOAT_EXT] = "Float (new)",
   [ATOM_UTF8_EXT] = "Atom (UTF-8)",
   [SMALL_ATOM_UTF8_EXT] = "Small atom (UTF-8)",
   [ATOM_EXT] = "Atom (Latin-1)",
   [SMALL_ATOM_EXT] = "Small atom (Latin-1)"
}

local pf_type = ProtoField.uint8("erlterm.type", "Term type",
				 base.DEC, types)

local pf_arity_8 = ProtoField.uint8("erlterm.arity", "Arity")

local pf_atom = ProtoField.string("erlterm.atom", "Atom")
local pf_atom_len_16 = ProtoField.uint16("erlterm.atom_length", "Atom length")
local pf_id = ProtoField.uint32("erlterm.id", "ID number")
local pf_serial = ProtoField.uint32("erlterm.serial", "Serial number")
local pf_creation = ProtoField.uint8("erlterm.creation", "Creation number")
local pf_list_len = ProtoField.uint32("erlterm.list_length", "List length")
local pf_uint_8 = ProtoField.uint8("erlterm.integer", "Integer")
local pf_int_32 = ProtoField.int32("erlterm.integer", "Integer")
local pf_string_len = ProtoField.uint16("erlterm.string_length", "String length")
local pf_string = ProtoField.string("erlterm.string", "String")

erlang_term_proto.fields =
   { pf_version_number, pf_type, pf_arity_8, pf_atom, pf_atom_len_16,
     pf_id, pf_serial, pf_creation, pf_list_len, pf_uint_8, pf_int_32,
     pf_string_len, pf_string }

local ef_unhandled_type = ProtoExpert.new("erlterm.unhandled", "Unhandled type",
					  expert.group.UNDECODED, expert.severity.NOTE)
local ef_truncated = ProtoExpert.new("erlterm.truncated", "Not enough data",
				     expert.group.UNDECODED, expert.severity.WARN)

erlang_term_proto.experts = { ef_unhandled_type, ef_truncated }

local dissect_term

-- All dissect_* functions return three values: the position where the
-- term ends, a human-readable form of the term as a string, and
-- the term itself represented in some Lua-appropriate type.

local function dissect_small_tuple(tvbuf, tree)
   tree:add(pf_arity_8, tvbuf:range(0, 1))

   local arity = tvbuf:range(0, 1):uint()
   local display_elements = {}
   local display_total_length = 0
   local pos = 1
   local elements = {}
   for i = 1, arity do
      if pos >= tvbuf:len() then
	 tree:add_proto_expert_info(ef_truncated)
	 break
      end

      local subtree = tree:add(erlang_term_proto, tvbuf:range(pos))
      subtree.text = "Tuple element"
      local len, element_display, element = dissect_term(tvbuf:range(pos), subtree)

      subtree.len = len
      pos = pos + len
      table.insert(elements, element)

      -- Are we still trying to build a detailed display form of the tuple?
      if display_total_length + string.len(element_display) < 50 then
	 table.insert(display_elements, element_display)
	 display_total_length = display_total_length + string.len(element_display)
      end
   end

   local display
   if display_total_length < 50 then
      display = "{" .. table.concat(display_elements, ", ") .. "}"
   else
      display = "{ " .. arity .. " elements }"
   end
   -- The third return value is the tuple elements as an array
   return pos, display, elements
end

local function dissect_atom(tvbuf, tree)
   tree:add(pf_atom_len_16, tvbuf:range(0, 2))

   local len = tvbuf:range(0, 2):uint()
   tree:add(pf_atom, tvbuf:range(2, len))
   local atom_name = tvbuf:range(2, len):string()
   -- The third return value is the atom name as a string
   return len + 2, atom_name, atom_name
end

local function dissect_pid(tvbuf, tree)
   -- First, the node name, encoded as some kind of atom
   local node_tree = tree:add(erlang_term_proto, tvbuf)
   node_tree.text = "Node name"
   local pos, node_name = dissect_term(tvbuf, node_tree)

   if pos >= tvbuf:len() then
      tree:add_proto_expert_info(ef_truncated)
      return pos
   end

   -- Then, some numbers
   tree:add(pf_id, tvbuf:range(pos, 4))
   tree:add(pf_serial, tvbuf:range(pos + 4, 4))
   tree:add(pf_creation, tvbuf:range(pos + 8, 1))

   local pid_display
   if node_name then
      -- This is similar to how pids are displayed within Erlang,
      -- but with an explicit node name instead of a number.
      pid_display = "<" .. node_name .. "." .. tvbuf:range(pos, 4):uint()
	 .. "." .. tvbuf:range(pos + 4, 4):uint() .. ">"
   end
   -- The third return value is the display form of the pid
   return pos + 9, pid_display, pid_display
end

local function dissect_list(tvbuf, tree)
   tree:add(pf_list_len, tvbuf:range(0, 4))

   local list_len = tvbuf:range(0, 4):uint()
   local display_elements = {}
   local display_total_length = 0
   local pos = 4
   local elements = {}
   for i = 1, list_len do
      if pos >= tvbuf:len() then
	 tree:add_proto_expert_info(ef_truncated)
	 break
      end

      local subtree = tree:add(erlang_term_proto, tvbuf:range(pos))
      subtree.text = "List element"
      local len, element_display, element = dissect_term(tvbuf:range(pos), subtree)
      subtree.len = len
      pos = pos + len
      table.insert(elements, element)

      -- Are we still trying to build a detailed display form of the list?
      if display_total_length + string.len(element_display) < 50 then
	 table.insert(display_elements, element_display)
	 display_total_length = display_total_length + string.len(element_display)
      end
   end

   -- Finally the "tail"
   if pos >= tvbuf:len() then
      tree:add_proto_expert_info(ef_truncated)
      return pos, display
   end
   local subtree = tree:add(erlang_term_proto, tvbuf:range(pos))
   subtree.text = "Tail"
   local len = dissect_term(tvbuf:range(pos), subtree)

   local display
   if display_total_length < 50 then
      display = "[" .. table.concat(display_elements, ", ") .. "]"
   else
      display = "[ " .. list_len .. " elements ]"
   end

   -- The third return value is the list elements as an array
   return pos + len, display, elements
end

local function dissect_nil(tvbuf, tree)
   return 0, "[]", {}
end

local function dissect_small_integer(tvbuf, tree)
   tree:add(pf_uint_8, tvbuf:range(0, 1))
   local value = tvbuf:range(0, 1):uint()
   return 1, "" .. value, value
end

local function dissect_integer(tvbuf, tree)
   tree:add(pf_int_32, tvbuf:range(0, 4))
   local value = tvbuf:range(0, 4):int()
   return 4, "" .. value, value
end

local function dissect_string(tvbuf, tree)
   tree:add(pf_string_len, tvbuf:range(0, 2))

   local len = tvbuf:range(0, 2):uint()
   tree:add(pf_string, tvbuf:range(2, len))
   local str = tvbuf:range(2, len):string()
   -- format "%q" escapes most things, but leaves newlines as
   -- backslash + newline.  let's change that to backslash + "n".
   return len + 2, string.format("%q", str):gsub("\n", "n"), str
end

local term_functions = {
   [SMALL_TUPLE_EXT] = dissect_small_tuple,
   [ATOM_EXT] = dissect_atom,
   [PID_EXT] = dissect_pid,
   [LIST_EXT] = dissect_list,
   [NIL_EXT] = dissect_nil,
   [SMALL_INTEGER_EXT] = dissect_small_integer,
   [INTEGER_EXT] = dissect_integer,
   [STRING_EXT] = dissect_string,
}

dissect_term = function(tvbuf, tree)
   tree:add(pf_type, tvbuf:range(0,1))
   local type_byte = tvbuf:range(0,1):uint()

   local term_function = term_functions[type_byte]
   if term_function then
      local pos, display, value = term_function(tvbuf:range(1), tree)
      if display then
	 tree:append_text(": " .. display)
      end
      return 1 + pos, display, value
   else
      local unhandled_text
      if types[type_byte] then
	 unhandled_text = "Unhandled type: " .. types[type_byte]
      else
	 unhandled_text = "Unhandled type: " .. type_byte
      end
      tree:add_proto_expert_info(ef_unhandled_type, unhandled_text)
      return tvbuf:len()
   end
end

-- This function is global, so that it can be called directly from
-- other modules, without going through Wireshark's dissector
-- framework - which would lose return values beyond the first.
function erlang_term_dissector(tvbuf, pktinfo, root)
   local tree = root:add(erlang_term_proto, tvbuf:range(0))

   local first_byte = tvbuf:range(0,1):uint()
   if first_byte == 131 then
      tree:add(pf_version_number, tvbuf:range(0,1))
      return dissect_term(tvbuf:range(1), tree)
   else
      -- No version number - let's just assume we're on the right track.
      return dissect_term(tvbuf, tree)
   end
end

erlang_term_proto.dissector = erlang_term_dissector

