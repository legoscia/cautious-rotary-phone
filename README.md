# cautious-rotary-phone
Wireshark plugin for reading Erlang trace files

To activate this plugin, copy or symlink `erlterm.lua` and
`erlang-trace.lua` into the `~/.config/wireshark/plugins` directory,
creating it if it doesn't exist.  (If in doubt, check the folder
name in the "Folders" tab of the Wireshark "About" dialog.)

Then, in your Erlang shell, trace to a file, and start tracing with
timestamps:

    dbg:tracer(port, dbg:trace_port(file, "foo.trace")).
    dbg:p(all, [call, timestamp]).

Then you can open the resulting trace file in Wireshark.
