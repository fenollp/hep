%% Copyright (c) 2013, Matthias Endler <matthias.endler@pantech.at>
%%
%% Permission to use, copy, modify, and distribute this software for any
%% purpose with or without fee is hereby granted, provided that the above
%% copyright notice and this permission notice appear in all copies.
%%
%% THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
%% WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
%% MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
%% ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
%% WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
%% ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
%% OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

-module(hep).

-include("hep.hrl").

-export([decode/1]).

-export_type([ uint8/0
             , uint16/0
             , uint32/0
             , version/0
             , chunk_value_length/0
             , chunk_value/0
             , chunk/0
             , vendor_id/0
             , chunk_id/0
             , state/0
             ]).

-type uint8() :: 0..255.
-type uint16() :: 0..65535.
-type uint32() :: 0..4294967295.

-type version() :: 1 | 2 | 3.

-type chunk_value_length() :: 0..65535.
-type chunk_value() :: binary().
-type chunk() :: {{vendor_id(), chunk_id()}, {chunk_value_length(), chunk_value()}}.

-type vendor_id() :: 1..65535.
-type chunk_id() :: uint16().
-opaque state() :: #hep{}.

%% API

-spec decode(binary()) -> {ok, state()} | {error, _, binary()}.
decode(<<1:8, _Rest/binary>> = Packet) ->
    hep_v1_decoder:decode(Packet);
decode(<<2:8, _Rest/binary>> = Packet) ->
    hep_v2_decoder:decode(Packet);
decode(<<"HEP3", _Rest/binary>> = Packet) ->
    hep_v3_decoder:decode(Packet);
decode(<<Packet/binary>>) ->
    {error, invalid_packet, Packet}.

%% Internals

%% End of Module.
