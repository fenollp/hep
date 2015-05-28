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

-export([encode/1]).
-export([decode/1]).

-export_type([ uint8/0
             , uint16/0
             , uint32/0 ]).
-export_type([version/0]).
-export_type([t/0]).

-type uint8() :: 0..255.
-type uint16() :: 0..65535.
-type uint32() :: 0..4294967295.

-type version() :: hep_v1 | hep_v2 | hep_v3.

-opaque t() :: #hep{}.

%% API

-spec encode(t()) -> {ok, binary()} | {error, _}.
encode(#hep{version = Version} = Hep)
  when Version == hep_v1; Version == hep_v2; Version == hep_v3 ->
    Version:encode(Hep);
encode(Hep) ->
    {error, {invalid_hep, Hep}}.


-spec decode(binary()) -> {ok, t()} | {error, _}.
decode(Packet = <<?HEP_V1_ID, _Rest/binary>>) ->
    hep_v1:decode(Packet);
decode(Packet = <<?HEP_V2_ID, _Rest/binary>>) ->
    hep_v2:decode(Packet);
decode(Packet = <<?HEP_V3_ID, _Rest/binary>>) ->
    hep_v3:decode(Packet);
decode(Packet = <<_/binary>>) ->
    {error, invalid_packet, Packet}.

%% Internals

%% End of Module.
