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

-module(hep_v1).

-include("hep.hrl").

-export([encode/1]).
-export([decode/1]).

%% API

-spec encode(hep:t()) -> {ok, binary()} | {error, _}.

encode(#hep{ protocol_family = ProtocolFamily = 2
           , protocol = Protocol
           , src_ip = {S1, S2, S3, S4}
           , src_port = SrcPort
           , dst_ip = {D1, D2, D3, D4}
           , dst_port = DstPort
           , payload_type = 1
           , payload = Payload}) ->
    Length = 16,
    Bin = <<?HEP_V1_ID, Length:8, ProtocolFamily:8, Protocol:8, SrcPort:16, DstPort:16,
            ?IPV4(S1, S2, S3, S4),
            ?IPV4(D1, D2, D3, D4),
            Payload/binary>>,
    {ok, Bin};

encode(#hep{ protocol_family = ProtocolFamily = 10
           , protocol = Protocol
           , src_ip = {S1, S2, S3, S4, S5, S6, S7, S8}
           , src_port = SrcPort
           , dst_ip = {D1, D2, D3, D4, D5, D6, D7, D8}
           , dst_port = DstPort
           , payload_type = 1
           , payload = Payload}) ->
    Length = 40,
    Bin = <<?HEP_V1_ID, Length:8, ProtocolFamily:8, Protocol:8, SrcPort:16, DstPort:16,
            ?IPV6(S1, S2, S3, S4, S5, S6, S7, S8),
            ?IPV6(D1, D2, D3, D4, D5, D6, D7, D8),
            Payload/binary>>,
    {ok, Bin};

encode(#hep{protocol_family = ProtocolFamily})
  when ProtocolFamily =/= 2; ProtocolFamily =/= 10 ->
    {error, {unknown_protocol_family, ProtocolFamily}};

encode(#hep{payload_type = PayloadType})
  when PayloadType =/= 1 ->
    {error, {unsupported_payload_type, PayloadType}}.



-spec decode(binary()) -> {ok, hep:t()} | {error, _}.

decode(<<?HEP_V1_ID, Length:8, ProtocolFamily:8, Protocol:8, SrcPort:16, DstPort:16,
         ?IPV4(S1, S2, S3, S4),
         ?IPV4(D1, D2, D3, D4),
         Payload/binary>>)
  when Length == 16, ProtocolFamily == 2 ->
    HEP = #hep{ version = ?MODULE
              , protocol_family = ProtocolFamily
              , protocol = Protocol
              , src_ip = {S1, S2, S3, S4}
              , src_port = SrcPort
              , dst_ip = {D1, D2, D3, D4}
              , dst_port = DstPort
              %% , timestamp = os:timestamp()
              , payload_type = 1
              , payload = Payload
              },
    {ok, HEP};

decode(<<?HEP_V1_ID, Length:8, ProtocolFamily:8, Protocol:8, SrcPort:16, DstPort:16,
         ?IPV6(S1, S2, S3, S4, S5, S6, S7, S8),
         ?IPV6(D1, D2, D3, D4, D5, D6, D7, D8),
         Payload/binary>>)
  when Length == 40, ProtocolFamily == 10 ->
    HEP = #hep{ version = ?MODULE
              , protocol_family = ProtocolFamily
              , protocol = Protocol
              , src_ip = {S1, S2, S3, S4, S5, S6, S7, S8}
              , src_port = SrcPort
              , dst_ip = {D1, D2, D3, D4, D5, D6, D7, D8}
              , dst_port = DstPort
              %% , timestamp = os:timestamp()
              , payload_type = 1
              , payload = Payload
              },
    {ok, HEP};

decode(<<Other/binary>>) ->
    {error, {invalid_packet, Other}}.

%% Internals

%% End of Module.
