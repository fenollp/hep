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

-module(hep_v3).

-include("hep.hrl").

-export([encode/1]).
-export([decode/1]).

-type chunk_value_length() :: 0..65535.
-type chunk_value() :: binary().
-type chunk() :: {{vendor_id(), chunk_id()}, {chunk_value_length(), chunk_value()}}.
-type vendor_id() :: 1..65535.
-type chunk_id() :: hep:uint16().

%% Chunk Vendor ID
-define(VENDOR_UNKNOWN,       16#0000).
-define(VENDOR_FREESWITCH,    16#0001).
-define(VENDOR_KAMALIO_SER,   16#0002).
-define(VENDOR_OPENSIPS,      16#0003).
-define(VENDOR_ASTERISK,      16#0004).
-define(VENDOR_HOMER_PROJECT, 16#0005).
-define(VENDOR_SIPXECS,       16#0006).

%% Generic Chunk Types
-define(IP_PROTOCOL_FAMILY,          16#0001).
-define(IP_PROTOCOL_ID,              16#0002).
-define(IPV4_SOURCE_ADDRESS,         16#0003).
-define(IPV4_DESTINATION_ADDRESS,    16#0004).
-define(IPV6_SOURCE_ADDRESS,         16#0005).
-define(IPV6_DESTINATION_ADDRESS,    16#0006).
-define(PROTOCOL_SOURCE_PORT,        16#0007).
-define(PROTOCOL_DESTINATION_PORT,   16#0008).
-define(TIMESTAMP_IN_SECONDS,        16#0009).
-define(TIMESTAMP_MS_OFFSET,         16#000a).
-define(PROTOCOL_TYPE,               16#000b).
-define(CAPTURE_AGENT_ID,            16#000c).
-define(KEEP_ALIVE_TIMER,            16#000d).
-define(AUTHENTICATE_KEY,            16#000e).
-define(CAPTURED_PACKET_PAYLOAD,     16#000f).
-define(CAPTURED_COMPRESSED_PAYLOAD, 16#0010).
-define(INTERNAL_CORRELATION_ID,     16#0011).
-define(VLAN_ID,                     16#0012).

%% Capture Protocol Types (0xb)
-define(PROTOCOL_RESERVED, 16#00).
-define(PROTOCOL_SIP,      16#01).
-define(PROTOCOL_XMPP,     16#02).
-define(PROTOCOL_SDP,      16#03).
-define(PROTOCOL_RTP,      16#04).
-define(PROTOCOL_RTCP,     16#05).
-define(PROTOCOL_MGCP,     16#06).
-define(PROTOCOL_MEGACO,   16#07).
-define(PROTOCOL_M2UA,     16#08).
-define(PROTOCOL_M3UA,     16#09).
-define(PROTOCOL_IAX,      16#0a).
-define(PROTOCOL_H322,     16#0b).
-define(PROTOCOL_H321,     16#0c).

%% API

-spec encode(hep:t()) -> {ok, iolist()} | {error, _}.

encode(#hep{chunks = Chunks} = Hep) ->
    case encode(protocol_family, Hep, 0, []) of
        {ok, GenericLength, GenericChunks} ->
            case encode_chunks(Chunks, GenericLength, GenericChunks) of
                {ok, AllChunkLength, AllChunks} ->
                    Length = 6 + AllChunkLength,
                    {ok, [<<"HEP3", Length:16>> | lists:reverse(AllChunks)]};
                {error, packet_too_large} ->
                    {error, {packet_too_large, Hep}}
            end;
        Error ->
            Error
    end.



-spec decode(binary()) -> {ok, hep:t()} | {error, _, binary()}.

decode(<<"HEP3", Length:16, _/binary>> = Packet)
  when Length >= 6 ->
    read_chunk_header(Packet, 6, Length, #hep{version = ?MODULE}).

%% Internals

encode(_, Hep, Len, _)
  when Len + 6 > 65535 ->
    {error, {packet_too_large, Hep}};
encode(protocol_family, #hep{protocol_family = ProtocolFamily}, _, _)
  when ProtocolFamily =/= 2, ProtocolFamily =/= 10 ->
    {error, {unknown_protocol_family, ProtocolFamily}};

encode(protocol_family, #hep{protocol_family = ProtocolFamily} = Hep, Len, Acc) ->
    ChunkLen = 6 + 1,
    Chunk = <<0:16, 1:16, ChunkLen:16, ProtocolFamily:8>>,
    encode(protocol, Hep, Len + ChunkLen, [Chunk|Acc]);

encode(protocol, #hep{protocol = Protocol} = Hep, Len, Acc) ->
    ChunkLen = 6 + 1,
    Chunk = <<0:16, 2:16, ChunkLen:16, Protocol:8>>,
    encode(src_ip, Hep, Len + ChunkLen, [Chunk|Acc]);

encode(src_ip, #hep{protocol_family = 2, src_ip = {I1, I2, I3, I4}} = Hep, Len, Acc) ->
    ChunkLen = 6 + 4*1,
    Chunk = <<0:16, 3:16, ChunkLen:16, I1:8, I2:8, I3:8, I4:8>>,
    encode(dst_ip, Hep, Len + ChunkLen, [Chunk|Acc]);
encode(src_ip, #hep{protocol_family = 10, src_ip = {I1, I2, I3, I4, I5, I6, I7, I8}} = Hep, Len, Acc) ->
    ChunkLen = 6 + 8*2,
    Chunk = <<0:16, 5:16, ChunkLen:16, I1:16, I2:16, I3:16, I4:16, I5:16, I6:16, I7:16, I8:16>>,
    encode(dst_ip, Hep, Len + ChunkLen, [Chunk|Acc]);

encode(dst_ip, #hep{protocol_family = 2, dst_ip = {I1, I2, I3, I4}} = Hep, Len, Acc) ->
    ChunkLen = 6 + 4*1,
    Chunk = <<0:16, 4:16, ChunkLen:16, I1:8, I2:8, I3:8, I4:8>>,
    encode(src_port, Hep, Len + ChunkLen, [Chunk|Acc]);
encode(dst_ip, #hep{protocol_family = 10, src_ip = {I1, I2, I3, I4, I5, I6, I7, I8}} = Hep, Len, Acc) ->
    ChunkLen = 6 + 8*2,
    Chunk = <<0:16, 6:16, ChunkLen:16, I1:16, I2:16, I3:16, I4:16, I5:16, I6:16, I7:16, I8:16>>,
    encode(src_port, Hep, Len + ChunkLen, [Chunk|Acc]);

encode(src_port, #hep{src_port = SrcPort} = Hep, Len, Acc) ->
    ChunkLen = 6 + 2,
    Chunk = <<0:16, 7:16, ChunkLen:16, SrcPort:16>>,
    encode(dst_port, Hep, Len + ChunkLen, [Chunk|Acc]);

encode(dst_port, #hep{dst_port = DstPort} = Hep, Len, Acc) ->
    ChunkLen = 6 + 2,
    Chunk = <<0:16, 8:16, ChunkLen:16, DstPort:16>>,
    encode(timestamp, Hep, Len + ChunkLen, [Chunk|Acc]);

encode(timestamp, #hep{timestamp = Timestamp} = Hep, Len, Acc) ->
    ChunkLen1 = 6 + 4,
    ChunkLen2 = 6 + 4,
    Secs = hep_util:timestamp_secs(Timestamp),
    Micros = hep_util:timestamp_microsecs(Timestamp),
    Chunk = <<0:16, 9:16, ChunkLen1:16, Secs:32, 0:16, 10:16, ChunkLen2, Micros:32>>,
    encode(payload_type, Hep, Len + ChunkLen1 + ChunkLen2, [Chunk|Acc]);

encode(payload_type, #hep{payload_type = PayloadType} = Hep, Len, Acc) ->
    case valid_payload_type(PayloadType) of
        true ->
            ChunkLen = 6 + 1,
            Chunk = <<0:16, 10:16, ChunkLen:16, PayloadType:8>>,
            encode(payload, Hep, Len + ChunkLen, [Chunk|Acc]);
        _ ->
            {error, {invalid_payload_type, PayloadType}}
    end;

encode(payload, #hep{payload = Payload}, Len, Acc) ->
    ChunkLen = 6 + byte_size(Payload),
    Chunk = <<0:16, 15:16, ChunkLen:16, Payload/binary>>,
    {ok, Len + ChunkLen, [Chunk|Acc]}.

encode_chunks([], Len, Acc) ->
    {ok, Len, Acc};
encode_chunks([{{VendorId, ChunkId}, ChunkValue} | Rest], Len, Acc) ->
    ChunkLength = 6 + byte_size(ChunkValue),
    case (ChunkLength + Len + 6) > 65535 of
        false ->
            Chunk = <<VendorId:16, ChunkId:16, ChunkLength:16, ChunkValue/binary>>,
            encode_chunks(Rest, Len + ChunkLength, [Chunk|Acc]);
        true ->
            {error, packet_too_large}
    end.

-spec valid_payload_type(non_neg_integer()) -> boolean().
valid_payload_type(1) -> true;
valid_payload_type(2) -> true;
valid_payload_type(3) -> true;
valid_payload_type(4) -> true;
valid_payload_type(5) -> true;
valid_payload_type(6) -> true;
valid_payload_type(7) -> true;
valid_payload_type(8) -> true;
valid_payload_type(9) -> true;
valid_payload_type(16) -> true;
valid_payload_type(_) -> false.


%% @private
%% TODO this needs some refactoring... ugly, ugly, ugly
-spec read_chunk_header(binary(), non_neg_integer(), non_neg_integer(), hep:state()) ->
                               {ok, hep:state()} | {error, term(), binary()}.
read_chunk_header(Packet, Offset, Length, Hep0) ->
    <<_:Offset/binary, VendorId:16, ChunkId:16, ChunkLen:16, _/binary>> = Packet,
    case Offset + ChunkLen =< Length of
        false ->
            ValueLen = ChunkLen - 6,
            {ok, Value} = read_chunk_value(Packet, Offset + 6, ValueLen),
            case decode_chunk(VendorId, ChunkId, ValueLen, Value, Hep0) of
                {ok, Hep} ->
                    case Offset + ChunkLen =:= Length of
                        true ->
                            #hep{chunks = Chunks} = Hep,
                            {ok, Hep#hep{chunks = lists:reverse(Chunks)}};
                        false ->
                            read_chunk_header(Packet, Offset + ChunkLen, Length, Hep)
                    end;
                {error, Reason} ->
                    {error, Reason, Packet}
            end;
        true ->
            {error, invalid_packet, Packet}
    end.

%% @private
-spec read_chunk_value(binary(), non_neg_integer(), non_neg_integer()) -> {ok, binary()}.
read_chunk_value(Packet, Offset, Len) ->
    <<_:Offset/binary, Value:Len/binary, _Rest/binary>> = Packet,
    {ok, Value}.

%% @private
-spec decode_chunk(vendor_id(), chunk_id(), chunk_value_length(), binary(), hep:t()) ->
                          {ok, hep:t()} | {error, _}.
decode_chunk(0, 1, 1, <<ProtocolFamily:8>>, Hep)
  when ProtocolFamily =:= 2; ProtocolFamily =:= 10 ->
    {ok, Hep#hep{protocol_family = ProtocolFamily}};
decode_chunk(0, 2, 1, <<Protocol:8>>, Hep) ->
    {ok, Hep#hep{protocol = Protocol}};
decode_chunk(0, 3, 4, <<I1:8, I2:8, I3:8, I4:8>>
            , #hep{protocol_family = 2} = Hep
            ) ->
    {ok, Hep#hep{src_ip = {I1, I2, I3, I4}}};
decode_chunk(0, 4, 4, <<I1:8, I2:8, I3:8, I4:8>>
            , #hep{protocol_family = 2} = Hep
            ) ->
    {ok, Hep#hep{dst_ip = {I1, I2, I3, I4}}};
decode_chunk(0, 5, 16
            , <<I1:16, I2:16, I3:16, I4:16, I5:16, I6:16, I7:16, I8:16>>
            , #hep{protocol_family = 10} = Hep
            ) ->
    {ok, Hep#hep{src_ip = {I1, I2, I3, I4, I5, I6, I7, I8}}};
decode_chunk(0, 6, 16
            , <<I1:16, I2:16, I3:16, I4:16, I5:16, I6:16, I7:16, I8:16>>
            , #hep{protocol_family = 10} = Hep
            ) ->
    {ok, Hep#hep{dst_ip = {I1, I2, I3, I4, I5, I6, I7, I8}}};
decode_chunk(0, 7, 2, <<SrcPort:16>>, Hep) ->
    {ok, Hep#hep{src_port = SrcPort}};
decode_chunk(0, 8, 2, <<DstPort:16>>, Hep) ->
    {ok, Hep#hep{dst_port = DstPort}};
decode_chunk(0, 9, 4, <<TimestampSecs:32>>, Hep) ->
    put_ts_secs(TimestampSecs, Hep);
decode_chunk(0, 10, 4, <<TimestampUSecs:32>>, Hep) ->
    put_ts_usecs(TimestampUSecs, Hep);
decode_chunk(0, 11, 1, <<PayloadType:8>>, Hep) ->
    {ok, Hep#hep{payload_type = PayloadType}};
decode_chunk(0, 12, 4, <<NodeId:32>>, Hep) ->
    {ok, Hep#hep{node_id = NodeId}};
decode_chunk(0, 13, 2, <<_KeepAlive:16>>, Hep) ->
    {ok, Hep};
decode_chunk(0, 14, _, <<_AuthKey/binary>>, Hep) ->
    {ok, Hep};
decode_chunk(0, 15, _, <<Payload/binary>>, Hep) ->
    {ok, Hep#hep{payload = Payload}};
decode_chunk(0, ChunkId, Len, Value, _Hep)
  when ChunkId >= 1, ChunkId =< 15 ->
    {error, {invalid_chunk, 0, ChunkId, Len, Value}};
decode_chunk(0, _, _, _, Hep) ->
    {ok, Hep};
decode_chunk(VendorId, ChunkId, Len, Value, #hep{chunks = Chunks0} = Hep) ->
    Chunks = [{{VendorId, ChunkId}, {Len, Value}} | Chunks0],
    {ok, Hep#hep{chunks = Chunks}}.

%% @private
-spec put_ts_secs(non_neg_integer(), hep:t()) -> {ok, hep:t()}.
put_ts_secs(TimestampSecs, #hep{timestamp = Timestamp} = Hep) ->
    MegaSecs = TimestampSecs div 1000000,
    Secs     = TimestampSecs rem 1000000,
    case Timestamp of
        {_, _, Micros} ->
            {ok, Hep#hep{timestamp = {MegaSecs, Secs, Micros}}};
        undefined ->
            {ok, Hep#hep{timestamp = {MegaSecs, Secs, 0}}}
    end.

%% @private
-spec put_ts_usecs(non_neg_integer(), hep:t()) -> {ok, hep:t()}.
put_ts_usecs(TimestampUSecs, #hep{timestamp = undefined} = Hep) ->
    {ok, Hep#hep{timestamp = {0, 0, TimestampUSecs}}};
put_ts_usecs(TimestampUSecs, #hep{timestamp = {M, S, _}} = Hep) ->
    {ok, Hep#hep{timestamp = {M, S, TimestampUSecs}}}.

%% End of Module.
