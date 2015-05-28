-module(hep_v3).

-include("hep.hrl").

-export([encode/1]).
-export([decode/1]).

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

%% Binary patterns
-define(vendor(Val), Val:16).
-define(type(Val),   Val:16).
-define(length(Val), Val:16).
-define(protocol_family(Val), Val:8).
-define(protocol(Val), Val:8).
-define(port(Val), Val:16).
-define(timestamp(Val), Val:32).
-define(node_id(Val),  Val:32).
-define(payload_type(Val), Val:8).

%% API

-spec encode(hep:t()) -> {ok, binary()} | {error, _}.

encode(#hep{version = ?MODULE} = Hep) ->
    Payload = pack_chunks(Hep),
    case byte_size(Payload) + length(?HEP_V3_ID) + 2 of
        TotalLength when TotalLength > 65535 ->
            {error, {packet_too_large}};
        TotalLength ->
            {ok, <<?HEP_V3_ID, TotalLength:2/unsigned-integer-unit:8, Payload/binary>>}
    end.



-spec decode(binary()) -> {ok, hep:t()} | {error, _}.

decode(<<?HEP_V3_ID, TotalLength:2/unsigned-integer-unit:8, Rest/binary>>)
  when TotalLength >= 6 ->
    Length = TotalLength - length(?HEP_V3_ID) - 2,
    <<Payload:Length/binary>> = Rest,
    case chunks_from_payload(Payload, #hep{version = ?MODULE}) of
        {error,_}=Error -> Error;
        Hep ->
            case {Hep#hep.src_ip, Hep#hep.dst_ip} of
                {{_,_,_,_}, {_,_,_,_}} ->
                    {ok, Hep#hep{protocol_family = ?FAMILY_IPV4}};
                {{_,_,_,_,_,_,_,_}, {_,_,_,_,_,_,_,_}} ->
                    {ok, Hep#hep{protocol_family = ?FAMILY_IPV6}};
                {SrcIP, DstIP} ->
                    {error, {ips_of_unmatching_protocols,SrcIP,DstIP}}
            end
    end;
decode(<<Packet/binary>>) ->
    {error, {invalid_packet, Packet}}.

%% Internals

%% @private
chunks_from_payload(<<>>, Hep) -> Hep;
chunks_from_payload(Payload, PrevHep) ->
    case chunk_from_payload(PrevHep, Payload) of
        {{error,_}=Error, _Rest} -> Error;
        {NewHep, Continuation} -> chunks_from_payload(Continuation, NewHep)
    end.

%% @private
chunk_from_payload(Hep, <<Vendor:16
                          , Type:16
                          , Length:16
                          , Rest/binary
                        >>) ->
    DataLength = Length -2 -2 -2,
    <<Data:DataLength/binary, Continuation/binary>> = Rest,
    NewHep = case vendor(Vendor) of
                 {error, _}=Error -> Error;
                 VendorId -> set_field(Type, Data, Hep#hep{vendor = VendorId})
             end,
    {NewHep, Continuation}.

%% @private
set_field(?IP_PROTOCOL_FAMILY, <<?protocol_family(Data)>>, Hep) ->
    io:format("set_dielf ~p\n", [Data]),
    Hep#hep{protocol_family = Data};
set_field(?IP_PROTOCOL_ID, <<?protocol(Data)>>, Hep) ->
    Hep#hep{protocol = Data};
set_field(?IPV4_SOURCE_ADDRESS, <<?IPV4(I1, I2, I3, I4)>>, Hep) ->
    Hep#hep{src_ip = {I1, I2, I3, I4}};
set_field(?IPV4_DESTINATION_ADDRESS, <<?IPV4(I1, I2, I3, I4)>>, Hep) ->
    Hep#hep{dst_ip = {I1, I2, I3, I4}};
set_field(?IPV6_SOURCE_ADDRESS, <<?IPV6(I1, I2, I3, I4, I5, I6, I7, I8)>>, Hep) ->
    Hep#hep{src_ip = {I1, I2, I3, I4, I5, I6, I7, I8}};
set_field(?IPV6_DESTINATION_ADDRESS, <<?IPV6(I1, I2, I3, I4, I5, I6, I7, I8)>>, Hep) ->
    Hep#hep{dst_ip = {I1, I2, I3, I4, I5, I6, I7, I8}};
set_field(?PROTOCOL_SOURCE_PORT, <<?port(Data)>>, Hep) ->
    Hep#hep{src_port = Data};
set_field(?PROTOCOL_DESTINATION_PORT, <<?port(Data)>>, Hep) ->
    Hep#hep{dst_port = Data};
set_field(?TIMESTAMP_IN_SECONDS, <<?timestamp(Secs)>>, Hep = #hep{timestamp = TS}) ->
    MegaSecs = Secs div 1000000,
    TSSecs   = Secs rem 1000000,
    case TS of
        {_, _, Micros} ->
            Hep#hep{timestamp = {MegaSecs, TSSecs, Micros}};
        undefined ->
            Hep#hep{timestamp = {MegaSecs, TSSecs, 0}}
    end;
set_field(?TIMESTAMP_MS_OFFSET, <<?timestamp(MicroSecs)>>, Hep = #hep{timestamp = TS}) ->
    case TS of
        undefined ->
            Hep#hep{timestamp = {0, 0, MicroSecs}};
        {M, S, _} ->
            Hep#hep{timestamp = {M, S, MicroSecs}}
    end;
set_field(?PROTOCOL_TYPE, <<?payload_type(Data)>>, Hep) ->
    case protocol_type(Data) of
        {error, _}=Error -> Error;
        Protocol -> Hep#hep{payload_type = Protocol}
    end;
set_field(?CAPTURE_AGENT_ID, <<?node_id(Data)>>, Hep) ->
    Hep#hep{node_id = Data};
set_field(?KEEP_ALIVE_TIMER, <<_Data:16>>, Hep) ->
    %% Hep#hep{keep_alive_timer = Data};
    Hep;
set_field(?AUTHENTICATE_KEY, _Data, Hep) ->
    %% Hep#hep{authenticate_key = Data};
    Hep;
set_field(?CAPTURED_PACKET_PAYLOAD, Data, Hep) ->
    Hep#hep{payload = Data};
set_field(?CAPTURED_COMPRESSED_PAYLOAD, Data, Hep) ->
    Hep#hep{payload = Data};
set_field(?INTERNAL_CORRELATION_ID, _Data, Hep) ->
    %% Hep#hep{internal_correlation_id = Data};
    Hep;
set_field(?VLAN_ID, <<_Data:8>>, Hep) ->
    %% Hep#hep{vlan_id = Data}.
    Hep.

%% @private
vendor(?VENDOR_UNKNOWN) -> 'unknown';
vendor(?VENDOR_FREESWITCH) -> 'freeswitch';
vendor(?VENDOR_KAMALIO_SER) -> 'kamailio';
vendor(?VENDOR_OPENSIPS) -> 'opensips';
vendor(?VENDOR_ASTERISK) -> 'asterisk';
vendor(?VENDOR_HOMER_PROJECT) -> 'homer';
vendor(?VENDOR_SIPXECS) -> 'sipxecs';
vendor('unknown') -> ?VENDOR_UNKNOWN;
vendor('freeswitch') -> ?VENDOR_FREESWITCH;
vendor('kamailio') -> ?VENDOR_KAMALIO_SER;
vendor('opensips') -> ?VENDOR_OPENSIPS;
vendor('asterisk') -> ?VENDOR_ASTERISK;
vendor('homer') -> ?VENDOR_HOMER_PROJECT;
vendor('sipxecs') -> ?VENDOR_SIPXECS;
vendor(Vendor) ->
    {error, {invalid_vendor, Vendor}}.

%% @private
protocol_type(?PROTOCOL_RESERVED) -> 'reserved';
protocol_type(?PROTOCOL_SIP) -> 'sip';
protocol_type(?PROTOCOL_XMPP) -> 'xmpp';
protocol_type(?PROTOCOL_SDP) -> 'sdp';
protocol_type(?PROTOCOL_RTP) -> 'rtp';
protocol_type(?PROTOCOL_RTCP) -> 'rtcp';
protocol_type(?PROTOCOL_MGCP) -> 'mgcp';
protocol_type(?PROTOCOL_MEGACO) -> 'megaco';
protocol_type(?PROTOCOL_M2UA) -> 'm2ua';
protocol_type(?PROTOCOL_M3UA) -> 'm3ua';
protocol_type(?PROTOCOL_IAX) -> 'iax';
protocol_type(?PROTOCOL_H322) -> 'h322';
protocol_type(?PROTOCOL_H321) -> 'h321';
protocol_type('reserved') -> ?PROTOCOL_RESERVED;
protocol_type('sip') -> ?PROTOCOL_SIP;
protocol_type('xmpp') -> ?PROTOCOL_XMPP;
protocol_type('sdp') -> ?PROTOCOL_SDP;
protocol_type('rtp') -> ?PROTOCOL_RTP;
protocol_type('rtcp') -> ?PROTOCOL_RTCP;
protocol_type('mgcp') -> ?PROTOCOL_MGCP;
protocol_type('megaco') -> ?PROTOCOL_MEGACO;
protocol_type('m2ua') -> ?PROTOCOL_M2UA;
protocol_type('m3ua') -> ?PROTOCOL_M3UA;
protocol_type('iax') -> ?PROTOCOL_IAX;
protocol_type('h322') -> ?PROTOCOL_H322;
protocol_type('h321') -> ?PROTOCOL_H321;
protocol_type(Protocol) ->
    {error, {invalid_protocol, Protocol}}.


pack_chunks(Hep) ->
    encode(protocol_family, <<>>, Hep).

encode(protocol_family, _Acc, #hep{protocol_family = ProtocolFamily})
  when ProtocolFamily =/= ?FAMILY_IPV4, ProtocolFamily =/= ?FAMILY_IPV6 ->
    {error, {invalid_protocol_family,ProtocolFamily}};
encode(protocol_family=Field, Acc, Hep) ->
    Chunk = make_chunk(Field, Hep),
    encode(protocol, <<Chunk/binary, Acc/binary>>, Hep);
encode(protocol=Field, Acc, Hep) ->
    Chunk = make_chunk(Field, Hep),
    encode(src_ip, <<Chunk/binary, Acc/binary>>, Hep);
encode(src_ip=Field, Acc, Hep) ->
    Chunk = make_chunk(Field, Hep),
    encode(dst_ip, <<Chunk/binary, Acc/binary>>, Hep);
encode(dst_ip=Field, Acc, Hep) ->
    Chunk = make_chunk(Field, Hep),
    encode(src_port, <<Chunk/binary, Acc/binary>>, Hep);
encode(src_port=Field, Acc, Hep) ->
    Chunk = make_chunk(Field, Hep),
    encode(dst_port, <<Chunk/binary, Acc/binary>>, Hep);
encode(timestamp=Field, Acc, Hep) ->
    Chunk = make_chunk(Field, Hep),
    encode(payload_type, <<Chunk/binary, Acc/binary>>, Hep);
encode(payload_type=Field, Acc, Hep) ->
    Chunk = make_chunk(Field, Hep),
    encode(payload, <<Chunk/binary, Acc/binary>>, Hep);
encode(payload=Field, Acc, Hep) ->
    Chunk = make_chunk(Field, Hep),
    <<Chunk/binary, Acc/binary>>.


make_chunk(protocol_family, #hep{protocol_family = Data}=Hep) ->
    do_make_chunk(Hep, ?IP_PROTOCOL_FAMILY, <<?protocol_family(Data)>>);
make_chunk(protocol, #hep{protocol = Data}=Hep) ->
    do_make_chunk(Hep, ?IP_PROTOCOL_ID, <<?protocol(Data)>>);

make_chunk(src_ip, #hep{ protocol_family = ?FAMILY_IPV4
                       , src_ip = {I1, I2, I3, I4}
                       }=Hep) ->
    do_make_chunk(Hep, ?IPV4_SOURCE_ADDRESS, <<?IPV4(I1, I2, I3, I4)>>);
make_chunk(src_ip, #hep{ protocol_family = ?FAMILY_IPV6
                       , src_ip = {I1, I2, I3, I4, I5, I6, I7, I8}
                       }=Hep) ->
    do_make_chunk(Hep, ?IPV6_SOURCE_ADDRESS, <<?IPV6(I1, I2, I3, I4, I5, I6, I7, I8)>>);

make_chunk(dst_ip, #hep{ protocol_family = ?FAMILY_IPV4
                       , dst_ip = {I1, I2, I3, I4}
                       }=Hep) ->
    do_make_chunk(Hep, ?IPV4_DESTINATION_ADDRESS, <<?IPV4(I1, I2, I3, I4)>>);
make_chunk(dst_ip, #hep{ protocol_family = ?FAMILY_IPV6
                       , dst_ip = {I1, I2, I3, I4, I5, I6, I7, I8}
                       }=Hep) ->
    do_make_chunk(Hep, ?IPV6_DESTINATION_ADDRESS, <<?IPV6(I1, I2, I3, I4, I5, I6, I7, I8)>>);

make_chunk(src_port, #hep{src_port = Data}=Hep) ->
    do_make_chunk(Hep, ?PROTOCOL_SOURCE_PORT, <<?port(Data)>>);

make_chunk(dst_port, #hep{dst_port = Data}=Hep) ->
    do_make_chunk(Hep, ?PROTOCOL_DESTINATION_PORT, <<?port(Data)>>);

make_chunk(timestamp, #hep{timestamp = Timestamp}=Hep) ->
    Seconds = hep_util:timestamp_secs(Timestamp),
    Micros  = hep_util:timestamp_microsecs(Timestamp),
    Chunk1 = do_make_chunk(Hep, ?TIMESTAMP_IN_SECONDS, <<?timestamp(Seconds)>>),
    Chunk2 = do_make_chunk(Hep, ?TIMESTAMP_MS_OFFSET, <<?timestamp(Micros)>>),
    <<Chunk1/binary, Chunk2/binary>>;

make_chunk(payload_type, #hep{payload_type = Data}=Hep) ->
    do_make_chunk(Hep, ?PROTOCOL_TYPE, <<?payload_type(Data)>>);

make_chunk(payload, #hep{payload = Payload}=Hep) ->
    do_make_chunk(Hep, ?CAPTURED_PACKET_PAYLOAD, Payload).


do_make_chunk(#hep{vendor = Vendor}, Type, Value) ->
    Len = byte_size(Value),
    <<(vendor(Vendor)):16, Type:16, (2+2+2 + Len):16, Value/binary>>.

%% End of Module.
