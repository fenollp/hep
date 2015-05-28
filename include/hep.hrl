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

-ifndef(HEP_HRL).

-record(hep, { version :: hep:version()
             , protocol_family :: hep:uint8()
             , protocol :: hep:uint8()
	     , src_ip :: inet:ip_address()
	     , src_port :: inet:port_number()
	     , dst_ip :: inet:ip_address()
	     , dst_port :: inet:port_number()
	     , timestamp :: erlang:timestamp() | undefined
	     , node_id :: hep:uint16() | hep:uint32() | undefined
	     , payload_type :: hep:uint8()
	     , payload :: binary()
             , vendor :: atom() | undefined
             }).

-define(HEP_V1_ID, 1:8).
-define(HEP_V2_ID, 2:8).
-define(HEP_V3_ID, "HEP3").

-define(IPV4(I1, I2, I3, I4),
        I1:8, I2:8, I3:8, I4:8).
-define(IPV6(I1, I2, I3, I4, I5, I6, I7, I8),
        I1:16, I2:16, I3:16, I4:16, I5:16, I6:16, I7:16, I8:16).

-define(HEP_HRL, true).
-endif.
