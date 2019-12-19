%%==============================================================================
%% Copyright 2016 Erlang Solutions Ltd.
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%% http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.
%%==============================================================================

-module(mod_http_upload_youzu).
-author('zhaoht@youzu.com').
-behaviour(mod_http_upload).

-export([create_slot/6]).

-include("mongoose.hrl").

%%--------------------------------------------------------------------
%% API
%%--------------------------------------------------------------------

-spec create_slot(UTCDateTime :: calendar:datetime(), Token :: binary(),
                  Filename :: unicode:unicode_binary(), ContentType :: binary(),
                  Size :: pos_integer(), Opts :: proplists:proplist()) ->
                         {PUTURL :: binary(), GETURL :: binary(),
                          Headers :: #{binary() => binary()}}.
create_slot(_, _, Filename, _, Size, Opts) ->
    YouzuOpts = gen_mod:get_opt(youzu, Opts),
    BaseURL = trim_slash(unicode:characters_to_binary(gen_mod:get_opt(url, YouzuOpts))),
    TS = erlang:system_time(seconds),
    Rand = rand:uniform(trunc(math:pow(2, 20))),
    CRC = erlang:crc32(Filename),
    Data = <<TS:40/big, Rand:24/big, Size:32/big, CRC:32/big>>,
    File = aws_signature_v4:uri_encode(Filename),
    Key = base64url:decode(gen_mod:get_opt(key, YouzuOpts)),
    IV = crypto:strong_rand_bytes(12),
    {CipherText, Tag} = crypto:block_encrypt(aes_gcm, Key, IV, {"",  Data }),
    Token = base64url:encode(<<IV/binary, CipherText/binary, Tag/binary >>),
    URL = <<BaseURL/binary,"/",Token/binary,"/", File/binary>>,
    {
     URL,
     URL,
      #{}
    }.


%% Path has always at least one byte ("/")
-spec trim_slash(binary()) -> binary().
trim_slash(Data) ->
    case binary:last(Data) of
        $/ -> erlang:binary_part(Data, 0, byte_size(Data) - 1);
        _ -> Data
    end.
