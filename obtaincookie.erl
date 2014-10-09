-module(obtaincookie).
-export([obtaincookie/0]).

%% technion@lolware.net

validatehash(Cdata, Hash) ->
    Key = <<"\x04\x67\xe7\x2e\x24\x67\x61\xd8\xf7\x2a\xb8\xe4\xd7\xaf\x6a\xda\x8d\x34\x59\xb8\x75\xd6\x4d\x3a\xd1\x00\x76\xd1\xfc\x29\x52\x12\x4c\x86\xa1\x86\x98\xcb\x7b\xf9\xfd\x62\xa3\xd7\xad\x56\xfe\xaa\x6c\x15\x05\x52\x37\x67\x6e\x88\xaf\xae\x7c\xf2\x01\xca\xf9\x77">>,
    <<Mac:160/integer>> = crypto:hmac('sha', Key, Cdata), 
    io:fwrite("~40.16.0b~n", [Mac]).

decryptcookie(Cdata) ->
    Key = <<"\x8c\x60\x98\x52\x64\x16\xfb\x79\x48\xdd\xbf\x55\x71\x2b\x76\x98\x1b\x15\xb1\xdf\xa8\x9d\xb8\x3b\xd8\x5e\xa3\x23\xb9\x75\x21\xe5">>,
    Decoded = base64:decode_to_string(Cdata),
    io:fwrite("~s~n", [Decoded]),
    [Cencrypted|IV] = string:tokens(Decoded, "--"),
    io:fwrite("~s~n", [Cencrypted]),
    io:fwrite("enc is ~s~n", IV),
    BinIV = base64:decode(list_to_binary(IV)),
    BinCencrypted = base64:decode(Cencrypted),
    Plaintext = crypto:block_decrypt('aes_cbc256', Key, BinIV, BinCencrypted),
    unpad(Plaintext).

unpad(B) ->
    % Liberated from https://raw.githubusercontent.com/joearms/paradis/master/elib2_aes.erl
    Size = size(B),
    {_, B2} = split_binary(B, Size - 1),
    [Pad] = binary_to_list(B2),
    Len = case Pad of
          0 ->
          %% the entire last block is padding
          Size - 16;
          _ ->
          Size - Pad
      end,
    {Bfinal, _} = split_binary(B, Len),
    io:fwrite("~s~n", [Bfinal]),
    Bfinal.

obtaincookie() ->
    Cookie = <<"MkIyOEJxd2xicGpuMW5HVG44TGMrTUdMK2ZURnp5ZXpLc1VFeU93aittOFFlaDg3VVczR2xsZ29heVMweXByL1NqdXhQVWl0RklNZ1ZEdkVNa1YzN2FQTHJ3YzdwRTFjRng3K2JVM2ora1hKOXJwUDNYc0M2R1F3aitzcEhTeDNJSXh4cjNlYlZpUm1FQTF6Z2NIS0kyRWFjazFucEVWMzJ6OUhKVUdwTFBNai9qL3lpVHNSRFRQUURaY2pWUDlLYlFLTGt0aThjMzhiWTN1Ky9ack1GQT09LS04S2w1ZWFjSys5eUh5UFNOYUN3ZGF3PT0=--1701f7c14a04358b6525d7e1b6e235d00471ed89">>,
    %% Afer this split, Hash will be the provided HMAC
    %[Cdata|Hash] = string:tokens(Cookie, "--"),
    [Cdata,Hash] = binary:split(Cookie, [<<"--">>]),
    validatehash(Cdata, Hash),
    decryptcookie(Cdata),
    io:fwrite("~s~n", [Hash]).



