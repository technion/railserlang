#!/usr/bin/env ruby
# technion@lolware.net

require 'active_support/all'
require 'json'
require 'openssl'

# Obtained via IE debugging tools
cookie = 'MkIyOEJxd2xicGpuMW5HVG44TGMrTUdMK2ZURnp5ZXpLc1VFeU93aittOFFlaDg3VVczR2xsZ29heVMweXByL1NqdXhQVWl0RklNZ1ZEdkVNa1YzN2FQTHJ3YzdwRTFjRng3K2JVM2ora1hKOXJwUDNYc0M2R1F3aitzcEhTeDNJSXh4cjNlYlZpUm1FQTF6Z2NIS0kyRWFjazFucEVWMzJ6OUhKVUdwTFBNai9qL3lpVHNSRFRQUURaY2pWUDlLYlFLTGt0aThjMzhiWTN1Ky9ack1GQT09LS04S2w1ZWFjSys5eUh5UFNOYUN3ZGF3PT0%3D--1701f7c14a04358b6525d7e1b6e235d00471ed89'

unescaped_cookie = URI.unescape(cookie)

# From config/secrets.yml
secret_key_base = '3ce1a489ee22ff103c068507e46b9dea15d890b5a52a9e2b5a31f733e5b6392cba81a31e48d36955d60780e7aefdd68a4ddc46213dcddfa361aebada07b0fdc8'

# Method 1: Rails way. Implemented this way to understand algorithm.
key_generator = ActiveSupport::KeyGenerator.new(secret_key_base, iterations: 1000)
secret = key_generator.generate_key('encrypted cookie')
sign_secret = key_generator.generate_key('signed encrypted cookie')

#Printing the secret here allows us to use it directly in other code
#The scan/join combo inserts \x escapes to further allow direct pasting.
puts 'Sign secret is: \x' + sign_secret.unpack('H*')[0].scan(/../).join('\x')
puts 'Secret is: \x' + secret[0, 32].unpack('H*')[0].scan(/../).join('\x')

encryptor = ActiveSupport::MessageEncryptor.new(secret, sign_secret, serializer: JSON)
# This command will raise exception if the HMAC is invalid
plaintext = encryptor.decrypt_and_verify(unescaped_cookie)
puts "Plaintext as per MessageEncryptor:\n" + plaintext.to_s

# Method 2: Decrypt manually.
# Based on the Go implementation here
# https://github.com/adjust/gorails/blob/master/session/session.go
str, sign = unescaped_cookie.split(/--/)
# Hex encoded HMAC
puts 'HMAC as per cookie validator: ' + sign

str2 = str.unpack('m').join
c, iv = str2.split(/--/)

c = c.unpack('m').join
iv = iv.unpack('m').join

openssl = OpenSSL::Cipher.new('AES-256-CBC')
openssl.decrypt
openssl.iv = iv
openssl.key = secret[0, 32]

# Decrypted plaintext
puts openssl.update(c) + openssl.final

# Generate the HMAC
digest = OpenSSL::Digest.new('sha1')
h = OpenSSL::HMAC.hexdigest(digest, sign_secret, str)
puts 'HMAC as per OpenSSL verifier ' + h
