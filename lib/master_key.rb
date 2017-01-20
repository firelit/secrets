require 'openssl'

class MasterKey

	CONFIG = {
	  cipher: 'aes-256-cbc',
	  key_len: 32,
	  iv_len: 16
	}

	def initialize(key, encrypted = true)
		@defaultCipher = 'AES-256-CBC'

		if (encrypted)
			@encrypted = key
		else
			@decrypted = key
		end
	end

	def self.generate
		cipher = OpenSSL::Cipher.new(CONFIG[:cipher])
		cipher.encrypt
		self.new(cipher.random_key, false)
	end

	def encryptWithPublicKey(public_key)
		key = OpenSSL::PKey::RSA.new public_key
		raise 'Not a public key' unless key.public?
		@encrypted = key.public_encrypt @decrypted
	end

	def decryptWithPrivateKey(private_key, pass_phrase = nil)
		key = OpenSSL::PKey::RSA.new private_key, pass_phrase
		raise 'Not a private key' unless key.private?
		@decrypted = key.private_decrypt @encrypted
	end

	def encryptSecret(secret)
		cipher = OpenSSL::Cipher.new(CONFIG[:cipher])
		cipher.encrypt
		cipher.key = @decrypted
		iv = cipher.random_iv
		iv + cipher.update(secret) + cipher.final
	end

	def decryptSecret(secret)
		decipher = OpenSSL::Cipher.new(CONFIG[:cipher])
		decipher.decrypt
		decipher.key = @decrypted
		iv_len = CONFIG[:iv_len]
		iv = secret[0..(iv_len-1)]
		secret = secret[iv_len..-1]
		decipher.iv = iv
		decipher.update(secret) + decipher.final
	end

	def self.bin_to_hex(s)
		s.each_byte.map { |b| b.to_s(16).rjust(2,'0') }.join
	end

	def self.hex_to_bin(b)
	  	[b].pack('H*')
	end

end