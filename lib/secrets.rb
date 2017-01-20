require 'openssl'

class Secrets

	config = {
	  cipher: 'aes-256-cbc',
	  key_len: 32,
	  iv_len: 16
	}

	def self.checkFileStructure
		unless File.exists?('manifest.yaml')
			raise ('Required manifest.yaml does not exist')
		end

		unless File.exists?('users')
			raise ('Users directory does not exist')
		end

	    self.manifest = parse_yaml('manifest.yaml')

	    unless self.manifest.is_a? Object
	    	raise 'No valid data in manifest.yaml'
	    end

	    unless self.manifest.users_file.is_a? Object
	    	raise 'No users_file listed in manifest.yaml'
	    end

		unless File.exists?(self.manifest.users_file.path)
			raise ('Required manifest.yaml does not exist')
		end

	    unless self.manifest.secrets_file.is_a? Object
	    	raise 'No secrets_file listed in manifest.yaml'
	    end

		unless File.exists?(self.manifest.secrets_file.path)
			raise ('Required manifest.yaml does not exist')
		end
	end

	def self.checkSignatures(masterKey)
		users_file = File.read(self.manifest.users_file.path)
		check = self.calculateSignature(masterKey, users_file)

		unless check == self.manifest.users_file.signature
			raise 'Signature mismatch for users_file ('+ self.manifest.users_file.path +')'
		end

		secrets_file = File.read(self.manifest.secrets_file.path)
		check = self.calculateSignature(masterKey, secrets_file)

		unless check == self.manifest.secrets_file.signature
			raise 'Signature mismatch for secrets_file ('+ self.manifest.secrets_file.path +')'
		end
	end

	def self.calculateSignature(masterKey, string)
		digest = OpenSSL::Digest.new('sha256')
		OpenSSL::HMAC.digest(digest, masterKey, string)
	end

	def self.encryptMasterKey(publicKey)

	end

	def self.decryptMasterKey(privateKey)

	end

	def self.encryptSecret(masterKey)

	end

	def self.decryptSecret(masterKey)

	end

	def self.newMasterKey
	    self.random self.config.key_len
	end

	def self.newIv
		self.random self.config.iv_len
	end

	def self.random(bytes)
		OpenSSL::Random.pseudo_bytes bytes
	end
end