class KeyHelper

	def self.getPublicKey(file_path)

		key_string = File.read(file_path)

	    if (key_string[0..7] == 'ssh-rsa ')
	      # Test the file conversion
	      unless system("ssh-keygen -f #{options[:key_file]} -e -m pem > /dev/null 2>&1")
	        raise 'Could not convert ssh-rsa public key to PEM format for OpenSSL'
	      end

	      key_string = `ssh-keygen -f #{options[:key_file]} -e -m pem`
	    end

	    key_string

	end

end