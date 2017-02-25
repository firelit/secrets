require 'openssl'
require_relative 'file_manager'

class SecretManager < FileManager

    attr_accessor :working_dir, :master_key

    def initialize(master_key = nil)
        @@working_dir = Dir.pwd
        @@master_key = master_key unless master_key.nil?
        @data = @data || []
    end

    # - name: SEND_GRID
    #   tags:
    #    - PROD
    #    - DEV
    #   account: my_user_name
    #   secret: 010b606069e6e63cd24c9cf60d08351775539...
    #   added: 2017-01-14 09:02:16.906998000 -05:00

    # Add a secret
    def add(secret_name, secret, account = nil, tags = [], notes = nil)
        unless find(secret_name, tags, false).empty?
            raise 'Secret already exists with these tags'
        end

        tags = [tags] unless tags.is_a? Array

        secret_data = {
            name: secret_name,
            tags: tags,
            account: account, # like the user name or email, if applicable
            secret: @@master_key.class.bin_to_hex( @@master_key.encryptSecret(secret) ),
            notes: notes,
            added: Time.now
        }

        @data.push secret_data
    end

    # Remove a secret, must have all tags given
    def remove(secret_name, tags = [])
        tags = [tags] unless tags.is_a? Array
        removed = 0

        @data.keep_if do |secret_data|
            if (secret_data[:name] == secret_name) && (tags.empty? || (tags - secret_data[:tags]).empty?)
                removed += 1
                false
            else
                true
            end
        end

        removed
    end

    # Search for a secret, must have all tags given
    def find(secret_name, tags = [], decrypt = true)
        tags = [tags] unless tags.is_a? Array

        return_data = []
        @data.each do |secret_data|
            if (secret_data[:name] == secret_name)
                next unless tags.empty? || (tags - secret_data[:tags]).empty?
                # If no tags or secret has all tags

                this_secret = secret_data.dup
                if decrypt
                    this_secret[:secret] = @@master_key.decryptSecret(@@master_key.class.hex_to_bin this_secret[:secret])
                end

                return_data.push(this_secret)
            end
        end
        return_data
    end

    # Get decrypted secret, array of secrets if mutliple matches
    def getSecret(secret_name, tags = [])
        res = find(secret_name, tags)
        return nil if res.empty?
        res = res.map {|x| x[:secret]}
        return res[0] if res.length == 1
        res
    end

    # Change the encryption key for all secrets
    def rotateMasterKey(new_master_key)
        @data = @data.map do |secret_data|
            secret = secret_data[:secret]
            plain_text = @@master_key.decryptSecret( @@master_key.class.hex_to_bin secret )
            secret = @@master_key.class.bin_to_hex( new_master_key.encryptSecret(plain_text) )
            secret_data[:secret] = secret
            secret_data
        end

        @@master_key = new_master_key
    end

    # Get all decrypted secrets
    def getAll(tags = [])
        tags = [tags] unless tags.is_a? Array
        return_data = []

        @data.each do |secret_data|
            if (tags.empty? || (tags - secret_data[:tags]).empty?) # If no tags or secret has all tags
                return_data.push(
                    name: secret_data[:name],
                    tags: secret_data[:tags] || [],
                    account: secret_data[:account],
                    secret: @@master_key.decryptSecret(@@master_key.class.hex_to_bin secret_data[:secret])
                )
            end
        end

        return_data
    end

end