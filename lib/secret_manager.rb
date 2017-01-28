require 'openssl'
require 'file_manager'

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
            raise 'Secret already exists, delete existing secret to replace'
        end

        unless tags.is_a? Array
            raise 'Tags must be an array'
        end

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

    # Remove a secret
    def remove(secret_name, tags = [])
        @data.keep_if do |secret_data|
            if (secret_data[:name] == secret_name) && (tag.empty? || (tags - secret_data[:tags]).empty?)
                false
            else
                true
            end
        end
    end

    # Search for a secret
    def find(secret_name, tags = [], decrypt = true)
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

    # Get decrypted secret
    def getSecret(secret_name, tags = [])
        res = find(secret_name, tags)
        return nil if res.empty?
        res = res.map {|x| x[:secret]}
        return res[0] if res.length == 1
        res
    end

    # Get all decrypted secrets
    def getAll(tags = [])
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