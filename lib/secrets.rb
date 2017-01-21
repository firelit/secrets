require 'openssl'

class Secrets < FileManager

    attr_accessor :working_dir, :master_key

    def initialize(master_key = nil)
        @@working_dir = Dir.pwd
        @@master_key = master_key unless master_key.nil?
        @data = @data || []
    end

    # - name: SEND_GRID
    #   category: PROD
    #   account: my_user_name
    #   secret: 010b606069e6e63cd24c9cf60d08351775539...
    #   added: 2017-01-14 09:02:16.906998000 -05:00

    # Add a secret
    def add(secret_name, secret, account = nil, category = nil, notes = nil)
        unless find(secret_name, category, false).nil?
            raise 'Secret already exists, delete existing secret to replace'
        end

        secret_data = {
            name: secret_name,
            category: category,
            account: account, # like the user name or email, if applicable
            secret: @@master_key.encryptSecret(secret),
            notes: notes,
            added: Time.now
        }

        @data.push secret_data
    end

    # Remove a secret
    def remove(secret_name, category = nil)
        @data.keep_if do |secret_data|
            if (secret_data[:name] == secret_name) && (secret_data[:category] == category)
                false
            else
                true
            end
        end
    end

    # Search for a secret
    def find(secret_name, category = nil, decrypt = true)
        @data.each do |secret_data|
            if (secret_data[:name] == secret_name) && (secret_data[:category] == category)
                return_data = secret_data.dup
                return_data[:secret] = @@master_key.decryptSecret(return_data[:secret]) if decrypt
                return return_data
            end
        end
        nil
    end

    # Get decrypted secret
    def getSecret(secret_name, category = nil)
        res = find(secret_name, category)
        return nil if res.nil?
        res[:secret]
    end

    # Get all decrypted secrets
    def getAll(category = nil)
        return_data = []

        @data.each do |secret_data|
            if (secret_data[:category] == category)
                return_data.push(
                    name: secret_data[:name],
                    category: secret_data[:category],
                    account: secret_data[:account],
                    secret: @@master_key.decryptSecret(secret_data[:secret])
                )
            end
        end

        return_data
    end

end