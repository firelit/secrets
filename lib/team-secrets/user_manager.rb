require_relative './file_manager'
require_relative './key_helper'
require_relative './master_key'

class UserManager < FileManager

    attr_accessor :working_dir, :user_dir, :master_key

    HASH_ALG = :sha256

    def initialize(master_key = nil)
        @@working_dir = Dir.pwd
        @@user_dir = @@working_dir + '/users'
        @data = @data || []
        @master_key = master_key unless master_key.nil?
    end

    # Add a user
    #  - Store public key
    #  - Add to listing
    def add(user_name, public_key_file)
        unless find(user_name).nil?
            raise 'User already exists, delete existing user record to replace'
        end

        public_key = KeyHelper.getPublicKey(public_key_file)
        key_file_hash = self.class.calcHash(HASH_ALG, public_key)

        unique_file_name = self.class.calcHash(HASH_ALG, key_file_hash + user_name)
        key_file = 'users/' + unique_file_name[0..10] + '.pem'

        Dir.mkdir(@@user_dir) unless File.exists?(@@user_dir)
        File.write(@@working_dir +'/'+ key_file, public_key)

        # - user: george
        #   public_key: users/eb0545f9010.pem
        #   added: 2017-01-14 09:02:16.906998000 -05:00
        #   sha256: eb0545f9010b606069e6e63cd24c9cf60d08351775539d878055cbf3330afafa
        #   lock_Box: 010b606069e6e63cd24c9cf60d08351775539...

        user_data = {
            user: user_name,
            public_key: key_file, # folder & file, relative to working directory
            added: Time.now,
            lock_box: 'error - should be replaced'
        }

        user_data[HASH_ALG] = key_file_hash

        @data.push user_data
        rotateMasterKey

    end

    # Remove a user
    #  - Remove public key
    #  - Remove from listing
    def remove(user_name)
        @data = @data.keep_if do |user_data|
            next true if user_data[:user] != user_name
            File.delete(@@working_dir +'/'+ user_data[:public_key])
            false
        end
        rotateMasterKey
    end

    # Search for a user
    def find(user_name)
        @data.each do |user_data|
            return user_data if user_data[:user] == user_name
        end
        nil
    end

    # List all user names
    def all
        ret = []
        @data.each { |user_data| ret.push user_data[:user] }
        ret
    end

    # Rotate master key
    #  - Create a new master key
    #  - Update all lock boxes
    def rotateMasterKey
        @master_key = MasterKey.generate

        @data.map! do |user_data|
            public_key = getUserKey user_data[:public_key], user_data[HASH_ALG]
            user_data[:lock_box] = MasterKey.bin_to_hex @master_key.encryptWithPublicKey(public_key)
            user_data
        end
    end

    # Get the user's public key as a string
    def getUserKey(file_name, check_hash)
        raise 'User key doesn\'t exist' unless File.exists?(@@working_dir +'/'+ file_name)
        file_data = File.read(@@working_dir +'/'+ file_name)
        unless (self.class.calcHash(HASH_ALG, file_data) == check_hash)
            raise('Key digest mismatch for '+ file_name)
        end
        file_data
    end

    def self.calcHash(algo, string)
        raise 'Hash algorithim not supported' unless algo == HASH_ALG
        Digest::SHA256.hexdigest string
    end

end