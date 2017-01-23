#!/usr/bin/env ruby
require 'rubygems'
require 'gli'

require 'yaml'
require 'fileutils'

require 'digest'
require 'openssl'

require './lib/manifest'
require './lib/users'
require './lib/secrets'

include GLI::App

program_desc 'Secrets - sharing secrets secretly'

pre do |global_options,command,options,args|
    config = File.read('config.yaml') if File.exists?('config.yaml')
    config = YAML.load(config) || {}

    unless options.key? :user && !options[:user].nil?
        if config.key? :user
            options[:user] = config[:user]
        else
            puts 'Your user name was not specified. Use the `-u` flag or put it in config.yaml.'
            next false
        end
    else
        options[:user] = options[:user].strip
    end

    unless options.key? :private && !options[:user].nil?
        if config.key? :private
            options[:private] = config[:private]
        else
            puts 'Your private key was not specified. Use the `-p` flag or put it in config.yaml.'
            next false
        end
    end

    true
end

valid_user_names = /\A[A-Z0-9_\.]+\Z/i

desc 'Start a new Secrets repository'
long_desc 'Create the necessary file structure to create a new Secrets repository'

skips_pre
command :init do |c|

    c.desc 'Your user name'
    c.flag [:u,:user], type: String, must_match: valid_user_names, default_value: %x(echo $USER)

    c.desc 'Path to public key (in PEM format)'
    c.flag [:k,:key_file], type: String, must_match: /\A.+\Z/, required: true

    c.action do |global_options,options,args|
        raise 'OpenSSL must be installed and in the PATH' unless system("openssl version")

        print "Checking public key...\n"
        raise 'Public key not found' unless File.exists?(options[:key_file])

        print "Creating users directory & users.yaml...\n"
        user = options[:user].strip

        users_file = Users.new
        users_file.add user, options[:key_file]
        # New master key
        master_key = users_file.master_key
        users_file.writeFile 'users.yaml'

        print "Creating template secrets.yaml...\n"

        secrets_file = Secrets.new
        secrets_file.writeFile 'secrets.yaml'

        print "Writing manifest.yaml...\n"

        manifest = Manifest.new master_key
        manifest.update
        manifest.writeFile 'manifest.yaml'

        print 'Done!'
    end
end

desc 'Manage users for this Secrets repository'
long_desc 'Add and remove users or servers who will be able to manage this Secrets repository'

command :user do |c|

    c.desc 'Add a new user'
    c.command :add do |add|
        add.action do |global_options,options,args|
            raise 'Not yet implemented'

            # Check signatures
            # Use current user's private key to get master key from lock_box
            # Use master key to get all secrets
            # Add new user's record & public key
            # Generate new master key
            # Encrypt all secrets with new master key
            # Encrypt master key with each user's public key, placing in lock_box
            # Update signatures

        end
    end

    c.desc 'List all users'
    c.command :list do |add|
        add.action do

            # List all users
            users = Users.new
            users.loadFile 'users.yaml'

            puts "#{users.all.length} users:\n"
            users.all.each do |user|
                puts user+"\n"
            end

        end
    end

    c.desc 'Your user name'
    c.flag [:u,:user], type: String, must_match: valid_user_names

    c.desc 'Path to your private key'
    c.flag [:p,:private], type: String, must_match: /\A.+\Z/

    c.desc 'User to remove'
    c.flag [:r,:remove], type: String, must_match: valid_user_names, required: true

    c.desc 'Remove a user'
    c.command :rm do |add|
        add.action do |global_options,options,args|

            # Check signatures
            # Use current user's private key to get master key from lock_box
            # Use master key to get all secrets
            # Remove old user's record & public key
            # Generate new master key
            # Encrypt all secrets with new master key
            # Encrypt master key with each user's public key, placing in lock_box
            # Update signatures
            users = Users.new
            user_data = users.find options[:user]

            raise 'Your user account could not be found' if user_data.nil?

            master_key = MasterKey.new MasterKey.hex_to_bin(user_data[:lock_box])
            master_key.decryptWithPrivateKey File.read(options[:private])

            users.master_key = master_key

            remove_data = users.find options[:remove]

            raise 'User not found for removal' if remove_data.nil?

            users.remove remove_data[:user]

        end
    end

end

desc 'Manage the secrets in this Secrets repository'
long_desc 'Add, read and remove secrets that users can retrieve from this Secrets repository'

command :secret do |c|

    c.desc 'Your user name'
    c.arg_name 'user'
    c.flag [:u,:user], type: String, must_match: valid_user_names

    c.desc 'Path to your private key'
    c.arg_name 'private'
    c.flag [:p,:private], type: String, must_match: /\A.+\Z/

    c.desc 'Name of this secret (e.g., SMTP_PASS)'
    c.arg_name 'name'
    c.flag [:n,:name], type: String

    c.desc 'The optional account name (e.g., a username)'
    c.arg_name 'account', :optional
    c.flag [:a,:account], type: String

    c.desc 'The optional category (e.g., PROD)'
    c.arg_name 'category', :optional
    c.flag [:c,:category], type: String

    c.desc 'Any optional notes'
    c.arg_name 'notes'
    c.flag [:notes], type: String

    c.arg_name 'plain_text_secret', :required

    c.desc 'Add a new secret'
    c.command :add do |add|
        add.action do |global_options,options,args|

            if options[:name].nil?
                raise 'A name must be specified'
            end

            if args.empty?
                raise 'No secret given'
            end

            # Check signatures
            # Use current user's private key to get master key from lock_box
            # Add new secret's record
            # Encrypt secret with master key
            # Update signatures

            users = Users.new
            users.loadFile 'users.yaml'
            user_data = users.find options[:user]

            raise 'Your user account could not be found' if user_data.nil?

            master_key = MasterKey.new MasterKey.hex_to_bin(user_data[:lock_box])
            master_key.decryptWithPrivateKey File.read(options[:private])

            secrets = Secrets.new master_key
            secrets.loadFile 'secrets.yaml'
            secrets.add options[:name].strip, args[0], options[:account], options[:category]
            secrets.writeFile 'secrets.yaml'

            manifest = Manifest.new master_key
            manifest.update
            manifest.writeFile 'manifest.yaml'
        end
    end

    c.desc 'List all secrets'
    c.command :list do |add|
        add.action do
            raise 'Not yet implemented'

            # Check signatures
            # List all secrets

        end
    end

    c.desc 'Reveal a secret'
    c.command :show do |add|
        add.action do
            raise 'Not yet implemented'

            # Check signatures
            # Use current user's private key to get master key from lock_box
            # Decrypt secret with master key

        end
    end

    c.desc 'Remove a secret'
    c.command :rm do |add|
        add.action do
            raise 'Not yet implemented'

            # Check signatures
            # Use current user's private key to get master key from lock_box
            # Remove secret from listing
            # Update signatures

        end
    end

end

on_error do |exception|
    # Use GLI error handling for GLI exception
    next true if exception.class.name.split("::").first == 'GLI'

    $stderr.puts exception.message
    false # skip GLI's error handling
end

exit run(ARGV)