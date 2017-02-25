#!/usr/bin/env ruby
require 'rubygems'
require 'gli'
require 'io/console'

require 'yaml'
require 'fileutils'

require 'digest'
require 'openssl'

require_relative 'team-secrets/manifest_manager'
require_relative 'team-secrets/user_manager'
require_relative 'team-secrets/secret_manager'

include GLI::App

program_desc 'Secrets - sharing secrets secretly'

pre do |global_options,command,options,args|
    config = File.read('config.yaml') if File.exists?('config.yaml')
    config = YAML.load(config) if config
    config ||= {}

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

    c.desc 'Your username'
    c.flag [:u,:user], type: String, must_match: valid_user_names

    c.desc 'Path to public key (in PEM format)'
    c.flag [:k,:key_file], type: String

    c.action do |global_options,options,args|
        raise 'OpenSSL must be installed and in the PATH' unless system("openssl version")

        user_name = options[:user]

        until user_name && (/\A.+\z/i =~ user_name)
            default = `echo $USER`.chomp
            print "Your username (no spaces) [#{default}]: "
            user_name = STDIN.gets.chomp
            user_name = default if user_name.empty?
        end

        key_file = options[:key_file]

        until key_file && File.exists?(key_file)
            print 'Path to public key: '
            key_file = STDIN.gets.chomp
            puts "File does not exist or cannot be acccessed." unless File.exists?(key_file)
        end

        puts "Creating users directory & users.yaml..."

        users_file = UserManager.new
        users_file.add user_name, key_file
        # New master key
        master_key = users_file.master_key
        users_file.writeFile 'users.yaml'

        puts "Creating template secrets.yaml..."

        secrets_file = SecretManager.new
        secrets_file.writeFile 'secrets.yaml'

        puts "Writing manifest.yaml..."

        manifest = ManifestManager.new master_key
        manifest.update
        manifest.writeFile 'manifest.yaml'

        puts green('Done!')
        puts 'Now, create a new repository with these files and commit. Your new secrets repo is ready to go.'
    end
end

desc 'Manage users for this Secrets repository'
long_desc 'Add and remove users or servers who will be able to manage this Secrets repository'

command :user do |c|

    c.desc 'Your user name'
    c.flag [:u,:user], type: String, must_match: valid_user_names

    c.desc 'Path to your private key'
    c.flag [:p,:private], type: String

    c.desc 'Add a new user'
    c.command :add do |add|
        add.action do |global_options,options,args|

            print 'New user\'s name: '
            new_user = STDIN.gets.chomp
            raise 'A user name must be specified' if new_user.empty?

            print 'Path to user\'s public key: '
            key_file = STDIN.gets.chomp
            raise "File does not exist or cannot be acccessed." unless File.exists?(key_file)

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
            users = UserManager.new
            users.loadFile 'users.yaml'

            puts "#{users.all.length} users:\n"
            users.all.each do |user|
                puts user+"\n"
            end

        end
    end

    c.desc 'Remove a user'
    c.command :rm do |add|
        add.action do |global_options,options,args|

            print 'User to remove: '
            new_user = STDIN.gets.chomp
            raise 'A user name must be specified' if new_user.empty?

            # Check signatures
            # Use current user's private key to get master key from lock_box
            # Use master key to get all secrets
            # Remove old user's record & public key
            # Generate new master key
            # Encrypt all secrets with new master key
            # Encrypt master key with each user's public key, placing in lock_box
            # Update signatures

            master_key = load_master_key(options[:user], options[:private])

            manifest = ManifestManager.new master_key
            manifest.validate

            secrets = SecretManager.new master_key
            secrets.loadFile 'secrets.yaml'

            users = UserManager.new master_key

            remove_data = users.find options[:remove]

            raise 'User not found for removal' if remove_data.nil?

            users.remove remove_data[:user]
            users.writeFile 'users.yaml'

            master_key = users.master_key

            secrets.rotateMasterKey master_key
            secrets.writeFile 'secrets.yaml'

            manifest.master_key = master_key
            manifest.update
            manifest.writeFile 'manifest.yaml'

            print green('Success! ')
            puts 'User removed.'

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
    c.flag [:p,:private], type: String

    c.desc 'Name of this secret (e.g., SMTP_PASS)'
    c.arg_name 'name'
    c.flag [:n,:name], type: String

    c.desc 'The optional account name (e.g., a username)'
    c.arg_name 'account', :optional
    c.flag [:a,:account], type: String

    c.desc 'Optional tags (e.g., PROD)'
    c.arg_name 'tags', :optional
    c.flag [:t,:tags], type: String

    c.desc 'Any optional notes'
    c.arg_name 'notes', :optional
    c.flag [:notes], type: String

    c.desc 'Add a new secret'
    c.command :add do |add|
        add.action do |global_options,options,args|

            if options[:name].nil?
                print 'A name for this secret: '
                options[:name] = STDIN.gets.chomp
                raise 'A name must be specified' if options[:name].empty?
            end

            if options[:account].nil?
                print 'The secret\'s account name (optional): '
                options[:account] = STDIN.gets.chomp
            end

            if options[:tags].nil?
                print 'Tags for this secret, space-separated (optional): '
                options[:tags] = STDIN.gets.chomp
            end

            tags = parse_tags(options[:tags])

            if args.empty?
                print 'Secret to encrypt: '
                secret = STDIN.noecho(&:gets)
                secret = secret.chomp
                raise 'No secret given' if secret.empty?
            else
                secret = args[0]
            end

            # Check signatures
            # Use current user's private key to get master key from lock_box
            # Add new secret's record
            # Encrypt secret with master key
            # Update signatures
            puts

            master_key = load_master_key(options[:user], options[:private])

            manifest = ManifestManager.new master_key
            manifest.validate

            secrets = SecretManager.new master_key
            secrets.loadFile 'secrets.yaml'
            secrets.add options[:name].strip, secret, options[:account], tags
            secrets.writeFile 'secrets.yaml'

            manifest.update
            manifest.writeFile 'manifest.yaml'

            print green('Success! ')
            puts 'New secret has been encrypted and added.'
        end
    end

    c.desc 'List all secrets'
    c.command :list do |add|
        add.action do |global_options,options,args|

            if options[:tags].nil?
                print 'Tags for this secret, space-separated (optional): '
                options[:tags] = STDIN.gets.chomp
            end

            tags = parse_tags(options[:tags])

            # Check signatures
            # List all secrets

            master_key = load_master_key(options[:user], options[:private])

            manifest = ManifestManager.new master_key
            manifest.validate

            secrets = SecretManager.new master_key
            secrets.loadFile 'secrets.yaml'
            all = secrets.getAll tags

            puts 'All secrets: '

            all.each {|tag| puts tag}
        end
    end

    c.desc 'Reveal a secret'
    c.command :show do |add|
        add.action do |global_options,options,args|

            if options[:name].nil?
                print 'The name of the secret: '
                options[:name] = STDIN.gets.chomp
                raise 'A name must be specified' if options[:name].empty?
            end

            if options[:tags].nil?
                print 'Tags for this secret, space-separated (optional): '
                options[:tags] = STDIN.gets.chomp
            end

            tags = parse_tags(options[:tags])

            # Check signatures
            # Use current user's private key to get master key from lock_box
            # Decrypt secret with master key

            master_key = load_master_key(options[:user], options[:private])

            manifest = ManifestManager.new master_key
            manifest.validate

            secrets = SecretManager.new master_key
            secrets.loadFile 'secrets.yaml'
            secret_data = secrets.find options[:name].strip, tags

            secret_data.each do |key, value|
                next if value.nil?
                puts key.to_s + ': ' + value.inspect
            end

        end
    end

    c.desc 'Remove a secret'
    c.command :rm do |add|
        add.action do |global_options,options,args|

            if options[:name].nil?
                print 'The name of the secret: '
                options[:name] = STDIN.gets.chomp
                raise 'A name must be specified' if options[:name].empty?
            end

            if options[:tags].nil?
                print 'Tags for this secret, space-separated (optional): '
                options[:tags] = STDIN.gets.chomp
            end

            tags = parse_tags(options[:tags])

            # Check signatures
            # Use current user's private key to get master key from lock_box
            # Remove secret from listing
            # Update signatures

            master_key = load_master_key(options[:user], options[:private])

            manifest = ManifestManager.new master_key
            manifest.validate

            secrets = SecretManager.new master_key
            secrets.loadFile 'secrets.yaml'
            removed = secrets.remove options[:name].strip, tags

            if removed == 0 then
                puts 'No secrets matched criteria'
                next
            end

            secrets.writeFile 'secrets.yaml'

            manifest.update
            manifest.writeFile 'manifest.yaml'

            print green('Success! ')

            if (removed == 1)
                puts removed +' matching secret has been removed.'
            else
                puts removed +' matching secrets have been removed.'
            end

        end
    end

end

on_error do |exception|
    # Use GLI error handling for GLI exception
    next true if exception.class.name.split("::").first == 'GLI'

    $stderr.puts red(exception.message)

    $stderr.puts exception.backtrace

    false # skip GLI's error handling
end

def load_master_key(user, private_key_file)
    users = UserManager.new
    users.loadFile 'users.yaml'
    user_data = users.find user

    raise "Your user account (#{user}) could not be found" if user_data.nil?

    master_key = MasterKey.new MasterKey.hex_to_bin(user_data[:lock_box])
    master_key.decryptWithPrivateKey File.read(private_key_file)
    master_key
end

def parse_tags(tags)
    return [] if tags.empty?
    tags = tags.split
    tags.keep_if {|tag| !tag.empty?}
    tags.map(&:to_sym)
end

def green(string)
    "\e[32m#{string}\e[0m"
end

def red(string)
    "\e[31m#{string}\e[0m"
end

exit run(ARGV)