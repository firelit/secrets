#!/usr/bin/env ruby
require 'rubygems'
require 'gli'

require 'yaml'
require 'fileutils'

require 'digest'
require 'openssl'

require 'secrets'

include GLI::App

program_desc 'Secrets - sharing secrets secretly'

pre do |global_options,command,options,args|
    # Check file structure
    Secrets.checkFileStructure
end

desc 'Start a new Secrets repository'
long_desc 'Create the necessary file structure to create a new Secrets repository'
skips_pre

command :init do |c|

    c.desc 'First user\'s name'
    c.flag [:u,:user], type: String, must_match: /\A.+\Z/, default_value: %x(echo $USER)

    c.desc 'Path to your public key (in PEM format)'
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

        print "Writing manifest.yaml...\n"

        manifestYaml = {
            users_file: {
                path: 'users.yaml',
                signature: Secrets::calculateSignature(master_key, userYaml)
            },
            secrets_file: {
                path: 'secrets.yaml',
                signature: nil #Secrets::calculateSignature(master_key, secretsYaml)
            }
        }.to_yaml

        File.write('manifest.yaml', manifestYaml)

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
            raise 'Not yet implemented'

            # List all users

        end
    end

    c.desc 'Remove a user'
    c.command :rm do |add|
        add.action do
            raise 'Not yet implemented'

            # Check signatures
            # Use current user's private key to get master key from lock_box
            # Use master key to get all secrets
            # Remove old user's record & public key
            # Generate new master key
            # Encrypt all secrets with new master key
            # Encrypt master key with each user's public key, placing in lock_box
            # Update signatures

        end
    end

end

desc 'Manage the secrets in this Secrets repository'
long_desc 'Add, read and remove secrets that users can retrieve from this Secrets repository'

command :secret do |c|

    c.desc 'Add a new secret'
    c.command :add do |add|
        add.action do |global_options,options,args|
            raise 'Not yet implemented'

            # Check signatures
            # Use current user's private key to get master key from lock_box
            # Add new secret's record
            # Encrypt secret with master key
            # Update signatures

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