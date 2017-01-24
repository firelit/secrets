require_relative './file_manager'

class Manifest < FileManager

    def initialize(master_key)
        unless (master_key.decrypted.is_a? String) && master_key.decrypted.length
            raise 'Master key must be decrypted'
        end

        @@working_dir = Dir.pwd
        @master_key = master_key
        @data = @data || {}
    end

    def validate

        unless File.exists?(@@working_dir +'/manifest.yaml')
            raise 'Required manifest.yaml does not exist'
        end

        loadFile(@@working_dir +'/manifest.yaml')

        unless @data.is_a? Object
            raise 'No valid data in manifest.yaml'
        end

        if @data[:secrets_file].nil? || @data[:users_file].nil?
            raise 'Manifest.yaml must list a secrets_file and users_file'
        end

        @data.each do |key, value|

            unless value.is_a? Object
                raise "#{key} does not have required data"
            end

            unless File.exists?(value[:path])
                raise "#{key} does not exist"
            end

            file_string = File.read @data[key][:path]
            signature = @master_key.sign file_string

            unless signature == value[:signature]
                raise "#{key} signature does not match"
            end

        end

        true
    end

    def update
        ['users', 'secrets'].each do |file|

            file_name = file +'.yaml'
            absolute = @@working_dir +'/'+ file_name

            unless File.exists?(absolute)
                raise "#{file_name}.yaml does not exist, cannot update manifest"
            end

            signature = @master_key.sign File.read(absolute)

            @data[(file + '_file').to_sym] = {
                path: file_name,
                signature: signature
            }

        end
    end
end
