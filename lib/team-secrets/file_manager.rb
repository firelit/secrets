require 'yaml'

class FileManager

    attr_accessor :data

    def loadFile(file = nil)
        if block_given?
            string_data = yield
        else
            raise 'No file given' if file.nil?
            string_data = File.read(file)
        end

        @data = YAML.load(string_data)
    end

    def writeFile(file = nil)
        yaml = @data.to_yaml

        if block_given?
            yield yaml
        else
            raise 'No file given' if file.nil?
            File.write(file, yaml)
        end

        yaml
    end

end