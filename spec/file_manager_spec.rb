require 'team-secrets/file_manager'

describe FileManager do

    it 'can load a file' do
        fm = FileManager.new
        fm.loadFile do
            <<~YAML
            :YAML: YAML Ain't Markup Language

            :List:
              - Item 1
              - Item 2
              - Item 3

            YAML
        end

        correct = {
            YAML: 'YAML Ain\'t Markup Language',
            List: [
                'Item 1',
                'Item 2',
                'Item 3'
            ]
        }

        expect(fm.data).to eq(correct)

    end

    it 'can export a file' do
        fm = FileManager.new
        fm.data = {
            YAML: 'YAML Ain\'t Markup Language',
            List: [
                'Item 1',
                'Item 2',
                'Item 3'
            ]
        }

        correct = <<~YAML
            ---
            :YAML: YAML Ain't Markup Language
            :List:
            - Item 1
            - Item 2
            - Item 3
        YAML

        fm.writeFile do |result|
            expect(result).to eq(correct)
        end

    end
end