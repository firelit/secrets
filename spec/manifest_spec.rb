require 'manifest_manager'
require 'master_key'

describe ManifestManager do

    context 'managing the manifest' do
        master_key = MasterKey.generate

        before(:all) do
            Dir.chdir File.dirname(File.dirname(__FILE__))
            Dir.mkdir 'tmp' unless File.exists? 'tmp'
            Dir.chdir 'tmp'

            File.delete 'manifest.yaml' if File.exists? 'manifest.yaml'

            File.write('users.yaml', 'Sample 1')
            File.write('secrets.yaml', 'Sample 2')
        end

        after(:all) do
            File.delete 'manifest.yaml' if File.exists? 'manifest.yaml'
            File.delete 'users.yaml' if File.exists? 'users.yaml'
            File.delete 'secrets.yaml' if File.exists? 'secrets.yaml'
        end

        it 'can update and write the data' do

            manifest = ManifestManager.new(master_key)

            expect(File.exists?('manifest.yaml')).to eq(false)

            manifest.update
            manifest.writeFile('manifest.yaml')

            expect(manifest.validate).to eq(true)
            expect(File.exists?('manifest.yaml')).to eq(true)

            written = File.read('manifest.yaml')
            data_written = YAML.load(written)

            expect(data_written[:users_file]).to be
            expect(data_written[:users_file].length).to eq(2)
            expect(data_written[:users_file][:path]).to eq('users.yaml')
            expect(data_written[:users_file][:signature]).to match(/\A[0-9a-f]{10,}\z/)

            expect(data_written[:secrets_file]).to be
            expect(data_written[:secrets_file].length).to eq(2)
            expect(data_written[:secrets_file][:path]).to eq('secrets.yaml')
            expect(data_written[:secrets_file][:signature]).to match(/\A[0-9a-f]{10,}\z/)

        end

        it 'can validate the data' do

            expect(File.exists?('manifest.yaml')).to eq(true)

            manifest = ManifestManager.new(master_key)
            manifest.loadFile('manifest.yaml')

            expect(manifest.validate).to eq(true)

            File.write('users.yaml', 'Sample 3')

            expect { manifest.validate }.to raise_error(/signature does not match/)

        end

    end

end
