
require 'users'
require 'fileutils'

describe Users do

    context 'user management' do
        temp_folder = File.dirname(File.dirname(__FILE__)) +'/tmp'

        before(:all) do
            Dir.mkdir(temp_folder) unless File.exists?(temp_folder)
        end

        after(:all) do
            FileUtils.rm_rf(temp_folder+'/users') if File.exists?(temp_folder+'/users')
        end

        it 'can add a user' do
            users = Users.new

            users.working_dir = temp_folder
            users.user_dir = temp_folder+'/users'

            users.add('new_guy', File.dirname(__FILE__) +'/support/test_key.pub.pem')
            users.add('new_gal', File.dirname(__FILE__) +'/support/test_key.pub.pem')

            expect(users.data).to be_a(Array)
            expect(users.data.size).to eq(2)
            expect(users.data[0].keys).to eq([:user, :public_key, :added, :lock_box, :sha256])
        end

        skip 'can find a user' do
            # TODO
        end

        skip 'can remove a user' do
            # TODO
        end
    end

end