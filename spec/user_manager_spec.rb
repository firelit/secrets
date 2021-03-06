require 'team-secrets/user_manager'
require 'fileutils'

describe UserManager do

    context 'user management' do
        temp_folder = File.dirname(File.dirname(__FILE__)) +'/tmp'

        before(:all) do
            Dir.mkdir(temp_folder) unless File.exists?(temp_folder)
        end

        after(:all) do
            FileUtils.rm_rf(temp_folder+'/users') if File.exists?(temp_folder+'/users')
        end

        it 'can add a user' do
            users = UserManager.new

            users.working_dir = temp_folder
            users.user_dir = temp_folder+'/users'

            users.add('new_guy', File.dirname(__FILE__) +'/support/test_key.pub.pem')
            users.add('new_gal', File.dirname(__FILE__) +'/support/test_key.pub.pem')

            expect(users.data).to be_a(Array)
            expect(users.data.size).to eq(2)
            expect(users.data[0].keys).to eq([:user, :public_key, :added, :lock_box, :sha256])
            expect(users.all).to eq(['new_guy', 'new_gal'])
        end

        it 'can find a user' do
            users = UserManager.new

            users.working_dir = temp_folder
            users.user_dir = temp_folder+'/users'

            users.add('new_guy', File.dirname(__FILE__) +'/support/test_key.pub.pem')
            users.add('new_gal', File.dirname(__FILE__) +'/support/test_key.pub.pem')

            expect(users.find('fake_bud')).to be_nil
            expect(users.find('new_guy')).to be
            expect(users.find('new_gal')).to have_key(:public_key)
            expect(users.find('new_gal')[:user]).to eq('new_gal')
        end

        it 'can remove a user' do
            users = UserManager.new

            users.working_dir = temp_folder
            users.user_dir = temp_folder+'/users'

            users.add('good_gal', File.dirname(__FILE__) +'/support/test_key.pub.pem')
            users.add('bad_guy', File.dirname(__FILE__) +'/support/test_key.pub.pem')

            expect(users.data).to be_a(Array)
            expect(users.data.size).to eq(2)
            expect(users.all).to eq(['good_gal', 'bad_guy'])

            users.remove('bad_guy')

            expect(users.data.size).to eq(1)
            expect(users.all).to eq(['good_gal'])
        end
    end

end