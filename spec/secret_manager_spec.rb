require 'team-secrets/secret_manager'
require 'team-secrets/master_key'
require 'fileutils'

describe SecretManager do

    context 'secret management' do
        master_key = MasterKey.generate
        secrets = SecretManager.new master_key

        it 'can add a secret' do
            # add(secret_name, secret, account = nil, category = nil, notes = nil)
            secrets.add('SMTP_PASS', 'sMith_bArney!', 'mailer@example.com', [:PROD], 'Production SMTP password')
            secrets.add('SMTP_PASS', 'jAmes_fRanke1', 'dev@example.com', [:DEV], 'Development SMTP password')
            secrets.add('SMS_API_KEY', '843jds83jd82jd', nil, [:PROD, :DEV])
            secrets.add('DEPLOY_KEY', '84dk84ujd83jeallmxcjrujdjjfjkhkjhakjshdfjk')

            expect(secrets.data).to be_a(Array)
            expect(secrets.data.size).to eq(4)
            expect(secrets.data[0].keys).to eq([:name, :tags, :account, :secret, :notes, :added])
            expect(secrets.data[0][:name]).to eq('SMTP_PASS')
            expect(secrets.data[0][:secret]).to_not eq('sMith_bArney!')
        end

        it 'find a secret with data' do
            # No tag
            res = secrets.find('SMTP_PASS')
            expect(res.length).to eq(2)

            # With tags
            res = secrets.find('SMTP_PASS', [:DEV], false)
            expect(res.length).to eq(1)

            expect(res[0][:name]).to eq('SMTP_PASS')
            expect(res[0][:secret]).to_not eq('jAmes_fRanke1')
            expect(res[0][:account]).to eq('dev@example.com')
            expect(res[0][:tags]).to eq([:DEV])
            expect(res[0][:notes]).to eq('Development SMTP password')
            expect(res[0][:added]).to be
        end

        it 'can get a secret' do
            # No tags
            res = secrets.getSecret('SMTP_PASS')
            expect(res.length).to eq(2)
            expect(res).to include('jAmes_fRanke1')
            expect(res).to include('sMith_bArney!')

            # With tag
            res = secrets.getSecret('SMTP_PASS', :DEV)
            expect(res).to eq('jAmes_fRanke1')

            # Can we get it twice?
            res = secrets.getSecret('SMTP_PASS', [:DEV])
            expect(res).to eq('jAmes_fRanke1')

            # With the other tags
            res = secrets.getSecret('SMTP_PASS', [:PROD])
            expect(res).to eq('sMith_bArney!')

            # With both tags, no matches
            res = secrets.getSecret('SMTP_PASS', [:DEV, :PROD])
            expect(res).to be_nil

            # A longer string, matches both tags
            res = secrets.getSecret('SMS_API_KEY', [:DEV, :PROD])
            expect(res).to eq('843jds83jd82jd')

            # No match, wrong tags
            res = secrets.getSecret('SMS_API_KEY', [:DEV, :QA])
            expect(res).to be_nil

            # No category
            res = secrets.getSecret('DEPLOY_KEY')
            expect(res).to eq('84dk84ujd83jeallmxcjrujdjjfjkhkjhakjshdfjk')
        end

        it 'can return all secrets' do
            res = secrets.getAll
            expect(res.length).to eq(4)

            res = secrets.getAll(:DEV)
            expect(res.length).to eq(2)
        end

        it 'can remove a secret' do
            res = secrets.getAll
            expect(res.length).to eq(4)

            # Remove nothing, tag doesn't match
            secrets.remove('SMS_API_KEY', :NOPE)
            res = secrets.getAll
            expect(res.length).to eq(4)

            secrets.remove('SMS_API_KEY', [:PROD, :DEV])
            res = secrets.getAll
            expect(res.length).to eq(3)

            secrets.remove('SMTP_PASS')
            res = secrets.getAll
            expect(res.length).to eq(1)
        end

        it 'can rotate encryption keys' do
            secrets.add('ROTATE_TEST_1', 'alskdfjalskjdf3984')
            secrets.add('ROTATE_TEST_2', '2o341-llakdsjfjfdk')

            secret_ref = []
            for i in 0..2
                secret_ref.push secrets.data[i][:secret]
            end

            secrets.rotateMasterKey(MasterKey.generate)

            for i in 0..2
                expect(secret_ref).not_to include(secrets.data[i][:secret])
            end
        end

    end

end