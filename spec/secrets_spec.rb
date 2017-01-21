
require 'secrets'
require 'fileutils'

describe Secrets do

    context 'secret management' do
        master_key = MasterKey.generate
        secrets = Secrets.new master_key

        it 'can add a secret' do
            # add(secret_name, secret, account = nil, category = nil, notes = nil)
            secrets.add('SMTP_PASS', 'sMith_bArney!', 'mailer@example.com', :PROD, 'Production SMTP password')
            secrets.add('SMTP_PASS', 'jAmes_fRanke1', 'dev@example.com', :DEV, 'Development SMTP password')
            secrets.add('SMS_API_KEY', '843jds83jd82jd', nil, :PROD)
            secrets.add('DEPLOY_KEY', '84dk84ujd83jeallmxcjrujdjjfjkhkjhakjshdfjk')

            expect(secrets.data).to be_a(Array)
            expect(secrets.data.size).to eq(4)
            expect(secrets.data[0].keys).to eq([:name, :category, :account, :secret, :notes, :added])
            expect(secrets.data[0][:name]).to eq('SMTP_PASS')
            expect(secrets.data[0][:secret]).to_not eq('sMith_bArney!')
        end

        it 'find a secret with data' do
            # No category
            res = secrets.find('SMTP_PASS')
            expect(res).to be_nil

            # With category
            res = secrets.find('SMTP_PASS', :DEV, false)
            expect(res[:name]).to eq('SMTP_PASS')
            expect(res[:secret]).to_not eq('jAmes_fRanke1')
            expect(res[:account]).to eq('dev@example.com')
            expect(res[:category]).to eq(:DEV)
            expect(res[:notes]).to eq('Development SMTP password')
            expect(res[:added]).to be
        end

        it 'can get a secret' do
            # No category
            res = secrets.getSecret('SMTP_PASS')
            expect(res).to be_nil

            # With category
            res = secrets.getSecret('SMTP_PASS', :DEV)
            expect(res).to eq('jAmes_fRanke1')

            # Can we get it twice?
            res = secrets.getSecret('SMTP_PASS', :DEV)
            expect(res).to eq('jAmes_fRanke1')

            # With the other category
            res = secrets.getSecret('SMTP_PASS', :PROD)
            expect(res).to eq('sMith_bArney!')

            # A longer string
            res = secrets.getSecret('SMS_API_KEY', :PROD)
            expect(res).to eq('843jds83jd82jd')

            # No category
            res = secrets.getSecret('DEPLOY_KEY')
            expect(res).to eq('84dk84ujd83jeallmxcjrujdjjfjkhkjhakjshdfjk')
        end

        skip 'can return all secrets' do
            # TODO
        end

        skip 'can remove a secret' do
            # TODOc
        end
    end

end