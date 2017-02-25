require 'team-secrets/master_key'

describe MasterKey do

    context 'doing hexidecimal conversion' do
        it 'can convert a string to hexidecimal string' do
            res = MasterKey.bin_to_hex('Hello!')
            expect(res).to eq('48656c6c6f21')
        end

        it 'can convert a hexidecimal string to binary' do
            res = MasterKey.hex_to_bin('576f726c6421')
            expect(res).to eq('World!')
        end

        it 'can go to hexidecimal and back' do
            res = MasterKey.bin_to_hex('Hello World!!')
            back = MasterKey.hex_to_bin(res)

            expect(back).to eq('Hello World!!')
        end
    end

    context 'generating AES keys' do
        it 'can generate a new AES key' do

            nk = MasterKey.generate

            expect(nk).to be_a_kind_of(MasterKey)
            expect(nk.instance_variable_get(:@decrypted).length).to eq(MasterKey::CONFIG[:key_len])

        end

        it 'can generate a unique AES key' do

            nk = MasterKey.generate
            nk2 = MasterKey.generate

            expect(nk.instance_variable_get(:@decrypted).length).to eq(MasterKey::CONFIG[:key_len])
            expect(nk2.instance_variable_get(:@decrypted).length).to eq(MasterKey::CONFIG[:key_len])
            expect(nk.instance_variable_get(:@decrypted)).to_not eq(nk2.instance_variable_get(:@decrypted))

        end
    end

    context 'encryption with key pair' do
        it 'can encrypt a new master key with a public key' do

            mk = MasterKey.generate

            pub_key = File.read File.expand_path('../support/test_key.pub.pem', __FILE__)
            mk.encryptWithPublicKey(pub_key)

            expect(mk.instance_variable_get(:@encrypted).length).to be > 50
            expect(mk.instance_variable_get(:@decrypted)).to_not eq(mk.instance_variable_get(:@encrypted))

        end

        it 'can decrypt a master key with a private key' do

            enc = '1f1656df3d2d4f9cd2376bc95f06d64003d0ba286699fde326df091f68ed8d2d287a4f09363c18061b124963ceeaa6136803859d9eaf296cf09011e9262efa5e3950b3cd947466115e251cb547afabb52bd0896fcf93c2796a4ce20795d2a5ea7f2eff6910cf7768f2df4a32ee6d95f8d43287e8af304be2648ebaa51f6d20572084e47b39b63a644546bf73fb28bf2610aeaaa68b9385ad90ec0aaf528019ca2e41553b3f2d722d928f930a54128d74c2a6871de3af9e09ff5e26c51a0740c289b49072c424e978e97b86e983792d54c58eb1a9e9821524d443ec6d01589c46260e09a77e6138ade975c75c0d8ec82480fe19514eab861e56dc1b2f756caef7'

            mk = MasterKey.new(MasterKey.hex_to_bin(enc), true)

            priv_key = File.read File.expand_path('../support/test_key', __FILE__)
            mk.decryptWithPrivateKey(priv_key, '12345')

            expect(mk.instance_variable_get(:@decrypted).length).to be(MasterKey::CONFIG[:key_len])
            expect(mk.instance_variable_get(:@decrypted)).to_not eq(mk.instance_variable_get(:@encrypted))

        end
    end

    context 'encryption functionality' do
        it 'can encrypt a string' do

            mk = MasterKey.new('1234'*8, false)
            res = mk.encryptSecret('My Secret')

            expect(res).to_not eq('My Secret')

        end

        it 'can not decrypt a string with the wrong key' do

            mk = MasterKey.new('1234'*8, false)
            res = mk.encryptSecret('My Secret 2')

            mk2 = MasterKey.new('0000'*8, false)

            expect { back = mk2.decryptSecret(res) }.to raise_error(/bad decrypt/)

        end

        it 'can encrypt and decrypt a string' do

            mk = MasterKey.new('1234'*8, false)
            res = mk.encryptSecret('My Secret 3')

            mk2 = MasterKey.new('1234'*8, false)
            back = mk2.decryptSecret(res)

            expect(back).to eq('My Secret 3')

        end
    end
end