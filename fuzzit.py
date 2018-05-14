import subprocess

payload = 'When doing a cyber security release, you need some things: a logo, a name and a website. Without these things, there is no vulnerability. Seriously. Who would have taken heartbleed seriously if it were not for the logo. It is so awesome. efail.de is another prime example.'.encode('utf-8')

keylen = 8192
recipient = '3777904141FCA92ABFBC6B13D84EF7E72ABEAD61'

# gpg -e -r {recipient}

result = subprocess.run(['gpg', '--encrypt',
                         '--compress-level', '0',
                         '--recipient', recipient],
                        input=payload, stdout=subprocess.PIPE)
encrypted = result.stdout
print('Have {} bytes to touch'.format(len(encrypted)))

# check it decrypts correctly

result = subprocess.run(['gpg', '--decrypt', '--status-fd', '2'],
                        input=encrypted,
                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
recovered = result.stdout
status = result.stderr.decode('latin-1')
assert 'DECRYPTION_OKAY' in status
assert 'GOODMDC' in status
assert recovered == payload

print('Untouched version done!')

for i in range((keylen//8)+36,len(encrypted)):
    print(str(i))

    m_encrypted = encrypted[:i] + bytes([(encrypted[i]+1) % 256]) + encrypted[i+1:]
    result = subprocess.run(['gpg', '--decrypt', '--status-fd', '2'],
                        input=m_encrypted,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE)

    decrypted = result.stdout
    if len(decrypted):
        if decrypted != payload:
            status = result.stderr.decode('latin-1')
            assert 'DECRYPTION_OKAY' not in status
            assert 'GOODMDC' not in status

            print('Got a result for i {}. stderr: \n{}\n'.format(i, status))
            print('original:  {}'.format(payload))
            print('decrypted: {}'.format(decrypted))
print('Done')
