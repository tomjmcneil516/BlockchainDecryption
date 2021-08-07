import sys

plaintext = open(sys.argv[3], "wb")
ciphertext = open(sys.argv[2], "rb")
password = sys.argv[1]
hash = 0

for element in password:
    c = ord(element)
    hash = c + (hash << 6) + (hash << 16) - hash

x = hash
IV = list()

for i in range(16):
    x = (1103515245*x + 12345) % 256
    IV.append(x)


ciphertext_byte = ciphertext.read(1)
cipher = list()
padding = 0

while ciphertext_byte:
    prev = cipher
    keystream = list()
    cipher = list()
    temp = list()
    text = list()

    for i in range(16):         #read ciphertext
        cipher.append(sum(bytearray(ciphertext_byte)))
        ciphertext_byte = ciphertext.read(1)

    for i in range(16):         #read the keystream
        x = (1103515245*x + 12345) % 256
        keystream.append(x)
        temp.append(cipher[i] ^ keystream[i])

    for i in range(16):         #unshuffle bytes
        bottom = keystream[15 - i] & 0xf
        top = keystream[15 - i]>>4 & 0xf
        tempblock = temp[bottom]
        temp[bottom] = temp[top]
        temp[top] = tempblock

    for i in range(16):
        if len(prev) == 0:      #XOR with IV
            text.append(IV[i] ^ temp[i])
        else:                   #XOR with prev block
            text.append(prev[i] ^ temp[i])
    
    if not ciphertext_byte:
        padding = text[15]

    for i in range(16 - padding):
        plaintext.write(text[i].to_bytes(1,'big'))
