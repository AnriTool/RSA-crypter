from random import randrange, getrandbits

def is_prime(n, k=128):
    """ Test if a number is prime
        Args:
            n -- int -- the number to test
            k -- int -- the number of tests to do
        return True if n is prime
    """
    # Test if n is not even.
    # But care, 2 is prime !
    if n == 2 or n == 3:
        return True
    if n <= 1 or n % 2 == 0:
        return False
    # find r and s
    s = 0
    r = n - 1
    while r & 1 == 0:
        s += 1
        r //= 2
    # do k tests
    for _ in range(k):
        a = randrange(2, n - 1)
        x = pow(a, r, n)
        if x != 1 and x != n - 1:
            j = 1
            while j < s and x != n - 1:
                x = pow(x, 2, n)
                if x == 1:
                    return False
                j += 1
            if x != n - 1:
                return False
    return True


def generate_prime_candidate(length):
    """ Generate an odd integer randomly
        Args:
            length -- int -- the length of the number to generate, in bits
        return a integer
    """
    # generate random bits
    p = getrandbits(length)
    # apply a mask to set MSB and LSB to 1
    p |= (1 << length - 1) | 1
    return p


def generate_prime_number(length):
    """ Generate a prime
        Args:
            length -- int -- length of the prime to generate, in          bits
        return a prime
    """
    p = 4
    # keep generating while the primality test fail
    while not is_prime(p, 128):
        p = generate_prime_candidate(length)
    return p


def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x

def crypt(original_text, open_exp, public_key):
    keyLen = len(str(public_key))
    lst = list()
    for i in original_text:
        lst.append(ord(i))

    crypt = ""
    for i in lst:
        cryptCh = str(pow(i, open_exp, public_key))
        nulls = keyLen - len(cryptCh)
        crypt = crypt + ("0" * nulls + cryptCh)
    return str(crypt)

def decrypt(crypted_text, private_key, public_key):
    keyLen = len(str(public_key))
    decrypt = list()
    for i in range(keyLen, len(crypted_text) + keyLen, keyLen):
        decrypt.append(int(crypted_text[i - keyLen:i]))

    decrypted_text = ""
    for i in decrypt:
        decrypted_text = decrypted_text + chr(pow(i, private_key, public_key))
    return decrypted_text




print("test 1/2/3")
test = int(input())
while test != 0:
    if test == 1:
        k = 512
        p = generate_prime_number(k)
        q = generate_prime_number(k)
        n = p*q
        elFunc = (p-1)*(q-1)



        print("Open E: 3,5,17,257,65537")
        openE = int(input())

        m, a, d = extended_gcd(elFunc, openE)
        while m != 1:
            print('Выберите Экспоненту')
            print("Open E: 3,5,17,257,65537")
            openE = int(input())
            m, a, d = extended_gcd(elFunc, openE)




        print('--------p--------')
        print(p)
        print('--------q--------')
        print(q)
        print('--------M--------')
        print(m)
        print('--------A--------')
        print(a)
        print('--------d--------')
        print(d)
        print('--------ПРОВЕРКА на 1--------')
        print((d * openE) % elFunc)

        public_key = "RSAPublicKey ::= SEQUENCE {\n\t modulus "+ str(n) + \
                     ",\n\t publicExponent "+ str(openE) + "\n}"
        print(public_key)

        private_key = "RSAPrivateKey ::= SEQUENCE { \n\t modulus " + str(n) + \
                      ",\n\t publicExponent " + str(openE) + \
                      ",\n\t privateExponent " +str(d) + \
                      ",\n\t prime1 " +str(p) + \
                      ",\n\t prime2 " +str(q) + ",\n}"
        print(private_key)
        test = -1


    if test == 2:
        public_key = 106937044967761521677906623513349393705632896322334406578948168381244727379379147716254477489452808249654082780467258837354993768647931103764427565224420818638361409480424116944526324440962597006840448762266455345059757577612538113536100961557062047730321086213152204438344120930743893754248349201871326002173
        prime1 = 11805708221347796146199418573623033805741311110956870703914805412703720359387817102938940808802667138685848851503091346592800780636845720336893780977737477
        prime2 = 9058079613927056455939431948838779125480714422575183982423184126705467208073550045654864497409033726343411058580856975879788552610826037304546245184375449
        private_key = -42774817987104608671162649405339757482253158528933762631579267352497890951751659086501790995781123299861633112186903534941997507459172441505771026089768319109829429682228605922270320791659866313925966092084707602828087267369988260867580947100702334411782422781296848196008659336564258432996283104738065555699
        pubE = 5

        text = "Hello world\ntext\t"
        keyLen = len(str(public_key))

        #crypt
        lst = list()
        for i in text:
            lst.append(ord(i))
        print("text to int")
        print(lst)
        print("chrlen = " + str(keyLen))

        crypt = ""
        for i in lst:
            cryptCh = str(pow(i,pubE,public_key))
            nulls = keyLen - len(cryptCh)
            crypt = crypt + ("0"*nulls + cryptCh)
        print("crypyed:")
        print(str(crypt))

        #Decrypt
        decrypt = list()
        for i in range(keyLen,len(crypt) + keyLen, keyLen):
            decrypt.append(int(crypt[i - keyLen:i]))

        print("dell nulls decrypt:")
        print(decrypt)


        dec_text = ""
        for i in decrypt:
            dec_text = dec_text +  chr(pow(i, private_key, public_key))
        print(dec_text)
        test = -1

    if test == 3:

        print('Выбирите количество бит(степень двойки)')
        k = int(input())
        p = generate_prime_number(k)
        q = generate_prime_number(k)
        n = p * q
        elFunc = (p - 1) * (q - 1)

        print("Open E: 3,5,17,257,65537")
        open_exp = int(input())

        m, a, d = extended_gcd(elFunc, open_exp)
        while m != 1:
            print('Выберите Экспоненту')
            print("Open E: 3,5,17,257,65537")
            open_exp = int(input())
            m, a, d = extended_gcd(elFunc, open_exp)

        public_key_str = "RSAPublicKey ::= SEQUENCE {\n\t modulus " + str(n) + \
                     ",\n\t publicExponent " + str(open_exp) + "\n}"
        print(public_key_str)

        private_key_str = "RSAPrivateKey ::= SEQUENCE { \n\t modulus " + str(n) + \
                      ",\n\t publicExponent " + str(open_exp) + \
                      ",\n\t privateExponent " + str(d) + \
                      ",\n\t prime1 " + str(p) + \
                      ",\n\t prime2 " + str(q) + ",\n}"
        print(private_key_str)



        public_key = n
        private_key = d

        print("Введите текст:")
        text = input()
        keyLen = len(str(public_key))

        # crypt
        # lst = list()
        # for i in text:
        #     lst.append(ord(i))
        # print("text to int")
        # print(lst)
        # print("chrlen = " + str(keyLen))
        #
        # crypt = ""
        # for i in lst:
        #     cryptCh = str(pow(i, pubE, public_key))
        #     nulls = keyLen - len(cryptCh)
        #     crypt = crypt + ("0" * nulls + cryptCh)
        # print("crypyed:")
        # print(str(crypt))

        crypted = crypt(text,open_exp, public_key)
        print(crypted)

        # Decrypt
        # decrypt = list()
        # for i in range(keyLen, len(crypt) + keyLen, keyLen):
        #     decrypt.append(int(crypt[i - keyLen:i]))
        #
        # print("dell nulls decrypt:")
        # print(decrypt)
        # dec_text = ""
        # for i in decrypt:
        #     dec_text = dec_text + chr(pow(i, private_key, public_key))
        decrypted = decrypt(crypted, private_key, public_key)
        print(decrypted)
        test = -1

    else:
        print("\n\ntest 1/2/3")
        test = int(input())



