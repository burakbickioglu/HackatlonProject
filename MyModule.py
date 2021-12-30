import hashlib as hasher
from cryptography.fernet import Fernet


class sifrelemeYontemleri:
    def __init__(self):
        pass

    def hashWithSHA1(text):
        sifreleyici = hasher.sha1()
        sifreleyici.update(text.encode("utf-8"))
        hashedText = sifreleyici.hexdigest()
        return hashedText

    def hashWithSHA256(text):
        sifreleyici = hasher.sha256()
        sifreleyici.update(text.encode("utf-8"))
        hashedText = sifreleyici.hexdigest()
        return hashedText

    def hashWithSHA384(text):
        sifreleyici = hasher.sha384()
        sifreleyici.update(text.encode("utf-8"))
        hashedText = sifreleyici.hexdigest()
        return hashedText

    def hashWithSHA512(text):
        sifreleyici = hasher.sha512()
        sifreleyici.update(text.encode("utf-8"))
        hashedText = sifreleyici.hexdigest()
        return hashedText

    def hashWithMD5(text):
        sifreleyici = hasher.md5()
        sifreleyici.update(text.encode("utf-8"))
        hashedText = sifreleyici.hexdigest()
        return hashedText

    def cryptWithFernet(text):
        # Key oluşturuluyor
        key = Fernet.generate_key()

        # Key değeri f değişkenine atılıyor
        f = Fernet(key)
        sifresizMetin = text
        Tr2Eng = str.maketrans("çğıöşü", "cgiosu")
        sifresizMetin = sifresizMetin.translate(Tr2Eng).encode()

        # Şifresiz metin fernet şifreleme yöntemiyle şifreleniyor
        sifrelenmisMetin = f.encrypt(sifresizMetin)

        # Şifreli metin ve key değerleri return ediliyor
        return sifrelenmisMetin, key

    def decryptWithFernet(text, key):

        # parametre olarak alınan key değeri f değişkenine atılıyor
        f = Fernet(key)
        # Şifreli metin fernet şifreleme yöntemiyle deşifre ediliyor
        d = f.decrypt(text)

        # şifreli metin string değere çevrilip return ediliyor
        return d.decode()

    # Temel olarak, hem anahtardaki karakterlerin hem de ifadenin ascii değerlerini ekler.
    def customEncrypt(key, text):
        encryped = []
        for i, c in enumerate(text):
            key_c = ord(key[i % len(key)])
            msg_c = ord(c)
            encryped.append(chr((msg_c + key_c) % 127))
        return ''.join(encryped)

    def customDecrypt(key, text):
        msg = []
        for i, c in enumerate(text):
            key_c = ord(key[i % len(key)])
            enc_c = ord(c)
            msg.append(chr((enc_c - key_c) % 127))
        return ''.join(msg)


# ------------------------------------------------------------------------------------------------------------------------------------------


class Dilkontrol:

    def __init__(self):
        print("DilKontrol Sınıfı Başlatıldı.")

    def prune(self, text):
        """ Verilen Text içerisindeki noktalama işaretlerini temizler."""
        text = text.strip()
        text = text.replace("...", " ")
        text = text.replace(".", " ")
        text = text.replace("?", " ")
        text = text.replace(",", " ")
        text = text.replace("!", " ")
        return text

    # Parametre kelime olmalıdır. Kelimenin ünlü uyumuna uyup uymadığını kontrol eder.
    def checkspellingrule(self, word):
        """
        Verilen Kelimenin Büyük Ünlü Uyumuna Uyup Uymadığını Kontrol Eder.
        :param word:
        :type word: string

        :rtype: bool / hatalı zamanlarda integer -1
        :return Kelimenin büyük ünlü uyumuna uyup uymadığını gösterir.
        """
        try:
            if self.iscontainsyllables(word) == -1 or not word.isalpha():
                raise ValueError
        except ValueError:
            print(word + " bir sözcük içermelidir veya sözcük formatında değil.")
            return -1

        # sabitler
        vowelsinword = []  # Kelime içerisindeki ünlü harfler
        thinvowels = {'E', 'İ', 'Ö', 'Ü', 'e', 'i', 'ö', 'ü'}
        boldvowels = {'A', 'I', 'O', 'U', 'a', 'ı', 'o', 'u'}

        # Kelime içerisindeki ünlü harfleri alıyoruz.
        for i in range(0, len(word), 1):
            if word[i] in thinvowels or word[i] in boldvowels:
                vowelsinword.append(word[i])

        # Hangi ünlü harfleri takip etmesi gerektiğini seçer.
        vowels = thinvowels if vowelsinword[0] in thinvowels else boldvowels

        # Takip Ettiğimiz ünlü uyumu kırılıyor mu ?
        for character in vowelsinword:
            if character in vowels:
                continue
            else:
                return False
        return True

    def calculationrule(self, text):
        """Büyük Ünlü Uyumuna uyan ve uymayan kelimelerin sayını döndürür.
            :param text:
            :type text: string

            :rtype: dict
            :return Uygun ve Uymayan key değerine sahiptir. Value olarak sayaç değerlerini tutar..
        """
        # Sabit
        validandinvalidwords = {"Uygun": 0, "Uymayan": 0, "Hatalı Sözcük": 0}
        # Text Temizleme işlemi
        text = self.prune(text)
        for word in text.split():  # Text kelimelere bölme
            if self.checkspellingrule(word) == -1:
                validandinvalidwords["Hatalı Sözcük"] = 1 + validandinvalidwords["Hatalı Sözcük"]
            elif self.checkspellingrule(word):
                validandinvalidwords["Uygun"] = 1 + validandinvalidwords["Uygun"]
            else:
                validandinvalidwords["Uymayan"] = 1 + validandinvalidwords["Uymayan"]
        return validandinvalidwords

    def wordcount(self, text=" "):
        """ Verilen Stringteki boşlukları referans alarak kelime sayısını saptar.
            :param text:
            :type text: string

            :rtype: dict / hatalı zamanlarda integer 0
            :return kelime/Hatalı Kelime sayısını döndürür.
        """
        if self.iscontainsyllables(text) == -1:
            return "Parametre hece içermiyor veya boş."

        Words = {"Sözcük": 0, "Hatalı Sözcük": 0}
        text = self.prune(text)
        for word in text.split():
            if word.isalpha():
                Words["Sözcük"] = 1 + Words["Sözcük"]
            else:
                Words["Hatalı Sözcük"] = 1 + Words["Hatalı Sözcük"]
        return Words

    def sentencecount(self, text=" "):
        """ Verilen String değer içerisindeki Cümle sayısını geri döndürür.
            :param text:
            :type text: string

            :rtype: dict
            :return cümle türlerine göre 4 adet key ve value olarak cümlelerin sayısını döndürmektedir.
        """
        if self.iscontainsyllables(text) == -1:
            return "Parametre hece içermiyor veya boş."
        # Sabit
        sentences = {"Soru Cümlesi": 0, "Ünlem Cümlesi": 0, "Eksiltili Cümle": 0, "Cümle": 0}
        text = text.replace("...", "*")
        text = text.replace(" ", "")

        sentences["Soru Cümlesi"] = text.count("?")
        sentences["Ünlem Cümlesi"] = text.count("!")
        sentences["Eksiltili Cümle"] = text.count("*")
        sentences["Cümle"] = text.count(".")
        return sentences

    def vowelscount(self, text=" "):
        """ Verilen String değer içerisindeki ünlü harf ve sayısını geri döndürür.
            :param text:
            :type text: string

            :rtype: dict
            :return Ünlü harflerin bulunduğu bir sözlük içerir ve key değerleri counter görevindedir.
        """
        if self.iscontainsyllables(text) == -1:
            return "Parametre hece içermiyor veya boş."

        text = self.prune(text)
        vowels = {"A": 0, "a": 0,
                  "E": 0, "e": 0,
                  "I": 0, "ı": 0,
                  "İ": 0, "i": 0,
                  "O": 0, "o": 0,
                  "Ö": 0, "ö": 0,
                  "U": 0, "u": 0,
                  "Ü": 0, "ü": 0}
        for c in text:
            if c in vowels.keys():
                vowels[c] = vowels[c] + 1
        return vowels

    def iscontainsyllables(self, text=" "):
        try:
            if len(text) < 2 or text.isspace():
                raise ValueError
        except ValueError:
            return -1


# text = "Merhaba. Nasılsın? Muhteşem! Sen nasılsın? iyi değilim... Peki Sonra görü3şrüz."
# Text = Dilkontrol()
# print(Text.sentencecount(text))
# print(Text.wordcount(text))
# print(Text.vowelscount(text))
# print(Text.calculationrule(text))


# ------------------------------------------------------------------------------------------------------------------------------------------


class help:
    sifrelemeYontemleriYardim = "----------------------------------------------------------------------------------------------------------------------" \
                                "\n-----------------------------------------\nsifrelemeYontemleri " \
                                "sınıfı\n-----------------------------------------\n\n" \
                                "Bu sınıfta text şifreleme işlemleri yapılmaktadır.\n" \
                                "5 Hash 2 Şifreleme algoritması olmak üzere toplam\n7 algoritma ve toplamda 9 " \
                                "fonksiyon bulunmaktadır.\n\n\n" \
                                "-----------------------\n" \
                                "hashWithSHA1 fonksiyonu\n" \
                                "-----------------------\n" \
                                "Bu fonksiyon parametre olarak alınan text değerini\nhashlib kütüphanesi yardımıyla " \
                                "SHA-1 algoritması\nile " \
                                "hashler ve oluşturulan hashlenmiş text değerini\ndöndürür.\n\n" \
                                "Örnek kullanım\n" \
                                "hashedText = sifrelemeYontemleri.hashWithSHA1('Merhaba')\n" \
                                "print('SHA1: ', hashedText)\n\n" \
                                "Ekran çıktısı\n" \
                                "SHA1:  df53c2b7c583ab7c9b0a5ad5912b2db83aa80571\n\n\n" \
                                "-----------------------\n" \
                                "hashWithSHA256 fonksiyonu\n" \
                                "-----------------------\n" \
                                "Bu fonksiyon parametre olarak alınan text değerini\nhashlib kütüphanesi yardımıyla " \
                                "SHA-256 algoritması\nile " \
                                "hashler ve oluşturulan hashlenmiş text değerini\ndöndürür.\n\n" \
                                "Örnek kullanım\n" \
                                "hashedText = sifrelemeYontemleri.hashWithSHA256('Merhaba')\n" \
                                "print('SHA256: ', hashedText)\n\n" \
                                "Ekran çıktısı\n" \
                                "SHA256:  7fdc9f4717c5fe66df286c700fab969b4d6209d03aa84624c5f8f58c17c9c058\n\n\n" \
                                "-----------------------\n" \
                                "hashWithSHA384 fonksiyonu\n" \
                                "-----------------------\n" \
                                "Bu fonksiyon parametre olarak alınan text değerini\nhashlib kütüphanesi yardımıyla " \
                                "SHA-384 algoritması\nile " \
                                "hashler ve oluşturulan hashlenmiş text değerini\ndöndürür.\n\n" \
                                "Örnek kullanım\n" \
                                "hashedText = sifrelemeYontemleri.hashWithSHA384('Merhaba')\n" \
                                "print('SHA384: ', hashedText)\n\n" \
                                "Ekran çıktısı\n" \
                                "SHA384:  " \
                                "063d48756a98c77a3258004300081f1bdbfcca0a4b6fe7953a5c8252622d0a68db86c6743b4d17ceb80af5a877685c30\n\n\n" \
                                "-----------------------\n" \
                                "hashWithSHA512 fonksiyonu\n" \
                                "-----------------------\n" \
                                "Bu fonksiyon parametre olarak alınan text değerini\nhashlib kütüphanesi yardımıyla " \
                                "SHA-512 algoritması\nile " \
                                "hashler ve oluşturulan hashlenmiş text değerini\ndöndürür.\n\n" \
                                "Örnek kullanım\n" \
                                "hashedText = sifrelemeYontemleri.hashWithSHA512('Merhaba')\n" \
                                "print('SHA512: ', hashedText)\n\n" \
                                "Ekran çıktısı\n" \
                                "SHA512:  " \
                                "a834963850d8e6f96dba5ef6a961e5c3a1f605fcf1d12b6da77bd47c0e0e86ee405a8e4161bc12763cd0340daac23582018df1201284a638f7a5cd7826379951\n\n\n" \
                                "-----------------------\n" \
                                "hashWithMD5 fonksiyonu\n" \
                                "-----------------------\n" \
                                "Bu fonksiyon parametre olarak alınan text değerini\nhashlib kütüphanesi yardımıyla " \
                                "MD5 algoritması ile\n" \
                                "hashler ve oluşturulan hashlenmiş text değerini\ndöndürür.\n\n" \
                                "Örnek kullanım\n" \
                                "hashedText = sifrelemeYontemleri.hashWithMD5('Merhaba')\n" \
                                "print('MD5: ', hashedText)\n\n" \
                                "Ekran çıktısı\n" \
                                "MD5:  " \
                                "137668746ece63255bf94ef175fa11e4\n\n\n" \
                                "-----------------------\n" \
                                "cryptWithFernet fonksiyonu\n" \
                                "-----------------------\n" \
                                "Bu fonksiyon parametre olarak alınan text değerini\ncryptography kütüphanesi " \
                                "yardımıyla " \
                                "Fernet algoritması\nile " \
                                "şifreler ve oluşturulan şifrelenmiş text,\nbu şifreleme için üretilen key değerlerini " \
                                "döndürür.\n\n" \
                                "Örnek kullanım\n" \
                                "message, key = sifrelemeYontemleri.cryptWithFernet('Merhaba')\n" \
                                "print('Fernet: ',message)\n\n" \
                                "Ekran çıktısı\n" \
                                "Fernet:  " \
                                "b'gAAAAABhy5Dm6x9nIsbHtxjNadJRLHvWZGRMwLb7zxtQ02VgM7pvixLqjE6UEwpqQSBAolSgdcSWp5W6Pt8unBXWltsjkVJSSw=='\n\n\n" \
                                "-----------------------\n" \
                                "decryptWithFernet fonksiyonu\n" \
                                "-----------------------\n" \
                                "Bu fonksiyon parametre olarak alınan text ve key\ndeğerlerini kullanarak cryptography kütüphanesi\n" \
                                "yardımıyla " \
                                "Fernet algoritması ile " \
                                "şifrenmiş text\ndeğerini decrypt eder,elde edilen şifrelenmemiş\ntext değerini " \
                                "döndürür.\n\n" \
                                "Örnek kullanım\n" \
                                "print(sifrelemeYontemleri.decryptWithFernet(message, key))\n\n" \
                                "Ekran çıktısı\n" \
                                "Merhaba\n\n\n" \
                                "-----------------------\n" \
                                "customEncrypt fonksiyonu\n" \
                                "-----------------------\n" \
                                "Bu fonksiyon parametre olarak alınan text ve key\ndeğerlerinin ascii karşılıklarını toplayarak\nşifreler." \
                                "Oluşturulan şifrelenmiş text değerini\ndöndürür.\n\n" \
                                "Örnek kullanım\n" \
                                "encrypted = sifrelemeYontemleri.customEncrypt(key, text)\n" \
                                "print('Encrypted:', repr(encrypted))\n\n" \
                                "Ekran çıktısı\n" \
                                "Encrypted: " + repr('+[\rOU\x0fa]\x13TN') + "\n\n\n" \
                                 "-----------------------\n" \
                                 "customDecrypt fonksiyonu\n" \
                                 "-----------------------\n" \
                                 "Bu fonksiyon parametre olarak alınan text ve key\ndeğerlerinin ascii karşılıklarını " \
                                 "çıkartarak\nşifrelenmiş text değerini çözer ve şifrelenmemiş\ntext oluşturur." \
                                 "Oluşturulan şifrelenmemiş text\ndeğerini döndürür.\n\n" \
                                 "Örnek kullanım\n" \
                                 "decrypted = sifrelemeYontemleri.customDecrypt(key, encrypted)\n" \
                                 "print('Decrypted:', repr(decrypted))\n\n" \
                                 "Ekran çıktısı\n" \
                                 "Decrypted: 'Hello world'\n" \
                                 "\n\n\n----------------------------------------------------------------------------------------------------------------------" \
                                 "\n-----------------------------------------\nDilKontrol " \
                                 "sınıfı\n-----------------------------------------\n\n" \
                                 "-----------------------\n" \
                                 "Prune Fonksiyonu\n" \
                                 "-----------------------\n" \
                                 "Girilen text verisindeki noktalama işaretlerini, başındaki ve sonundaki boşlukları " \
                                 "temizler.\n\n\n" \
                                 "-----------------------\n" \
                                 "checkspellingrule Fonksiyonu\n" \
                                 "-----------------------\n" \
                                 "Verilen sözcüğün büyük ünlü uyumuna uyup uymadığını kontrol eder. True, false ya da kelime hatalı ise -1 değerini döner.\n\n\n" \
                                 "-----------------------\n" \
                                 "calculationrule Fonksiyonu\n" \
                                 "-----------------------\n" \
                                 "Verilen metin içerisindeki büyük ünlü uyumuna uyan-uymayan ve hatalı sözcük sayısını geri döndürür.\n\n\n" \
                                 "-----------------------\n" \
                                 "wordcount Fonksiyonu\n" \
                                 "-----------------------\n" \
                                 "Verilen metin içerisindeki kelime sayısını ve hatalı kelime sayısını döndürür.\n\n\n" \
                                 "-----------------------\n" \
                                 "sentencecount Fonksiyonu\n" \
                                 "-----------------------\n" \
                                 "Verilen metin içerisindeki türlerine göre cümle sayısını.\n\n\n" \
                                 "-----------------------\n" \
                                 "vowelscount Fonksiyonu\n" \
                                 "-----------------------\n" \
                                 "Metin içerisindeki ünlü harfleri ve sayılarını döndürür.\n\n\n" \
                                 "-----------------------\n" \
                                 "iscontainsyllables Fonksiyonu\n" \
                                 "-----------------------\n" \
                                 "Girilen metnin boş olmadığını ve 2 karakterden fazla olması gerektiğini kontrol eder.\n\n\n"

    def __init__(self):
        print(self.sifrelemeYontemleriYardim)
