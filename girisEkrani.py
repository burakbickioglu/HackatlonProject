import pyodbc
from MyModule import sifrelemeYontemleri
from MyModule import Dilkontrol
from MyModule import help

conn = pyodbc.connect('Driver={SQL Server};'
                      'Server=BURAK;'
                      'Database=hackathon;'
                      'Trusted_Connection=yes;')


def main():

    helpYazdir = help()

    print("-----------\nHOŞGELDİNİZ\n-----------")

    print("1 - Kullanıcı Girişi")
    print("2 - Kullanıcı Kaydı")
    print("3 - Dil menüsü")
    secim = input("Seçiniz: ")
    try:
        if secim.isdigit():
            secim = int(secim)
        else:
            raise TypeError
    except TypeError:
        print("Geçersiz seçim")
        main()

    match (secim):
        case 1:
            kullaniciGiris()
        case 2:
            kullaniciKayit()
        case 3:
            dilMenusu()
        case _:
            print("Geçersiz seçim")
            main()


def kullaniciKayit():
    userName = input("Kullanıcı adı: ")
    userPassword = input("Şifre: ")
    firstName = input("Ad: ")
    lastName = input("Soyad: ")
    eMail = input("Mail: ")
    age = int(input("Yaş: "))
    city = int(input("Plaka kodu: "))
    profession = int(input("Beyaz yakalı için 1, Mavi yakalı için 2: "))
    cursor = conn.cursor()
    cursor.execute(
        "exec addUser '{}','{}','{}','{}','{}',{},{},{}".format(userName, userPassword, firstName, lastName, eMail,
                                                                age, city, profession))
    cursor.commit()
    print("Kayıt tamamlandı !")
    main()


def kullaniciGiris():
    kullaniciAdi = input("Kullanıcı adı: ")
    sifre = input("Sifre: ")

    imlec = conn.cursor()
    try:
        imlec.execute(
            "SELECT userName,userPassword FROM tblAccount where userName = '{}' and userPassword = '{}'".format(
                kullaniciAdi, sifre))

        if len(imlec.fetchall()) != 0:
            print("Giriş başarılı")
            kullaniciArayuz(kullaniciAdi=kullaniciAdi, sifre=sifre)

        else:
            raise PermissionError

    except PermissionError:
        print("Giriş başarısız")
        kullaniciGiris()


def kullaniciArayuz(kullaniciAdi, sifre):
    print("1 - Metin şifrele")
    print("2 - Şifrelenmiş metinlerim")
    print("3 - Bilgilerim")

    secim = int(input("Seçiniz: "))
    match (secim):
        case 1:
            sifrelenmisMetin= metinSifrele(kullaniciAdi=kullaniciAdi, sifre=sifre)
            print("Şifrelenmiş metin: ", sifrelenmisMetin)

            kullaniciArayuz(kullaniciAdi, sifre)

        case 2:
            sifrelenmisMetinGoster(kullaniciAdi=kullaniciAdi)
            kullaniciArayuz(kullaniciAdi, sifre)

        case 3:
            kullaniciBilgiGoster(kullaniciAdi)
            kullaniciArayuz(kullaniciAdi,sifre)

        case _:
            print("Geçersiz seçim")
            kullaniciArayuz(kullaniciAdi, sifre)


def metinSifrele(kullaniciAdi, sifre):
    metin = input("Şifrelemek istediğiniz metni girin: ")
    try:
        algoritma = input("Şifrelemek istediğiniz algoritmayı seçin\n"
                          "1 - SHA1\n"
                          "2 - SHA256\n"
                          "3 - SHA384\n"
                          "4 - SHA512\n"
                          "5 - MD5\n"
                          "6 - FERNET\n"
                          "7 - CUSTOM\n"
                          "seçiminiz: ")
        if algoritma.isdigit():
            algoritma = int(algoritma)
        else:
            raise TypeError
    except TypeError:
        print("Geçersiz seçim")
        kullaniciArayuz(kullaniciAdi, sifre)

    match (algoritma):
        case 1:
            sifrelenmisMetin = sifrelemeYontemleri.hashWithSHA1(metin)
            algoritmaAdi = "SHA1"
        case 2:
            sifrelenmisMetin = sifrelemeYontemleri.hashWithSHA256(metin)
            algoritmaAdi = "SHA256"
        case 3:
            sifrelenmisMetin = sifrelemeYontemleri.hashWithSHA384(metin)
            algoritmaAdi = "SHA384"
        case 4:
            sifrelenmisMetin = sifrelemeYontemleri.hashWithSHA512(metin)
            algoritmaAdi = "SHA512"
        case 5:
            sifrelenmisMetin = sifrelemeYontemleri.hashWithMD5(metin)
            algoritmaAdi = "MD5"
        case 6:
            sifrelenmisMetin = sifrelemeYontemleri.cryptWithFernet(metin)
            algoritmaAdi = "FERNET"
        case 7:
            key = input("Bir key giriniz: ")
            sifrelenmisMetin = sifrelemeYontemleri.customEncrypt(key, metin)
            algoritmaAdi = "CUSTOM"
            print(repr(sifrelenmisMetin))
        case _:
            print("Geçersiz seçim")
            metinSifrele(kullaniciAdi, sifre)

    veritabaniKayit(kullaniciAdi, algoritmaAdi, metin, sifrelenmisMetin)
    return sifrelenmisMetin


def sifrelenmisMetinGoster(kullaniciAdi):
    cursor = conn.cursor()
    sifrelenmisMetinler = cursor.execute("select * from getTextDetails where userName = '{}'".format(kullaniciAdi))
    for i in sifrelenmisMetinler:
        print("Şifreleme algoritması : {}\n"
              "Şifrelenmemiş metin: {}\n"
              "Şifrelenmiş metin: {}\n\n".format(i[1], i[2], i[3]))




def veritabaniKayit(kullaniciAdi, algoritmaAdi, metin, sifrelenmisMetin):
    cursor = conn.cursor()
    cursor.execute(
        "exec addText '{}','{}','{}','{}'".format(kullaniciAdi, algoritmaAdi, metin, sifrelenmisMetin))
    cursor.commit()
    print("Şifrelenmiş metin veritabanına kaydedildi. tamamlandı !")


def dilMenusu():
    nesne = Dilkontrol()
    print("----------\n"
          "Dil Menüsü\n"
          "---------\n"
          "1 - Kelime sayısı bulma\n"
          "2 - Cümle sayısı bulma\n"
          "3 - Ünlü harf sayısı bulma\n"
          "4 - Büyük ünlü uyumu kontrolü\n")
    secim = int(input("Seçiminiz: "))

    match(secim):
        case 1:
            cumle = input("Kelime sayısını bulmak istediğiniz cümleyi girin: ")
            print(nesne.wordcount(cumle))
            dilMenusu()
        case 2:
            cumle = input("Cümle sayısını bulmak istediğiniz cümleyi girin: ")
            print(nesne.sentencecount(cumle))
            dilMenusu()
        case 3:
            cumle = input("Ünlü harf sayısını bulmak istediğiniz cümleyi girin: ")
            print(nesne.vowelscount(cumle))
            dilMenusu()
        case 4:
            cumle = input("Büyük ünlü testi yapmak istediğiniz cümleyi girin: ")
            print(nesne.calculationrule(cumle))
            dilMenusu()

def kullaniciBilgiGoster(kullaniciAdi):
    cursor = conn.cursor()
    cursor.execute("select * from getUserDetail('{}')".format(kullaniciAdi))
    for i in cursor:
        print("Adı:", i[0], "\nSoyad:", i[1], "\nKullanıcı adı:", i[2], "\nMail:", i[3], "\nYaş:", i[4], "\nŞehir:",
              i[5], "\nMeslek:", i[6])

main()
