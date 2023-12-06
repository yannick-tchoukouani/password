import hashlib
import random
import string

def is_password_secure(password):
    # Exigences de sécurité pour le mot de passe
    return (
        len(password) >= 8 and
        any(char.isupper() for char in password) and
        any(char.islower() for char in password) and
        any(char.isdigit() for char in password) and
        any(char in '!@#$%^&*' for char in password)
    )

def get_valid_password():
    while True:
        password = input("Choisissez un mot de passe : ")

        if is_password_secure(password):
            return password
        else:
            print("Le mot de passe ne répond pas aux exigences de sécurité. Veuillez réessayer.")

def generate_salt(length=16):
    characters = string.ascii_letters + string.digits
    return ''.join(random.choice(characters) for _ in range(length))

def hash_password(password, salt):
    # Salage du mot de passe avant le hachage
    salted_password = password + salt

    sha256 = hashlib.sha256()
    sha256.update(salted_password.encode('utf-8'))
    hashed_password = sha256.hexdigest()
    return hashed_password

def main():
    print("Création d'un mot de passe sécurisé")

    # Obtenir un mot de passe valide
    password = get_valid_password()

    # Générer un sel aléatoire
    salt = generate_salt()

    # Hasher le mot de passe avec SHA-256 et le sel
    hashed_password = hash_password(password, salt)

    print(f"\nMot de passe sécurisé avec succès !\nMot de passe d'origine : {password}\nSel : {salt}\nMot de passe haché : {hashed_password}")

if __name__ == "__main__":
    main()
