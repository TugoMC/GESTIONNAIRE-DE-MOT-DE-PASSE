# Secure Password Manager

Ce projet est une application de gestionnaire de mots de passe créée avec **Python** et **PySide6**. Elle permet aux utilisateurs de stocker, visualiser, modifier et supprimer des mots de passe de manière sécurisée. L'application inclut une fonctionnalité de thème (clair/sombre) et se connecte à une base de données SQLite pour stocker les informations des utilisateurs et leurs mots de passe.

## Fonctionnalités

- **Inscription et Connexion sécurisées**: Les mots de passe sont hachés avec SHA-256 avant d'être stockés dans la base de données.
- **Gestion des mots de passe**: Ajouter, visualiser, modifier et supprimer des mots de passe pour différents sites.
- **Thème**: Possibilité de basculer entre le mode clair et le mode sombre.
- **Tableau de bord**: Affiche les mots de passe enregistrés dans une table avec des options pour les afficher, les modifier ou les supprimer.
- **Déconnexion**: Permet de se déconnecter pour retourner à la fenêtre de connexion.

## Prérequis

- Python 3.8 ou plus
- PySide6

## Installation

1. Clonez ce dépôt ou téléchargez les fichiers:
   ```bash
   git clone https://github.com/votre-utilisateur/secure-password-manager.git
Accédez au répertoire du projet:

bash

cd secure-password-manager

Installez les dépendances requises:

bash

pip install -r requirements.txt

Exécutez l'application:

bash

    python main.py

Utilisation

    Inscription: Entrez un nom d'utilisateur et un mot de passe pour créer un compte.
    Connexion: Utilisez les informations d'inscription pour vous connecter.
    Ajouter un mot de passe: Après la connexion, utilisez le tableau de bord pour ajouter, modifier, afficher ou supprimer vos mots de passe.
    Thème: Utilisez le bouton "Changer de thème" pour basculer entre le thème clair et sombre.

Structure du projet

bash

main.py                # Fichier principal contenant toute la logique de l'application
passwords.db           # Fichier SQLite utilisé pour stocker les utilisateurs et les mots de passe
README.md              # Documentation du projet
requirements.txt       # Dépendances du projet
