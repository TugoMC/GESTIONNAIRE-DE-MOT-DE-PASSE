import sys
import sqlite3
import hashlib
import random
import string
import base64
import os
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from PySide6.QtWidgets import (
    QApplication,
    QMainWindow,
    QVBoxLayout,
    QHBoxLayout,
    QWidget,
    QPushButton,
    QLineEdit,
    QLabel,
    QMessageBox,
    QTableWidget,
    QTableWidgetItem,
    QHeaderView,
    QSizePolicy,
    QDialog,
    QDialogButtonBox,
    QFrame,
    QProgressBar,
    QSlider,
    QCheckBox,
    QTabWidget,
)
from PySide6.QtGui import QFont, QColor
from PySide6.QtCore import Qt, QSettings

# Define light and dark mode stylesheets
LIGHT_STYLE = """
QWidget {
    background-color: #f5f5f5;
    color: #333333;
    font-family: 'Segoe UI', Arial, sans-serif;
}
QPushButton {
    background-color: #3c6e71;
    color: white;
    border: none;
    padding: 8px 16px;
    text-align: center;
    text-decoration: none;
    font-size: 14px;
    margin: 4px 2px;
    border-radius: 4px;
    min-width: 120px;
}
QPushButton:hover {
    background-color: #284b63;
}
QLineEdit {
    padding: 8px;
    margin: 4px 2px;
    border: 1px solid #bbb;
    border-radius: 4px;
    background-color: white;
}
QTableWidget {
    gridline-color: #d3d3d3;
    background-color: white;
    alternate-background-color: #f0f0f0;
}
QHeaderView::section {
    background-color: #353535;
    color: white;
    padding: 8px;
    font-weight: bold;
}
QTableWidget::item {
    padding: 5px;
}
"""

DARK_STYLE = """
QWidget {
    background-color: #282828;
    color: #e0e0e0;
    font-family: 'Segoe UI', Arial, sans-serif;
}
QPushButton {
    background-color: #4a6fa5;
    color: white;
    border: none;
    padding: 8px 16px;
    text-align: center;
    text-decoration: none;
    font-size: 14px;
    margin: 4px 2px;
    border-radius: 4px;
    min-width: 120px;
}
QPushButton:hover {
    background-color: #5a8abe;
}
QLineEdit {
    padding: 8px;
    margin: 4px 2px;
    border: 1px solid #555;
    border-radius: 4px;
    background-color: #3a3a3a;
    color: white;
}
QTableWidget {
    gridline-color: #555;
    background-color: #2b2b2b;
    alternate-background-color: #323232;
    color: #e0e0e0;
}
QHeaderView::section {
    background-color: #1c1c1c;
    color: white;
    padding: 8px;
    font-weight: bold;
}
QTableWidget::item {
    padding: 5px;
}
"""


class Encryptor:
    def __init__(self, master_password, salt):
        self.salt = salt
        self.key = PBKDF2(master_password, self.salt, dkLen=32, count=1000000)

    def encrypt(self, data):
        cipher = AES.new(self.key, AES.MODE_ECB)
        padded_data = pad(data.encode(), AES.block_size)
        encrypted_data = cipher.encrypt(padded_data)
        return base64.b64encode(encrypted_data).decode()

    def decrypt(self, encrypted_data):
        cipher = AES.new(self.key, AES.MODE_ECB)
        encrypted_bytes = base64.b64decode(encrypted_data.encode())
        decrypted_data = cipher.decrypt(encrypted_bytes)
        return unpad(decrypted_data, AES.block_size).decode()


class PasswordStrengthIndicator(QProgressBar):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setRange(0, 100)
        self.setTextVisible(False)
        self.setFixedHeight(10)

    def update_strength(self, password):
        strength = self.calculate_strength(password)
        self.setValue(strength)
        self.update_color(strength)

    def calculate_strength(self, password):
        strength = 0
        if len(password) >= 8:
            strength += 25
        if any(c.islower() for c in password) and any(c.isupper() for c in password):
            strength += 25
        if any(c.isdigit() for c in password):
            strength += 25
        if any(c in string.punctuation for c in password):
            strength += 25
        return strength

    def update_color(self, strength):
        if strength < 50:
            self.setStyleSheet("QProgressBar::chunk { background-color: red; }")
        elif strength < 75:
            self.setStyleSheet("QProgressBar::chunk { background-color: yellow; }")
        else:
            self.setStyleSheet("QProgressBar::chunk { background-color: green; }")


class PasswordGenerator(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Générateur de mot de passe")
        self.setGeometry(100, 100, 400, 300)

        layout = QVBoxLayout(self)

        self.length_slider = QSlider(Qt.Horizontal)
        self.length_slider.setRange(8, 32)
        self.length_slider.setValue(16)
        self.length_label = QLabel(f"Longueur: {self.length_slider.value()}")
        self.length_slider.valueChanged.connect(self.update_length_label)

        self.use_numbers = QCheckBox("Inclure des chiffres")
        self.use_symbols = QCheckBox("Inclure des symboles")
        self.use_numbers.setChecked(True)
        self.use_symbols.setChecked(True)

        self.generated_password = QLineEdit()
        self.generated_password.setReadOnly(True)

        generate_button = QPushButton("Générer")
        generate_button.clicked.connect(self.generate_password)

        use_button = QPushButton("Utiliser ce mot de passe")
        use_button.clicked.connect(self.accept)

        layout.addWidget(self.length_label)
        layout.addWidget(self.length_slider)
        layout.addWidget(self.use_numbers)
        layout.addWidget(self.use_symbols)
        layout.addWidget(self.generated_password)
        layout.addWidget(generate_button)
        layout.addWidget(use_button)

    def update_length_label(self, value):
        self.length_label.setText(f"Longueur: {value}")

    def generate_password(self):
        length = self.length_slider.value()
        chars = string.ascii_letters
        if self.use_numbers.isChecked():
            chars += string.digits
        if self.use_symbols.isChecked():
            chars += "@#$%&!?+=-_"

        password = "".join(random.choice(chars) for _ in range(length))
        self.generated_password.setText(password)

    def get_generated_password(self):
        return self.generated_password.text()


class DatabaseManager:
    def __init__(self, db_path="passwords.db"):
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        self.initialize_database()
        self.migrate_database()

    def initialize_database(self):
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                salt TEXT NOT NULL
            )
        """
        )
        self.cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS passwords (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                site TEXT NOT NULL,
                username TEXT NOT NULL,
                encrypted_password TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
        """
        )
        self.conn.commit()

    def close(self):
        self.conn.commit()
        self.conn.close()

    def migrate_database(self):
        # Vérifier si la colonne email existe déjà
        self.cursor.execute("PRAGMA table_info(passwords)")
        columns = [column[1] for column in self.cursor.fetchall()]

        if "email" not in columns:
            # Ajouter la colonne email si elle n'existe pas
            self.cursor.execute("ALTER TABLE passwords ADD COLUMN email TEXT")
            self.conn.commit()
            print("La colonne 'email' a été ajoutée à la table 'passwords'.")


class ThemeManager:
    def __init__(self):
        self.settings = QSettings("SecurePasswordManager", "Theme")
        self.current_theme = self.settings.value("theme", "light")

    def toggle_theme(self):
        self.current_theme = "dark" if self.current_theme == "light" else "light"
        self.settings.setValue("theme", self.current_theme)
        self.apply_theme()

    def apply_theme(self):
        if self.current_theme == "light":
            QApplication.instance().setStyleSheet(LIGHT_STYLE)
        else:
            QApplication.instance().setStyleSheet(DARK_STYLE)

    def get_current_theme(self):
        return self.current_theme


class LoginWindow(QMainWindow):
    def __init__(self, theme_manager):
        super().__init__()
        self.theme_manager = theme_manager
        self.setWindowTitle("Gestionnaire de mots de passe - Login")
        self.setGeometry(100, 100, 400, 400)

        self.conn = sqlite3.connect("passwords.db")
        self.cursor = self.conn.cursor()

        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        layout = QVBoxLayout(main_widget)

        # Logo
        logo_label = QLabel("🔒", alignment=Qt.AlignCenter)
        logo_label.setFont(QFont("Arial", 48))
        layout.addWidget(logo_label)

        # Onglets pour basculer entre connexion et inscription
        self.tab_widget = QTabWidget()
        layout.addWidget(self.tab_widget)

        # Onglet de connexion
        login_tab = QWidget()
        login_layout = QVBoxLayout(login_tab)
        self.login_username = QLineEdit()
        self.login_username.setPlaceholderText("Nom d'utilisateur")
        self.login_password = QLineEdit()
        self.login_password.setPlaceholderText("Mot de passe")
        self.login_password.setEchoMode(QLineEdit.Password)
        login_button = QPushButton("Connexion")
        login_button.clicked.connect(self.login)
        login_layout.addWidget(self.login_username)
        login_layout.addWidget(self.login_password)
        login_layout.addWidget(login_button)
        self.tab_widget.addTab(login_tab, "Connexion")

        # Onglet d'inscription
        register_tab = QWidget()
        register_layout = QVBoxLayout(register_tab)
        self.register_username = QLineEdit()
        self.register_username.setPlaceholderText("Nom d'utilisateur")
        self.register_password = QLineEdit()
        self.register_password.setPlaceholderText("Mot de passe")
        self.register_password.setEchoMode(QLineEdit.Password)
        self.confirm_password = QLineEdit()
        self.confirm_password.setPlaceholderText("Confirmer le mot de passe")
        self.confirm_password.setEchoMode(QLineEdit.Password)
        register_button = QPushButton("Inscription")
        register_button.clicked.connect(self.register)
        register_layout.addWidget(self.register_username)
        register_layout.addWidget(self.register_password)
        register_layout.addWidget(self.confirm_password)
        register_layout.addWidget(register_button)
        self.tab_widget.addTab(register_tab, "Inscription")

        # Indicateur de force du mot de passe
        self.password_strength = PasswordStrengthIndicator()
        layout.addWidget(self.password_strength)

        # Bouton pour changer de thème
        self.theme_toggle_button = QPushButton("Changer de thème")
        self.theme_toggle_button.clicked.connect(self.toggle_theme)
        layout.addWidget(self.theme_toggle_button)

        # Connecter les champs de mot de passe à l'indicateur de force
        self.register_password.textChanged.connect(
            self.password_strength.update_strength
        )
        self.confirm_password.textChanged.connect(self.check_password_match)

    def toggle_theme(self):
        self.theme_manager.toggle_theme()

    def check_password_match(self):
        if self.register_password.text() == self.confirm_password.text():
            self.confirm_password.setStyleSheet("border: 1px solid green;")
        else:
            self.confirm_password.setStyleSheet("border: 1px solid red;")

    def login(self):
        username = self.login_username.text()
        password = self.login_password.text()

        if not username or not password:
            QMessageBox.warning(self, "Erreur", "Tous les champs doivent être remplis.")
            return

        self.cursor.execute(
            "SELECT id, password, salt FROM users WHERE username = ?", (username,)
        )
        result = self.cursor.fetchone()

        if result:
            user_id, stored_password, salt = result
            hashed_password = hashlib.sha256(
                password.encode() + salt.encode()
            ).hexdigest()
            if hashed_password == stored_password:
                QMessageBox.information(self, "Succès", "Connexion réussie.")
                self.open_password_manager(user_id, username, password, salt)
            else:
                QMessageBox.warning(
                    self, "Erreur", "Nom d'utilisateur ou mot de passe incorrect."
                )
        else:
            QMessageBox.warning(
                self, "Erreur", "Nom d'utilisateur ou mot de passe incorrect."
            )

    def register(self):
        username = self.register_username.text()
        password = self.register_password.text()
        confirm_password = self.confirm_password.text()

        if not username or not password or not confirm_password:
            QMessageBox.warning(self, "Erreur", "Tous les champs doivent être remplis.")
            return

        if password != confirm_password:
            QMessageBox.warning(
                self, "Erreur", "Les mots de passe ne correspondent pas."
            )
            return

        self.cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        if self.cursor.fetchone():
            QMessageBox.warning(self, "Erreur", "Cet utilisateur existe déjà.")
            return

        salt = os.urandom(16).hex()
        hashed_password = hashlib.sha256(password.encode() + salt.encode()).hexdigest()

        self.cursor.execute(
            "INSERT INTO users (username, password, salt) VALUES (?, ?, ?)",
            (username, hashed_password, salt),
        )
        self.conn.commit()

        QMessageBox.information(self, "Succès", "Utilisateur enregistré avec succès.")
        self.clear_fields()
        self.tab_widget.setCurrentIndex(0)  # Basculer vers l'onglet de connexion

    def clear_fields(self):
        self.login_username.clear()
        self.login_password.clear()
        self.register_username.clear()
        self.register_password.clear()
        self.confirm_password.clear()
        self.confirm_password.setStyleSheet("")

    def open_password_manager(self, user_id, username, master_password, salt):
        self.close()
        self.password_manager = PasswordManager(
            self.theme_manager, user_id, username, master_password, salt
        )
        self.password_manager.show()


class PasswordManager(QMainWindow):
    def __init__(self, theme_manager, user_id, username, master_password, salt):
        super().__init__()
        self.theme_manager = theme_manager
        self.user_id = user_id
        self.username = username
        self.encryptor = Encryptor(master_password, salt.encode())
        self.setWindowTitle(f"Gestionnaire de mots de passe de ({username})")
        self.setGeometry(100, 100, 1400, 700)
        self.conn = sqlite3.connect("passwords.db")
        self.cursor = self.conn.cursor()
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QHBoxLayout(main_widget)
        sidebar = QWidget()
        sidebar.setMaximumWidth(250)
        sidebar.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Expanding)
        sidebar_layout = QVBoxLayout(sidebar)
        add_button = QPushButton("Ajouter un mot de passe")
        add_button.setFixedHeight(40)
        add_button.clicked.connect(self.toggle_add_password_form)
        sidebar_layout.addWidget(add_button)
        sidebar_layout.addStretch()
        self.logout_button = QPushButton("Déconnexion")
        self.logout_button.setFixedHeight(40)
        self.logout_button.clicked.connect(self.logout)
        sidebar_layout.addWidget(self.logout_button)
        self.theme_toggle_button = QPushButton("Changer de thème")
        self.theme_toggle_button.setFixedHeight(40)
        self.theme_toggle_button.clicked.connect(self.theme_manager.toggle_theme)
        sidebar_layout.addWidget(self.theme_toggle_button)
        main_layout.addWidget(sidebar)
        self.content_area = QWidget()
        self.content_layout = QVBoxLayout(self.content_area)
        self.add_password_section = QFrame()
        self.add_password_section.setFrameShape(QFrame.StyledPanel)
        self.add_password_section.setFrameShadow(QFrame.Raised)
        add_password_layout = QVBoxLayout(self.add_password_section)
        self.site_input = QLineEdit()
        self.site_input.setPlaceholderText("Nom du site")
        self.username_input = QLineEdit()
        self.username_input.setPlaceholderText("Nom d'utilisateur")
        self.password_input = QLineEdit()
        self.password_input.setPlaceholderText("Mot de passe")
        self.password_input.setEchoMode(QLineEdit.Password)

        add_button = QPushButton("Ajouter")
        self.email_input = QLineEdit()
        self.email_input.setPlaceholderText("E-mail (optionnel)")
        add_password_layout.addWidget(self.email_input)
        add_password_layout.addWidget(self.username_input)
        add_button.clicked.connect(self.add_password)
        add_password_layout.addWidget(self.site_input)
        add_password_layout.addWidget(self.username_input)
        add_password_layout.addWidget(self.password_input)
        add_password_layout.addWidget(add_button)
        self.content_layout.addWidget(self.add_password_section)
        self.add_password_section.hide()
        self.password_table = QTableWidget()
        self.password_table.setColumnCount(6)
        self.password_table.setHorizontalHeaderLabels(
            [
                "Site",
                "Nom d'utilisateur",
                "Mot de passe",
                "Afficher",
                "Modifier",
                "Supprimer",
            ]
        )
        self.password_table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.content_layout.addWidget(self.password_table)
        main_layout.addWidget(self.content_area)
        self.load_passwords()

        # Add password strength indicator
        self.password_strength = PasswordStrengthIndicator()
        add_password_layout.addWidget(self.password_strength)

        # Connect password input to strength indicator
        self.password_input.textChanged.connect(self.password_strength.update_strength)

        # Add password generator button
        generate_password_button = QPushButton("Générer un mot de passe")
        generate_password_button.clicked.connect(self.generate_password)
        add_password_layout.addWidget(generate_password_button)

    def generate_password(self):
        generator = PasswordGenerator(self)
        if generator.exec() == QDialog.Accepted:
            generated_password = generator.get_generated_password()
            self.password_input.setText(generated_password)
            self.password_strength.update_strength(generated_password)

    def toggle_add_password_form(self):
        if self.add_password_section.isVisible():
            self.add_password_section.hide()
        else:
            self.add_password_section.show()

    def add_password(self):
        site = self.site_input.text()
        username = self.username_input.text()
        email = self.email_input.text()
        password = self.password_input.text()
        if not site or not password:
            QMessageBox.warning(
                self, "Erreur", "Le site et le mot de passe sont obligatoires."
            )
            return
        encrypted_password = self.encryptor.encrypt(password)
        self.cursor.execute(
            "INSERT INTO passwords (user_id, site, username, email, encrypted_password) VALUES (?, ?, ?, ?, ?)",
            (self.user_id, site, username, email, encrypted_password),
        )
        self.conn.commit()
        QMessageBox.information(self, "Succès", "Mot de passe ajouté avec succès.")
        self.load_passwords()
        self.site_input.clear()
        self.username_input.clear()
        self.email_input.clear()
        self.password_input.clear()

    def load_passwords(self):
        self.password_table.setRowCount(0)
        self.password_table.setColumnCount(7)  # Ajout d'une colonne pour l'e-mail
        self.password_table.setHorizontalHeaderLabels(
            [
                "Site",
                "Nom d'utilisateur",
                "E-mail",
                "Mot de passe",
                "Afficher",
                "Modifier",
                "Supprimer",
            ]
        )
        self.cursor.execute(
            "SELECT id, site, username, email, encrypted_password FROM passwords WHERE user_id = ?",
            (self.user_id,),
        )
        for row, (id, site, username, email, encrypted_password) in enumerate(
            self.cursor.fetchall()
        ):
            decrypted_password = self.encryptor.decrypt(encrypted_password)
            self.password_table.insertRow(row)
            self.password_table.setItem(row, 0, QTableWidgetItem(site))
            self.password_table.setItem(row, 1, QTableWidgetItem(username or ""))
            self.password_table.setItem(row, 2, QTableWidgetItem(email or ""))
            self.password_table.setItem(
                row, 3, QTableWidgetItem("•" * len(decrypted_password))
            )
            show_button = QPushButton("Afficher")
            show_button.clicked.connect(
                lambda _, r=row, p=decrypted_password: self.show_password(r, p)
            )
            self.password_table.setCellWidget(row, 3, show_button)
            edit_button = QPushButton("Modifier")
            edit_button.clicked.connect(
                lambda _, i=id, s=site, u=username, p=decrypted_password: self.edit_password(
                    i, s, u, p
                )
            )
            self.password_table.setCellWidget(row, 4, edit_button)
            delete_button = QPushButton("Supprimer")
            delete_button.clicked.connect(lambda _, i=id: self.delete_password(i))
            self.password_table.setCellWidget(row, 5, delete_button)
            self.password_table.setRowHeight(row, 50)

        # Rest of the method remains the same

    def show_password(self, row, password):
        current_text = self.password_table.item(row, 2).text()
        if current_text == "•" * len(password):
            self.password_table.setItem(row, 2, QTableWidgetItem(password))
        else:
            self.password_table.setItem(row, 2, QTableWidgetItem("•" * len(password)))

    def edit_password(self, id, site, username, email, password):
        dialog = QDialog(self)
        dialog.setWindowTitle("Modifier le mot de passe")
        layout = QVBoxLayout(dialog)

        site_input = QLineEdit(site)
        username_input = QLineEdit(username)
        email_input = QLineEdit(email)
        password_input = QLineEdit(password)
        password_strength = PasswordStrengthIndicator()

        layout.addWidget(QLabel("Site:"))
        layout.addWidget(site_input)
        layout.addWidget(QLabel("Nom d'utilisateur (optionnel):"))
        layout.addWidget(username_input)
        layout.addWidget(QLabel("E-mail (optionnel):"))
        layout.addWidget(email_input)
        layout.addWidget(QLabel("Mot de passe:"))
        layout.addWidget(password_input)
        layout.addWidget(password_strength)

        # Add password generator button
        generate_password_button = QPushButton("Générer un mot de passe")
        generate_password_button.clicked.connect(
            lambda: self.generate_password_for_edit(password_input, password_strength)
        )
        layout.addWidget(generate_password_button)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        password_input.textChanged.connect(password_strength.update_strength)
        password_strength.update_strength(password)

        if dialog.exec() == QDialog.Accepted:
            new_site = site_input.text()
            new_username = username_input.text()
            new_email = email_input.text()
            new_password = password_input.text()
            if not new_site or not new_password:
                QMessageBox.warning(
                    self, "Erreur", "Le site et le mot de passe sont obligatoires."
                )
                return
            encrypted_password = self.encryptor.encrypt(new_password)
            self.cursor.execute(
                "UPDATE passwords SET site=?, username=?, email=?, encrypted_password=? WHERE id=?",
                (new_site, new_username, new_email, encrypted_password, id),
            )
            self.conn.commit()
            self.load_passwords()

    def generate_password_for_edit(self, password_input, password_strength):
        generator = PasswordGenerator(self)
        if generator.exec() == QDialog.Accepted:
            generated_password = generator.get_generated_password()
            password_input.setText(generated_password)
            password_strength.update_strength(generated_password)

    def delete_password(self, id):
        confirm = QMessageBox.question(
            self,
            "Confirmation",
            "Êtes-vous sûr de vouloir supprimer ce mot de passe ?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm == QMessageBox.Yes:
            self.cursor.execute("DELETE FROM passwords WHERE id=?", (id,))
            self.conn.commit()
            self.load_passwords()

    def logout(self):
        reply = QMessageBox.question(
            self,
            "Confirmation",
            "Êtes-vous sûr de vouloir vous déconnecter ?",
            QMessageBox.Yes | QMessageBox.No,
            QMessageBox.No,
        )
        if reply == QMessageBox.Yes:
            self.close()
            self.login_window = LoginWindow(self.theme_manager)
            self.login_window.show()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    db_manager = DatabaseManager()
    theme_manager = ThemeManager()
    theme_manager.apply_theme()
    login_window = LoginWindow(theme_manager)
    login_window.show()
    sys.exit(app.exec())
