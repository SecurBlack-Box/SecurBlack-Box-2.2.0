from __future__ import annotations

"""
Voltig Global – SecurBlack Box
Version: 2.2.0

Проект с открытым исходным кодом.
https://github.com/SecurBlack-Box/SecurBlack-Box-2.2.0
www.voltig.ru
"""

import argparse
import base64
import fnmatch
import gc
import hashlib
import json
import locale
import logging
import os
import platform
import re
import secrets
import shutil
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import dataclass, asdict, field
from datetime import datetime
from enum import Enum
from getpass import getpass
from pathlib import Path
from threading import Lock
from typing import BinaryIO, Optional, Union

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

APP_NAME = "SecurBlack Box"
APP_VERSION = "2.2.0"
APP_FULL_NAME = f"{APP_NAME} {APP_VERSION}"
DEVELOPER = "Voltig Global"

GITHUB_MAIN = "https://github.com/SecurBlack-Box"
GITHUB_REPO = "https://github.com/SecurBlack-Box/SecurBlack-Box-2.2.0"
OFFICIAL_WEBSITE = "www.voltig.ru"
EULA_URL = "https://www.voltig.ru/securblack-box/eula"

MAGIC = b"SBX3"
FORMAT_VERSION = 3
KEY_VAULT_DIR_NAME = ".securblack_keys"

class Language(Enum):
    ENGLISH = "en"
    RUSSIAN = "ru"
    AUTO = "auto"

class I18N:
    _instance = None
    _translations = {}
    _current_language = Language.AUTO

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._load_translations()
        return cls._instance

    def _load_translations(self):
        en = {
            "app_name": APP_NAME,
            "app_full_name": APP_FULL_NAME,
            "version": "Version",
            "yes": "Yes",
            "no": "No",
            "cancel": "Cancel",
            "continue": "Continue",
            "back": "Back",
            "exit": "Exit",
            "main_menu": "MAIN MENU",
            "file_operations": "File Operations",
            "folder_operations": "Folder Operations",
            "settings": "Settings",
            "security_settings": "Security Settings",
            "encryption_settings": "Encryption Settings",
            "about": "About",
            "encrypt_file": "Encrypt File",
            "decrypt_file": "Decrypt File",
            "change_password": "Change Password",
            "verify_file": "Verify File",
            "encrypt_folder": "Encrypt Folder",
            "decrypt_folder": "Decrypt Folder",
            "change_password_folder": "Change Password",
            "verify_folder": "Verify Folder",
            "file_path": "Enter file path",
            "encrypted_file_path": "Enter encrypted file path",
            "folder_path": "Enter folder path",
            "enter_password": "Enter password",
            "enter_new_password": "Enter new password",
            "confirm_password": "Confirm password",
            "current_password": "Enter current password",
            "choose_action": "Choose action",
            "current_settings": "Current settings",
            "language": "Language",
            "language_auto": "Auto",
            "language_en": "English",
            "language_ru": "Russian",
            "language_prompt": "Select language",
            "language_changed": "Language changed to {}",
            "language_restart": "Restart now? (y/n): ",
            "path_completion": "Path completion enabled",
            "file_not_found": "File not found",
            "folder_not_found": "Folder not found",
            "invalid_file": "Invalid encrypted file",
            "invalid_password": "Invalid password",
            "password_mismatch": "Passwords do not match",
            "password_visible": "Password visible",
            "password_stars": "Password masked with asterisks",
            "password_hidden": "Password hidden",
            "char_counter_enabled": "Character counter enabled",
            "char_counter_disabled": "Character counter disabled",
            "logging_enabled": "Logging enabled",
            "logging_disabled": "Logging disabled",
            "temp_enabled": "Temporary files enabled",
            "temp_disabled": "Temporary files disabled",
            "eula": "EULA",
            "eula_title": "End User License Agreement",
            "eula_intro": "Please read and accept the agreement to continue.",
            "eula_link": "The agreement is available at:",
            "eula_accept_prompt": "Do you accept the EULA?",
            "eula_accepted_message": "EULA accepted",
            "eula_declined": "EULA declined",
            "eula_accepted": "EULA accepted",
            "eula_not_accepted": "EULA not accepted",
            "error": "Error",
            "error_critical": "Critical error: {}",
            "error_missing_dependency": "Missing dependency: {}",
            "error_install_crypto": "Install the cryptography package.",
            "error_interrupted": "Interrupted by user",
            "error_invalid_choice": "Invalid choice",
            "error_invalid_number": "Invalid number",
            "error_eula_not_accepted": "EULA must be accepted first",
            "access_denied": "Access denied",
            "warning": "Warning",
            "file_too_large": "File is too large. Maximum is {} GB",
            "encrypted_success": "Encrypted successfully",
            "decrypted_success": "Decrypted successfully",
            "password_changed": "Password changed successfully",
            "verification_passed": "Verification passed",
            "verification_failed": "Verification failed",
            "saved": "Saved",
            "save_settings": "Save settings",
            "reset_settings": "Reset settings",
            "security_info": "Security information",
            "processing_file": "Processing file {} of {}: {}",
            "threads": "Threads",
            "threads_prompt": "Threads",
            "threads_info": "Using {} worker threads",
            "min_password_length": "Minimum password length",
            "iterations": "PBKDF2 iterations",
            "max_file_size": "Max file size",
            "algorithm": "Algorithm",
            "key_size": "Key size",
            "salt_size": "Salt size",
            "nonce_size": "Nonce size",
            "req_length": "Password must be at least {} characters",
            "req_uppercase": "Password must contain an uppercase letter",
            "req_lowercase": "Password must contain a lowercase letter",
            "req_digit": "Password must contain a digit",
            "req_special": "Password must contain a special character",
            "req_not_common": "Password is too common",
            "password_valid": "Password is valid",
            "starting": "Starting",
            "encrypted_file_exists": "Encrypted file already exists",
            "original_file_exists": "Original file already exists",
            "confirm_overwrite": "Overwrite? (y/n): ",
            "temp_files": "Temporary files",
            "logging": "Logging",
            "password_mode": "Password mode",
            "char_counter": "Character counter",
            "key_vault": "Key Vault",
            "create_managed_key": "Create managed key",
            "list_managed_keys": "List managed keys",
            "encrypt_with_managed_key": "Encrypt with managed key",
            "decrypt_with_managed_key": "Decrypt with managed key",
            "key_vault_menu": "Key Vault",
            "drive_root_prompt": "Drive / vault root path",
            "key_label_prompt": "Key label",
            "key_passphrase_prompt": "Key passphrase",
            "allowed_targets_prompt": "Allowed targets (comma-separated paths or globs)",
            "notes_prompt": "Notes (optional)",
            "key_created": "Created managed key: {}",
            "no_keys_found": "No managed keys found.",
            "key_id": "Key ID",
            "scan_root_prompt": "Drive / vault root to scan (blank = all)",
            "path_to_encrypt": "Path to file or folder",
            "path_to_decrypt": "Path to file or folder",
            "drive_root_optional": "Drive / vault root (blank = auto-detect)",
            "processing_recursively": "Process recursively? (y/n)",
            "reset_eula_prompt": "Reset EULA acceptance? (y/n): ",
            "reset_all_settings": "Reset all settings to defaults? (y/n): ",
            "open_source": "Open Source",
            "github_main": "GitHub (Main)",
            "github_repo": "GitHub (Repository)",
            "official_website": "Official Website",
            "update_reminder": "Check for updates: {}",
            "launch_10_message": "You have launched {app} 10 times.\nPlease check for updates on GitHub: {url}",
            "launch_10_prompt": "Press Enter to continue...",
            "password_in_cmdline": "WARNING: Using command-line passwords is insecure. Use interactive input instead.",
        }
        ru = {
            "app_name": APP_NAME,
            "app_full_name": APP_FULL_NAME,
            "version": "Версия",
            "yes": "Да",
            "no": "Нет",
            "cancel": "Отмена",
            "continue": "Продолжить",
            "back": "Назад",
            "exit": "Выход",
            "main_menu": "ГЛАВНОЕ МЕНЮ",
            "file_operations": "Работа с файлами",
            "folder_operations": "Работа с папками",
            "settings": "Настройки",
            "security_settings": "Настройки безопасности",
            "encryption_settings": "Настройки шифрования",
            "about": "О программе",
            "encrypt_file": "Зашифровать файл",
            "decrypt_file": "Расшифровать файл",
            "change_password": "Изменить пароль",
            "verify_file": "Проверить файл",
            "encrypt_folder": "Зашифровать папку",
            "decrypt_folder": "Расшифровать папку",
            "change_password_folder": "Изменить пароль",
            "verify_folder": "Проверить папку",
            "file_path": "Введите путь к файлу",
            "encrypted_file_path": "Введите путь к зашифрованному файлу",
            "folder_path": "Введите путь к папке",
            "enter_password": "Введите пароль",
            "enter_new_password": "Введите новый пароль",
            "confirm_password": "Подтвердите пароль",
            "current_password": "Введите текущий пароль",
            "choose_action": "Выберите действие",
            "current_settings": "Текущие настройки",
            "language": "Язык",
            "language_auto": "Авто",
            "language_en": "Английский",
            "language_ru": "Русский",
            "language_prompt": "Выберите язык",
            "language_changed": "Язык изменён на {}",
            "language_restart": "Перезапустить сейчас? (y/n): ",
            "path_completion": "Автодополнение путей включено",
            "file_not_found": "Файл не найден",
            "folder_not_found": "Папка не найдена",
            "invalid_file": "Некорректный зашифрованный файл",
            "invalid_password": "Неверный пароль",
            "password_mismatch": "Пароли не совпадают",
            "password_visible": "Пароль виден",
            "password_stars": "Пароль скрыт звёздочками",
            "password_hidden": "Пароль скрыт",
            "char_counter_enabled": "Счётчик символов включён",
            "char_counter_disabled": "Счётчик символов выключен",
            "logging_enabled": "Логирование включено",
            "logging_disabled": "Логирование выключено",
            "temp_enabled": "Временные файлы включены",
            "temp_disabled": "Временные файлы выключены",
            "eula": "Лицензия",
            "eula_title": "Лицензионное соглашение",
            "eula_intro": "Прочитайте соглашение и примите его для продолжения.",
            "eula_link": "Соглашение находится по адресу:",
            "eula_accept_prompt": "Вы принимаете лицензию?",
            "eula_accepted_message": "Лицензия принята",
            "eula_declined": "Лицензия отклонена",
            "eula_accepted": "Лицензия принята",
            "eula_not_accepted": "Лицензия не принята",
            "error": "Ошибка",
            "error_critical": "Критическая ошибка: {}",
            "error_missing_dependency": "Отсутствует зависимость: {}",
            "error_install_crypto": "Установите пакет cryptography.",
            "error_interrupted": "Прервано пользователем",
            "error_invalid_choice": "Неверный выбор",
            "error_invalid_number": "Неверное число",
            "error_eula_not_accepted": "Сначала нужно принять лицензию",
            "access_denied": "Нет доступа",
            "warning": "Предупреждение",
            "file_too_large": "Файл слишком большой. Максимум {} ГБ",
            "encrypted_success": "Успешно зашифровано",
            "decrypted_success": "Успешно расшифровано",
            "password_changed": "Пароль успешно изменён",
            "verification_passed": "Проверка пройдена",
            "verification_failed": "Проверка не пройдена",
            "saved": "Сохранено",
            "save_settings": "Сохранить настройки",
            "reset_settings": "Сбросить настройки",
            "security_info": "Информация о безопасности",
            "processing_file": "Обработка файла {} из {}: {}",
            "threads": "Потоки",
            "threads_prompt": "Потоки",
            "threads_info": "Используется {} рабочих потоков",
            "min_password_length": "Минимальная длина пароля",
            "iterations": "Итерации PBKDF2",
            "max_file_size": "Макс. размер файла",
            "algorithm": "Алгоритм",
            "key_size": "Размер ключа",
            "salt_size": "Размер соли",
            "nonce_size": "Размер nonce",
            "req_length": "Пароль должен быть не короче {} символов",
            "req_uppercase": "Пароль должен содержать заглавную букву",
            "req_lowercase": "Пароль должен содержать строчную букву",
            "req_digit": "Пароль должен содержать цифру",
            "req_special": "Пароль должен содержать спецсимвол",
            "req_not_common": "Пароль слишком распространён",
            "password_valid": "Пароль подходит",
            "starting": "Запуск",
            "encrypted_file_exists": "Зашифрованный файл уже существует",
            "original_file_exists": "Исходный файл уже существует",
            "confirm_overwrite": "Перезаписать? (y/n): ",
            "temp_files": "Временные файлы",
            "logging": "Логирование",
            "password_mode": "Режим пароля",
            "char_counter": "Счётчик символов",
            "key_vault": "Хранилище ключей",
            "create_managed_key": "Создать управляемый ключ",
            "list_managed_keys": "Список управляемых ключей",
            "encrypt_with_managed_key": "Зашифровать управляемым ключом",
            "decrypt_with_managed_key": "Расшифровать управляемым ключом",
            "key_vault_menu": "Хранилище ключей",
            "drive_root_prompt": "Путь к диску / хранилищу ключей",
            "key_label_prompt": "Метка ключа",
            "key_passphrase_prompt": "Парольная фраза ключа",
            "allowed_targets_prompt": "Разрешённые цели (пути или шаблоны через запятую)",
            "notes_prompt": "Заметки (необязательно)",
            "key_created": "Создан управляемый ключ: {}",
            "no_keys_found": "Управляемые ключи не найдены.",
            "key_id": "ID ключа",
            "scan_root_prompt": "Диск / хранилище для сканирования (пусто = все)",
            "path_to_encrypt": "Путь к файлу или папке",
            "path_to_decrypt": "Путь к файлу или папке",
            "drive_root_optional": "Диск / хранилище (пусто = автоопределение)",
            "processing_recursively": "Обрабатывать рекурсивно? (y/n)",
            "reset_eula_prompt": "Сбросить принятие лицензии? (y/n): ",
            "reset_all_settings": "Сбросить все настройки? (y/n): ",
            "open_source": "Открытый проект",
            "github_main": "GitHub (основной)",
            "github_repo": "GitHub (репозиторий)",
            "official_website": "Официальный сайт",
            "update_reminder": "Проверьте обновления: {}",
            "launch_10_message": "Вы запустили {app} уже 10 раз.\nПроверьте обновления на GitHub: {url}",
            "launch_10_prompt": "Нажмите Enter для продолжения...",
            "password_in_cmdline": "ВНИМАНИЕ: Пароли в командной строке небезопасны. Используйте интерактивный ввод.",
        }
        self._translations = {"en": en, "ru": ru}
        self._current_language = Language.AUTO

    def detect_system_language(self):
        try:
            if os.name == "nt":
                import ctypes
                windll = ctypes.windll.kernel32
                lang_id = windll.GetUserDefaultUILanguage()
                if lang_id == 1049:
                    return Language.RUSSIAN
                if lang_id == 1033:
                    return Language.ENGLISH
            for var in ("LANG", "LANGUAGE", "LC_ALL"):
                val = os.environ.get(var, "").lower()
                if "ru" in val:
                    return Language.RUSSIAN
                if "en" in val:
                    return Language.ENGLISH
            lc, _ = locale.getlocale()
            if lc:
                if lc.startswith("ru"):
                    return Language.RUSSIAN
                if lc.startswith("en"):
                    return Language.ENGLISH
        except Exception:
            pass
        return Language.ENGLISH

    def set_language(self, lang):
        self._current_language = lang

    def get_language(self):
        return self._current_language

    def get_current_language(self):
        if self._current_language == Language.AUTO:
            return self.detect_system_language()
        return self._current_language

    def t(self, key, *args, **kwargs):
        lang = self.get_current_language().value
        tr = self._translations.get(lang, self._translations["en"]).get(key, self._translations["en"].get(key, key))
        try:
            if args or kwargs:
                return tr.format(*args, **kwargs)
            return tr
        except Exception:
            return tr

_ = I18N().t

@dataclass
class EncryptionConfig:
    iterations: int = 600_000
    key_size: int = 32
    salt_size: int = 16
    nonce_size: int = 12
    algorithm: str = "AES-256-GCM"
    min_password_length: int = 12
    max_file_size_gb: int = 10
    chunk_size: int = 64 * 1024

    @classmethod
    def load(cls, config_file="securblack_config.json"):
        if not os.path.exists(config_file):
            return cls()
        try:
            with open(config_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            filtered = {k: v for k, v in data.items() if k in cls.__dataclass_fields__}
            return cls(**filtered)
        except Exception as e:
            print_error(_("error_critical", str(e)))
            return cls()

    def save(self, config_file="securblack_config.json"):
        try:
            with open(config_file, "w", encoding="utf-8") as f:
                json.dump(asdict(self), f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print_error(_("error_critical", str(e)))
            return False

@dataclass
class ManagedKeyRecord:
    key_id: str
    label: str
    salt: str
    nonce: str
    wrapped_key: str
    iterations: int
    allowed_targets: list = field(default_factory=list)
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())
    notes: str = ""

@dataclass
class ManagedKeySession:
    record: ManagedKeyRecord
    raw_key: bytes
    root_path: str

class KeyVaultManager:
    def __init__(self, config=None):
        self.config = config or EncryptionConfig.load()

    @staticmethod
    def _normalize_path(value):
        val = os.path.expanduser(value.strip())
        val = os.path.abspath(val)
        # resolve symlinks to prevent bypass
        val = os.path.realpath(val)
        norm = os.path.normpath(val)
        if os.name == "nt":
            norm = norm.lower()
        return norm.replace("\\", "/")

    @staticmethod
    def _pattern_matches(path, pattern):
        cand = KeyVaultManager._normalize_path(path)
        pat = KeyVaultManager._normalize_path(pattern)
        if pat.endswith("/*"):
            base = pat[:-2]
            return cand == base or cand.startswith(base + "/")
        if pat.endswith("/"):
            pat = pat.rstrip("/")
        return fnmatch.fnmatchcase(cand, pat)

    @classmethod
    def is_target_allowed(cls, target_path, allowed_targets):
        if not allowed_targets:
            return True
        return any(cls._pattern_matches(target_path, p) for p in allowed_targets)

    @classmethod
    def _default_vault_dir(cls, root_path):
        return os.path.join(root_path, KEY_VAULT_DIR_NAME)

    @classmethod
    def _record_path(cls, root_path, key_id):
        return os.path.join(cls._default_vault_dir(root_path), f"{key_id}.json")

    @staticmethod
    def _candidate_roots():
        roots = []
        if os.name == "nt":
            for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
                drive = f"{letter}:\\"
                if os.path.exists(drive):
                    roots.append(drive)
        else:
            for base in ("/media", "/mnt", "/run/media", "/Volumes"):
                if os.path.isdir(base):
                    try:
                        with os.scandir(base) as entries:
                            for entry in entries:
                                if entry.is_dir(follow_symlinks=False):
                                    roots.append(entry.path)
                    except Exception:
                        continue
            for cand in ("/mnt/data", str(Path.home())):
                if os.path.isdir(cand):
                    roots.append(cand)
        seen = set()
        out = []
        for r in roots:
            nr = os.path.abspath(r)
            if nr not in seen:
                seen.add(nr)
                out.append(nr)
        return out

    @staticmethod
    def _encode_bytes(data):
        return base64.urlsafe_b64encode(data).decode("ascii")

    @staticmethod
    def _decode_bytes(data):
        return base64.urlsafe_b64decode(data.encode("ascii"))

    def create_key_record(self, label, passphrase, root_path, allowed_targets=None, notes=""):
        if isinstance(passphrase, SecureString):
            passphrase = passphrase.get()
        os.makedirs(self._default_vault_dir(root_path), exist_ok=True)
        raw = secrets.token_bytes(self.config.key_size)
        salt = secrets.token_bytes(self.config.salt_size)
        nonce = secrets.token_bytes(self.config.nonce_size)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.config.key_size,
            salt=salt,
            iterations=self.config.iterations,
        )
        protector = kdf.derive(passphrase.encode("utf-8"))
        aesgcm = AESGCM(protector)
        wrapped = aesgcm.encrypt(nonce, raw, b"SBX-KEY-V1")

        rec = ManagedKeyRecord(
            key_id=secrets.token_hex(16),
            label=label.strip() or "managed-key",
            salt=self._encode_bytes(salt),
            nonce=self._encode_bytes(nonce),
            wrapped_key=self._encode_bytes(wrapped),
            iterations=self.config.iterations,
            allowed_targets=[self._normalize_path(p) for p in (allowed_targets or []) if p.strip()],
            notes=notes.strip(),
        )
        path = self._record_path(root_path, rec.key_id)
        payload = asdict(rec)
        payload["created_at"] = rec.created_at
        payload["root_hint"] = self._normalize_path(root_path)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        return rec

    def _load_record_from_file(self, record_path):
        with open(record_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        filtered = {k: v for k, v in data.items() if k in ManagedKeyRecord.__dataclass_fields__}
        filtered.setdefault("allowed_targets", [])
        filtered.setdefault("notes", "")
        filtered.setdefault("created_at", datetime.now().isoformat())
        return ManagedKeyRecord(**filtered)

    def find_record_path(self, key_id, root_hint=None, wait=True, timeout=None):
        start = time.time()
        while True:
            roots = [root_hint] if root_hint else self._candidate_roots()
            for root in roots:
                if not root:
                    continue
                cand = self._record_path(root, key_id)
                if os.path.exists(cand):
                    return cand
            if not wait:
                break
            if timeout is not None and (time.time() - start) >= timeout:
                break
            print_info(f"Waiting for key drive / vault for key {key_id}...")
            time.sleep(2)
        raise FileNotFoundError(f"Key record {key_id} not found")

    def load_record(self, key_id, root_hint=None, wait=True, timeout=None):
        path = self.find_record_path(key_id, root_hint, wait, timeout)
        rec = self._load_record_from_file(path)
        root_dir = os.path.dirname(os.path.dirname(path))
        return rec, root_dir

    def open_session(self, key_id, passphrase, root_hint=None, wait=True, timeout=None):
        if isinstance(passphrase, SecureString):
            passphrase = passphrase.get()
        rec, root_dir = self.load_record(key_id, root_hint, wait, timeout)
        salt = self._decode_bytes(rec.salt)
        nonce = self._decode_bytes(rec.nonce)
        wrapped = self._decode_bytes(rec.wrapped_key)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.config.key_size,
            salt=salt,
            iterations=rec.iterations,
        )
        protector = kdf.derive(passphrase.encode("utf-8"))
        aesgcm = AESGCM(protector)
        try:
            raw = aesgcm.decrypt(nonce, wrapped, b"SBX-KEY-V1")
        except InvalidTag as e:
            raise ValueError(_("invalid_password")) from e
        return ManagedKeySession(record=rec, raw_key=raw, root_path=root_dir)

    def list_records(self, root_hint=None):
        res = []
        roots = [root_hint] if root_hint else self._candidate_roots()
        for root in roots:
            if not root:
                continue
            vault = self._default_vault_dir(root)
            if not os.path.isdir(vault):
                continue
            for fname in os.listdir(vault):
                if not fname.endswith(".json"):
                    continue
                full = os.path.join(vault, fname)
                try:
                    rec = self._load_record_from_file(full)
                    res.append((root, rec, full))
                except Exception:
                    continue
        return res

    def describe_targets(self, targets):
        if not targets:
            return "all targets" if I18N().get_current_language() == Language.ENGLISH else "все цели"
        return ", ".join(targets)

class Settings:
    SHOW_PASSWORD = False
    SHOW_PASSWORD_STARS = True
    SHOW_CHAR_COUNT = True
    KEEP_TEMP_FILES = False
    ENABLE_LOGGING = False
    TEMP_FILES_DIR = "temp_encrypted"
    BACKUP_DIR = "backups"
    LOGS_DIR = "logs"
    EULA_ACCEPTED = False
    LANGUAGE = Language.AUTO.value
    THREADS = 4
    AUTO_YES = False
    LAUNCH_COUNT = 0

    @classmethod
    def load(cls, settings_file="securblack_settings.json"):
        if not os.path.exists(settings_file):
            try:
                I18N().set_language(Language(cls.LANGUAGE))
            except Exception:
                I18N().set_language(Language.AUTO)
            return False
        try:
            with open(settings_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            cls.SHOW_PASSWORD = data.get("show_password", False)
            cls.SHOW_PASSWORD_STARS = data.get("show_password_stars", True)
            cls.SHOW_CHAR_COUNT = data.get("show_char_count", True)
            cls.KEEP_TEMP_FILES = data.get("keep_temp_files", False)
            cls.ENABLE_LOGGING = data.get("enable_logging", False)
            cls.TEMP_FILES_DIR = data.get("temp_files_dir", "temp_encrypted")
            cls.BACKUP_DIR = data.get("backup_dir", "backups")
            cls.LOGS_DIR = data.get("logs_dir", "logs")
            cls.EULA_ACCEPTED = data.get("eula_accepted", False)
            cls.LANGUAGE = data.get("language", Language.AUTO.value)
            cls.THREADS = int(data.get("threads", 4))
            cls.AUTO_YES = data.get("auto_yes", False)
            cls.LAUNCH_COUNT = int(data.get("launch_count", 0))
            try:
                I18N().set_language(Language(cls.LANGUAGE))
            except Exception:
                I18N().set_language(Language.AUTO)
            return True
        except Exception as e:
            print_warning(f"Settings load error: {e}")
            return False

    @classmethod
    def save(cls, settings_file="securblack_settings.json"):
        try:
            sdata = {
                "show_password": cls.SHOW_PASSWORD,
                "show_password_stars": cls.SHOW_PASSWORD_STARS,
                "show_char_count": cls.SHOW_CHAR_COUNT,
                "keep_temp_files": cls.KEEP_TEMP_FILES,
                "enable_logging": cls.ENABLE_LOGGING,
                "temp_files_dir": cls.TEMP_FILES_DIR,
                "backup_dir": cls.BACKUP_DIR,
                "logs_dir": cls.LOGS_DIR,
                "eula_accepted": cls.EULA_ACCEPTED,
                "language": I18N().get_language().value,
                "threads": cls.THREADS,
                "auto_yes": cls.AUTO_YES,
                "launch_count": cls.LAUNCH_COUNT,
                "last_update": datetime.now().isoformat(),
            }
            with open(settings_file, "w", encoding="utf-8") as f:
                json.dump(sdata, f, indent=2, ensure_ascii=False)
            return True
        except Exception as e:
            print_error(_("error_critical", str(e)))
            return False

class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    RESET = "\033[0m"
    BOLD = "\033[1m"
    GRAY = "\033[90m"
    WHITE = "\033[97m"

def print_success(msg):
    print(f"{Colors.GREEN}✓ {msg}{Colors.RESET}")

def print_error(msg):
    print(f"{Colors.RED}✗ {msg}{Colors.RESET}")

def print_warning(msg):
    print(f"{Colors.YELLOW}⚠ {msg}{Colors.RESET}")

def print_info(msg):
    print(f"{Colors.CYAN}ℹ {msg}{Colors.RESET}")

def clear_screen():
    os.system("cls" if os.name == "nt" else "clear")

@contextmanager
def secure_memory(data):
    if isinstance(data, str):
        buf = bytearray(data.encode("utf-8"))
    elif isinstance(data, bytes):
        buf = bytearray(data)
    else:
        buf = data
    try:
        yield buf
    finally:
        for i in range(len(buf)):
            buf[i] = 0
        gc.collect()

class SecureString:
    def __init__(self, value=""):
        self._value = bytearray(value.encode("utf-8"))

    def __del__(self):
        try:
            for i in range(len(self._value)):
                self._value[i] = 0
        except Exception:
            pass

    def get(self):
        return self._value.decode("utf-8")

    def __len__(self):
        return len(self._value)

    def clear(self):
        for i in range(len(self._value)):
            self._value[i] = 0
        self._value = bytearray()

def setup_readline():
    try:
        if os.name == "nt":
            try:
                import pyreadline3 as readline
            except Exception:
                return False
        else:
            import readline
        readline.set_completer_delims(" \t\n;")
        readline.parse_and_bind("tab: complete")
        return True
    except Exception:
        return False

def _supports_tty_input():
    return sys.stdin.isatty() and sys.stdout.isatty()

def _read_password_interactive(prompt, mode, show_count):
    if not _supports_tty_input():
        if mode == "hidden":
            return getpass(prompt)
        return input(prompt)

    rendered = []
    prev_len = 0

    def redraw():
        nonlocal prev_len
        line = prompt
        if mode == "visible":
            line += "".join(rendered)
        elif mode == "stars":
            line += "*" * len(rendered)
        if show_count:
            line += f" [{len(rendered)}]"
        sys.stdout.write("\r\033[2K")
        sys.stdout.write(line)
        if prev_len > len(line):
            sys.stdout.write(" " * (prev_len - len(line)))
            sys.stdout.write("\r\033[2K")
            sys.stdout.write(line)
        prev_len = len(line)
        sys.stdout.flush()

    if os.name == "nt":
        import msvcrt
        sys.stdout.write(prompt)
        sys.stdout.flush()
        while True:
            ch = msvcrt.getwch()
            if ch in ("\r", "\n"):
                break
            if ch == "\x03":
                raise KeyboardInterrupt
            if ch in ("\b", "\x7f"):
                if rendered:
                    rendered.pop()
                    redraw()
                continue
            rendered.append(ch)
            redraw()
        sys.stdout.write("\n")
        sys.stdout.flush()
        return "".join(rendered)

    import termios
    import tty
    fd = sys.stdin.fileno()
    old = termios.tcgetattr(fd)
    try:
        tty.setraw(fd)
        sys.stdout.write(prompt)
        sys.stdout.flush()
        while True:
            ch = sys.stdin.read(1)
            if ch in ("\r", "\n"):
                break
            if ch == "\x03":
                raise KeyboardInterrupt
            if ch in ("\x7f", "\b"):
                if rendered:
                    rendered.pop()
                    redraw()
                continue
            rendered.append(ch)
            redraw()
    finally:
        termios.tcsetattr(fd, termios.TCSADRAIN, old)
    sys.stdout.write("\n")
    sys.stdout.flush()
    return "".join(rendered)

def get_password_input(prompt, confirm=False):
    print()
    if Settings.SHOW_PASSWORD:
        print(f"{Colors.GRAY}[{_('password_visible')}] {Colors.RESET}", end="")
        pwd = _read_password_interactive(prompt, "visible", Settings.SHOW_CHAR_COUNT)
    elif Settings.SHOW_PASSWORD_STARS:
        print(f"{Colors.GRAY}[{_('password_stars')}] {Colors.RESET}", end="")
        pwd = _read_password_interactive(prompt, "stars", Settings.SHOW_CHAR_COUNT)
    else:
        print(f"{Colors.GRAY}[{_('password_hidden')}] {Colors.RESET}", end="")
        pwd = _read_password_interactive(prompt, "hidden", Settings.SHOW_CHAR_COUNT)
    if confirm:
        second = get_password_input(_("confirm_password") + ": ")
        if not second or pwd != second.get():
            print_error(_("password_mismatch"))
            return None
    return SecureString(pwd)

class CryptoEngine:
    def __init__(self, config):
        self.config = config

    def derive_key(self, password, salt):
        if isinstance(password, SecureString):
            password = password.get()
        # Avoid leaving password in memory longer than needed
        pw_bytes = bytearray(password.encode("utf-8"))
        try:
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=self.config.key_size,
                salt=salt,
                iterations=self.config.iterations,
            )
            key = kdf.derive(pw_bytes)
            return key
        finally:
            for i in range(len(pw_bytes)):
                pw_bytes[i] = 0

    @staticmethod
    def _canonical_meta(meta):
        return json.dumps(meta, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

    def _write_header_v2(self, out, meta):
        mbytes = self._canonical_meta(meta)
        out.write(MAGIC)
        out.write(bytes([FORMAT_VERSION]))
        out.write(len(mbytes).to_bytes(4, "big"))
        out.write(mbytes)
        return mbytes

    def _read_header(self, inp):
        magic = inp.read(len(MAGIC))
        if magic != MAGIC:
            raise ValueError(_("invalid_file"))
        vb = inp.read(1)
        if len(vb) != 1:
            raise ValueError(_("invalid_file"))
        version = vb[0]
        if version == 1:
            salt = inp.read(self.config.salt_size)
            if len(salt) != self.config.salt_size:
                raise ValueError(_("invalid_file"))
            meta = {"mode": "password", "salt": KeyVaultManager._encode_bytes(salt)}
            aad = MAGIC + bytes([version]) + salt
            return version, meta, aad
        if version != FORMAT_VERSION:
            raise ValueError(_("invalid_file"))
        raw_len = inp.read(4)
        if len(raw_len) != 4:
            raise ValueError(_("invalid_file"))
        metalen = int.from_bytes(raw_len, "big")
        mbytes = inp.read(metalen)
        if len(mbytes) != metalen:
            raise ValueError(_("invalid_file"))
        try:
            meta = json.loads(mbytes.decode("utf-8"))
        except Exception as e:
            raise ValueError(_("invalid_file")) from e
        aad = MAGIC + bytes([version]) + mbytes
        return version, meta, aad

    def inspect_metadata(self, path):
        with open(path, "rb") as f:
            return self._read_header(f)[:2]

    def encrypt_stream(self, in_, out, credential, *, raw_key=None, metadata=None):
        if raw_key is None:
            salt = secrets.token_bytes(self.config.salt_size)
            key = self.derive_key(credential, salt)
            meta = {"mode": "password", "salt": KeyVaultManager._encode_bytes(salt)}
        else:
            key = raw_key
            meta = {"mode": "managed"}
            if metadata:
                meta.update(metadata)
        content_hasher = hashlib.sha256()
        try:
            pos = in_.tell()
            in_.seek(0)
            while True:
                chunk = in_.read(self.config.chunk_size)
                if not chunk:
                    break
                content_hasher.update(chunk)
            in_.seek(pos)
        except (io.UnsupportedOperation, AttributeError):
            data = in_.read()
            content_hasher.update(data)
            in_ = io.BytesIO(data)
        content_hash = content_hasher.hexdigest()
        meta["content_hash"] = content_hash

        mbytes = self._write_header_v2(out, meta)
        base_aad = MAGIC + bytes([FORMAT_VERSION]) + mbytes

        aesgcm = AESGCM(key)
        chunk_idx = 0
        while True:
            plain = in_.read(self.config.chunk_size)
            if not plain:
                break
            plain_len = len(plain)
            chunk_aad = base_aad + chunk_idx.to_bytes(4, "big") + plain_len.to_bytes(4, "big")
            nonce = secrets.token_bytes(self.config.nonce_size)
            ct = aesgcm.encrypt(nonce, plain, chunk_aad)
            out.write(chunk_idx.to_bytes(4, "big"))
            out.write(plain_len.to_bytes(4, "big"))
            out.write(nonce)
            out.write(len(ct).to_bytes(4, "big"))
            out.write(ct)
            chunk_idx += 1
        return content_hash

    def decrypt_stream(self, in_, out, credential, *, raw_key=None, managed_record=None):
        version, meta, aad = self._read_header(in_)
        mode = meta.get("mode", "password")
        if mode == "password":
            salt_raw = meta.get("salt", "")
            if isinstance(salt_raw, str):
                salt = KeyVaultManager._decode_bytes(salt_raw)
            else:
                salt = salt_raw
            if not isinstance(salt, (bytes, bytearray)) or len(salt) != self.config.salt_size:
                raise ValueError(_("invalid_file"))
            key = self.derive_key(credential, bytes(salt))
        elif mode == "managed":
            if raw_key is None:
                raise ValueError(_("access_denied"))
            if managed_record is not None:
                kid = meta.get("key_id")
                if kid and managed_record.key_id != kid:
                    raise ValueError(_("access_denied"))
                ptag = meta.get("policy_tag")
                if ptag and not KeyVaultManager.is_target_allowed(ptag, managed_record.allowed_targets):
                    raise ValueError(_("access_denied"))
            key = raw_key
        else:
            raise ValueError(_("invalid_file"))
        base_aad = MAGIC + bytes([FORMAT_VERSION]) + self._canonical_meta(meta)
        aesgcm = AESGCM(key)
        content_hasher = hashlib.sha256()
        while True:
            idx_raw = in_.read(4)
            if not idx_raw:
                break
            if len(idx_raw) != 4:
                raise ValueError(_("invalid_file"))
            chunk_idx = int.from_bytes(idx_raw, "big")
            plen_raw = in_.read(4)
            if len(plen_raw) != 4:
                raise ValueError(_("invalid_file"))
            plain_len = int.from_bytes(plen_raw, "big")
            nonce = in_.read(self.config.nonce_size)
            if len(nonce) != self.config.nonce_size:
                raise ValueError(_("invalid_file"))
            ct_len_raw = in_.read(4)
            if len(ct_len_raw) != 4:
                raise ValueError(_("invalid_file"))
            ct_len = int.from_bytes(ct_len_raw, "big")
            ct = in_.read(ct_len)
            if len(ct) != ct_len:
                raise ValueError(_("invalid_file"))
            chunk_aad = base_aad + chunk_idx.to_bytes(4, "big") + plain_len.to_bytes(4, "big")
            try:
                plain = aesgcm.decrypt(nonce, ct, chunk_aad)
            except InvalidTag as e:
                raise ValueError(_("invalid_password")) from e
            if len(plain) != plain_len:
                raise ValueError(_("invalid_file"))
            content_hasher.update(plain)
            out.write(plain)
        expected_hash = meta.get("content_hash")
        if expected_hash:
            actual_hash = content_hasher.hexdigest()
            if actual_hash != expected_hash:
                raise ValueError(_("verification_failed"))
        return actual_hash if expected_hash else content_hasher.hexdigest()

    def verify_password(self, path, password):
        try:
            with open(path, "rb") as f:
                version, meta, aad = self._read_header(f)
                if meta.get("mode") != "password":
                    return False
                base_aad = MAGIC + bytes([FORMAT_VERSION]) + self._canonical_meta(meta)
                salt = KeyVaultManager._decode_bytes(meta["salt"])
                key = self.derive_key(password, salt)
                aesgcm = AESGCM(key)
                idx_raw = f.read(4)
                if len(idx_raw) != 4:
                    return False
                chunk_idx = int.from_bytes(idx_raw, "big")
                plen_raw = f.read(4)
                if len(plen_raw) != 4:
                    return False
                plain_len = int.from_bytes(plen_raw, "big")
                nonce = f.read(self.config.nonce_size)
                if len(nonce) != self.config.nonce_size:
                    return False
                ct_len_raw = f.read(4)
                if len(ct_len_raw) != 4:
                    return False
                ct_len = int.from_bytes(ct_len_raw, "big")
                ct = f.read(ct_len)
                if len(ct) != ct_len:
                    return False
                chunk_aad = base_aad + chunk_idx.to_bytes(4, "big") + plain_len.to_bytes(4, "big")
                try:
                    aesgcm.decrypt(nonce, ct, chunk_aad)
                    return True
                except InvalidTag:
                    return False
        except Exception:
            return False

class FileHandler:
    def __init__(self, settings):
        self.settings = settings
        self._create_dirs()

    def _create_dirs(self):
        if self.settings.KEEP_TEMP_FILES:
            os.makedirs(self.settings.TEMP_FILES_DIR, exist_ok=True)
        if self.settings.ENABLE_LOGGING:
            os.makedirs(self.settings.LOGS_DIR, exist_ok=True)
        os.makedirs(self.settings.BACKUP_DIR, exist_ok=True)

    def calculate_hash(self, path):
        h = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    h.update(chunk)
            return h.hexdigest()
        except Exception as e:
            print_error(f"Hash error: {e}")
            return ""

    def create_backup(self, path):
        try:
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            name = f"{os.path.basename(path)}.{stamp}.backup"
            dest = os.path.join(self.settings.BACKUP_DIR, name)
            shutil.copy2(path, dest)
            return dest
        except Exception as e:
            print_warning(f"Backup failed: {e}")
            return None

    def safe_move(self, src, dst, overwrite=False):
        if os.path.exists(dst) and not overwrite and not Settings.AUTO_YES:
            ans = input(f"{_('warning')}: {dst} exists. Overwrite? (y/n): ")
            if ans.lower() != "y":
                return False
        try:
            os.replace(src, dst)
            return True
        except Exception as e:
            print_error(f"Move failed: {e}")
            return False

    def safe_delete(self, path, secure=True):
        try:
            if not os.path.exists(path):
                return True
            if secure:
                size = os.path.getsize(path)
                with open(path, "r+b") as f:
                    f.seek(0)
                    f.write(secrets.token_bytes(size))
                    f.flush()
                    os.fsync(f.fileno())
            os.remove(path)
            return True
        except Exception as e:
            print_error(f"Delete failed: {e}")
            return False

    def get_files_recursive(self, folder, pattern="*", exclude_pattern=None, recursive=True):
        fp = Path(folder)
        if not fp.exists():
            return []
        it = fp.rglob(pattern) if recursive else fp.glob(pattern)
        files = []
        for f in it:
            if not f.is_file():
                continue
            if exclude_pattern and exclude_pattern in f.name:
                continue
            files.append(str(f))
        return files

    def get_temp_path(self, original):
        if self.settings.KEEP_TEMP_FILES:
            os.makedirs(self.settings.TEMP_FILES_DIR, exist_ok=True)
            tmp = os.path.basename(original) + ".tmp"
            tmp = os.path.join(self.settings.TEMP_FILES_DIR, tmp)
            fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_RDWR, 0o600)
            os.close(fd)
            return tmp
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(original) or ".", suffix=".tmp")
        os.close(fd)
        os.chmod(tmp, 0o600)
        return tmp

class SecureLogger:
    def __init__(self, settings):
        self.settings = settings
        self.logger = None
        self._setup()

    def _setup(self):
        if not self.settings.ENABLE_LOGGING:
            return
        try:
            os.makedirs(self.settings.LOGS_DIR, exist_ok=True)
            fname = os.path.join(self.settings.LOGS_DIR, f"securblack_{datetime.now().strftime('%Y%m%d')}.log")
            self.logger = logging.getLogger(f"SecurBlack-{id(self)}")
            self.logger.setLevel(logging.INFO)
            self.logger.handlers.clear()
            h = logging.FileHandler(fname, encoding="utf-8")
            h.setLevel(logging.INFO)
            fmt = logging.Formatter("%(asctime)s - %(levelname)s - %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
            h.setFormatter(fmt)
            self.logger.addHandler(h)
            self.logger.propagate = False
        except Exception as e:
            print_warning(f"Logger setup failed: {e}")
            self.logger = None

    def log(self, level, msg, sensitive=False):
        if not self.logger or not self.settings.ENABLE_LOGGING or sensitive:
            return
        if level == "info":
            self.logger.info(msg)
        elif level == "error":
            self.logger.error(msg)
        elif level == "warning":
            self.logger.warning(msg)
        elif level == "debug":
            self.logger.debug(msg)
        else:
            self.logger.info(msg)

class FileEncryptor:
    def __init__(self, config=None, settings=None):
        self.config = config or EncryptionConfig.load()
        self.settings = settings or Settings()
        self.crypto = CryptoEngine(self.config)
        self.fh = FileHandler(self.settings)
        self.logger = SecureLogger(self.settings)
        self.kv = KeyVaultManager(self.config)

    def create_managed_key(self, label, passphrase, root_path, allowed_targets=None, notes=""):
        return self.kv.create_key_record(label, passphrase, root_path, allowed_targets=allowed_targets, notes=notes)

    def load_managed_key_session(self, key_id, passphrase, root_hint=None, wait=True, timeout=None):
        return self.kv.open_session(key_id, passphrase, root_hint=root_hint, wait=wait, timeout=timeout)

    def _policy_tag_for_path(self, path):
        return KeyVaultManager._normalize_path(path)

    def validate_password(self, pwd):
        if len(pwd) < self.config.min_password_length:
            return False, _("req_length", self.config.min_password_length)
        if not re.search(r"[A-Z]", pwd):
            return False, _("req_uppercase")
        if not re.search(r"[a-z]", pwd):
            return False, _("req_lowercase")
        if not re.search(r"\d", pwd):
            return False, _("req_digit")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", pwd):
            return False, _("req_special")
        common = {"password", "123456", "qwerty", "admin", "welcome",
                  "password123", "123456789", "letmein", "monkey", "dragon"}
        if pwd.lower() in common:
            return False, _("req_not_common")
        return True, _("password_valid")

    def _resolve_output_path(self, src, out, decrypt=False):
        if out:
            return out
        if decrypt and src.endswith(".enc"):
            return src[:-4]
        return src + ".enc"

    def encrypt_file(self, file_path, password, create_backup=True, keep_temp=None, overwrite=False, output=None,
                     managed_key_id=None, managed_key_password=None, managed_key_root=None, policy_tag=None):
        self.logger.log("info", f"Encrypt start: {file_path}")
        if not os.path.exists(file_path):
            print_error(_("file_not_found"))
            return False
        if not os.access(file_path, os.R_OK):
            print_error(_("access_denied"))
            return False
        size = os.path.getsize(file_path)
        if size > self.config.max_file_size_gb * 1024**3:
            print_error(_("file_too_large", self.config.max_file_size_gb))
            return False
        out_path = self._resolve_output_path(file_path, output)
        if os.path.exists(out_path) and not overwrite and not Settings.AUTO_YES:
            ans = input(f"{_('warning')}: {out_path} exists. Overwrite? (y/n): ")
            if ans.lower() != "y":
                print_info(_("cancel"))
                return False
        backup_ok = True
        if create_backup:
            bp = self.fh.create_backup(file_path)
            if bp:
                print_info(f"Backup: {bp}")
            else:
                backup_ok = False
        keep = Settings.KEEP_TEMP_FILES if keep_temp is None else keep_temp
        tmp = self.fh.get_temp_path(file_path)
        ms = None
        if managed_key_id:
            if managed_key_password is None:
                print_error(_("enter_password"))
                return False
            try:
                ms = self.load_managed_key_session(managed_key_id, managed_key_password, root_hint=managed_key_root, wait=True)
            except Exception as e:
                print_error(str(e))
                return False
            ptag = policy_tag or self._policy_tag_for_path(file_path)
            if ms.record.allowed_targets and not self.kv.is_target_allowed(ptag, ms.record.allowed_targets):
                print_error(_("access_denied"))
                return False
        try:
            with open(file_path, "rb") as src, open(tmp, "wb") as dst:
                if ms is not None:
                    self.crypto.encrypt_stream(src, dst, "", raw_key=ms.raw_key,
                                               metadata={"mode": "managed", "key_id": ms.record.key_id,
                                                         "policy_tag": ptag if ms else self._policy_tag_for_path(file_path),
                                                         "key_label": ms.record.label if ms else ""})
                else:
                    self.crypto.encrypt_stream(src, dst, password)
            if keep:
                print_success(f"{_('encrypted_success')}: {tmp}")
                self.logger.log("info", f"Enc temp kept: {tmp}")
                return True
            if self.fh.safe_move(tmp, out_path, overwrite=True):
                if create_backup and not backup_ok:
                    print_warning("Backup failed, original kept for safety.")
                else:
                    if not self.fh.safe_delete(file_path, secure=True):
                        print_warning("Could not securely delete original.")
                print_success(f"{_('encrypted_success')}: {out_path}")
                return True
            print_error(_("error"))
            return False
        except Exception as e:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except Exception:
                    pass
            print_error(f"{_('error')}: {e}")
            self.logger.log("error", f"Encryption failed: {file_path} - {e}")
            return False

    def decrypt_file(self, file_path, password, overwrite=False, output=None,
                     managed_key_id=None, managed_key_password=None, managed_key_root=None):
        self.logger.log("info", f"Decrypt start: {file_path}")
        if not file_path.endswith(".enc") and output is None:
            print_error(_("invalid_file"))
            return False
        if not os.path.exists(file_path):
            print_error(_("file_not_found"))
            return False
        try:
            self.crypto.inspect_metadata(file_path)
        except Exception:
            print_error(_("invalid_file"))
            return False
        if os.path.getsize(file_path) < len(MAGIC) + 1:
            print_error(_("invalid_file"))
            return False
        out_path = self._resolve_output_path(file_path, output, decrypt=True)
        if os.path.exists(out_path) and not overwrite and not Settings.AUTO_YES:
            ans = input(f"{_('warning')}: {out_path} exists. Overwrite? (y/n): ")
            if ans.lower() != "y":
                print_info(_("cancel"))
                return False
        tmp = self.fh.get_temp_path(file_path)
        ms = None
        if managed_key_id:
            if managed_key_password is None:
                print_error(_("enter_password"))
                return False
            try:
                ms = self.load_managed_key_session(managed_key_id, managed_key_password, root_hint=managed_key_root, wait=True)
            except Exception as e:
                print_error(str(e))
                return False
        try:
            with open(file_path, "rb") as src, open(tmp, "wb") as dst:
                self.crypto.decrypt_stream(src, dst, password, raw_key=ms.raw_key if ms else None,
                                           managed_record=ms.record if ms else None)
            if self.fh.safe_move(tmp, out_path, overwrite=True):
                if self.fh.safe_delete(file_path, secure=True):
                    print_success(f"{_('decrypted_success')}: {out_path}")
                    return True
            print_error(_("error"))
            return False
        except ValueError as e:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except Exception:
                    pass
            print_error(str(e))
            self.logger.log("error", f"Decryption failed: {file_path} - {e}")
            return False
        except Exception as e:
            if os.path.exists(tmp):
                try:
                    os.unlink(tmp)
                except Exception:
                    pass
            print_error(f"{_('error')}: {e}")
            self.logger.log("error", f"Decryption failed: {file_path} - {e}")
            return False

    def verify_file(self, file_path, password):
        self.logger.log("info", f"Verify: {file_path}")
        try:
            if not os.path.exists(file_path):
                print_error(_("file_not_found"))
                return False
            _, meta = self.crypto.inspect_metadata(file_path)
            if meta.get("mode") != "password":
                print_error(_("access_denied"))
                return False
            ok = self.crypto.verify_password(file_path, password)
            if ok:
                print_success(_("verification_passed"))
            else:
                print_error(_("verification_failed"))
            return ok
        except Exception as e:
            print_error(f"{_('error')}: {e}")
            return False

    def change_password(self, file_path, old_pwd, new_pwd, overwrite=True):
        self.logger.log("info", f"Change password: {file_path}")
        if not self.verify_file(file_path, old_pwd):
            print_error(_("invalid_password"))
            return False
        with tempfile.NamedTemporaryFile(delete=False, suffix=".tmp") as t1:
            dec_path = t1.name
        with tempfile.NamedTemporaryFile(delete=False, suffix=".tmp") as t2:
            enc_path = t2.name
        try:
            os.chmod(dec_path, 0o600)
            os.chmod(enc_path, 0o600)
            with open(file_path, "rb") as src, open(dec_path, "wb") as dst:
                self.crypto.decrypt_stream(src, dst, old_pwd)
            with open(dec_path, "rb") as src2, open(enc_path, "wb") as dst2:
                self.crypto.encrypt_stream(src2, dst2, new_pwd)
            if self.fh.safe_move(enc_path, file_path, overwrite=overwrite):
                print_success(_("password_changed"))
                self.logger.log("info", f"Password changed: {file_path}")
                return True
            return False
        except Exception as e:
            print_error(f"{_('error')}: {e}")
            self.logger.log("error", f"Change password failed: {file_path} - {e}")
            return False
        finally:
            for path in (dec_path, enc_path):
                if os.path.exists(path):
                    try:
                        self.fh.safe_delete(path, secure=True)
                    except Exception:
                        try:
                            os.unlink(path)
                        except Exception:
                            pass

    def process_folder(self, folder_path, operation, password, new_password=None, recursive=True, threads=None,
                       managed_key_id=None, managed_key_password=None, managed_key_root=None):
        if operation == "decrypt":
            files = self.fh.get_files_recursive(folder_path, "*.enc", recursive=recursive)
        elif operation in ("change_password", "verify"):
            files = self.fh.get_files_recursive(folder_path, "*.enc", recursive=recursive)
        elif operation == "encrypt":
            files = self.fh.get_files_recursive(folder_path, "*", exclude_pattern=".enc", recursive=recursive)
        else:
            return 0, 0
        if not files:
            print_warning(_("folder_not_found"))
            return 0, 0
        total = len(files)
        ok = 0
        fail = 0
        threads = threads or Settings.THREADS
        if threads > 1 and total > 1:
            print_info(_("threads_info", threads))
            with ThreadPoolExecutor(max_workers=threads) as ex:
                futures = []
                for f in files:
                    if operation == "encrypt":
                        fut = ex.submit(self.encrypt_file, f, password, False, None, True, None,
                                        managed_key_id=managed_key_id,
                                        managed_key_password=managed_key_password,
                                        managed_key_root=managed_key_root)
                    elif operation == "decrypt":
                        fut = ex.submit(self.decrypt_file, f, password, True, None,
                                        managed_key_id=managed_key_id,
                                        managed_key_password=managed_key_password,
                                        managed_key_root=managed_key_root)
                    elif operation == "change_password":
                        fut = ex.submit(self.change_password, f, password, new_password, True)
                    else:
                        fut = ex.submit(self.verify_file, f, password)
                    futures.append((f, fut))
                for idx, (f, fut) in enumerate(futures, 1):
                    print_info(_("processing_file", idx, total, os.path.basename(f)))
                    try:
                        if fut.result():
                            ok += 1
                        else:
                            fail += 1
                    except Exception:
                        fail += 1
        else:
            for idx, f in enumerate(files, 1):
                print_info(_("processing_file", idx, total, os.path.basename(f)))
                if operation == "encrypt":
                    res = self.encrypt_file(f, password, False, None, True, None,
                                            managed_key_id=managed_key_id,
                                            managed_key_password=managed_key_password,
                                            managed_key_root=managed_key_root)
                elif operation == "decrypt":
                    res = self.decrypt_file(f, password, True, None,
                                            managed_key_id=managed_key_id,
                                            managed_key_password=managed_key_password,
                                            managed_key_root=managed_key_root)
                elif operation == "change_password":
                    res = self.change_password(f, password, new_password, True)
                else:
                    res = self.verify_file(f, password)
                if res:
                    ok += 1
                else:
                    fail += 1
        return ok, fail


def parse_args():
    p = argparse.ArgumentParser(description=f"{APP_NAME} - Advanced File Encryption Tool",
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--version", action="store_true", help="Show version")
    p.add_argument("-e", "--encrypt", metavar="PATH")
    p.add_argument("-d", "--decrypt", metavar="PATH")
    p.add_argument("-c", "--change-password", metavar="PATH", dest="change_password")
    p.add_argument("-v", "--verify", metavar="PATH")
    # Password arguments removed for security; passwords must be entered interactively.
    p.add_argument("-o", "--output")
    p.add_argument("-r", "--recursive", action="store_true")
    p.add_argument("-t", "--threads", type=int, default=4, help="1-8")
    p.add_argument("-y", "--yes", action="store_true")
    p.add_argument("--lang", choices=["auto", "en", "ru"])
    p.add_argument("--settings-file", default="securblack_settings.json")
    p.add_argument("--config-file", default="securblack_config.json")
    p.add_argument("--create-key", action="store_true")
    p.add_argument("--list-keys", action="store_true")
    p.add_argument("--encrypt-with-key", metavar="PATH")
    p.add_argument("--decrypt-with-key", metavar="PATH")
    p.add_argument("--key-id")
    p.add_argument("--key-label")
    p.add_argument("--key-root")
    # Removed --key-passphrase
    p.add_argument("--allow-target", action="append", default=[])
    p.add_argument("--notes")
    return p.parse_args()

def _get_pwd_or_ask(prompt, confirm=False):
    # Always prompts interactively; no command-line password accepted
    return get_password_input(prompt, confirm=confirm)

def _get_key_pass_or_ask():
    return get_password_input(_("key_passphrase_prompt") + ": ", confirm=True)

def cli_main():
    args = parse_args()
    if args.version:
        print(APP_FULL_NAME)
        return 0
    Settings.load(args.settings_file)
    if args.lang:
        I18N().set_language(Language(args.lang))
        Settings.LANGUAGE = args.lang
        Settings.save(args.settings_file)
    if not Settings.EULA_ACCEPTED:
        print(f"{Colors.BOLD}{Colors.YELLOW}{_('eula_title')}{Colors.RESET}\n")
        print(_("eula_intro"))
        print()
        print(f"{Colors.CYAN}{_('eula_link')}{Colors.RESET} {EULA_URL}")
        print()
        try:
            choice = input(f"{Colors.CYAN}{_('yes')}/{_('no')} (Y/N): {Colors.RESET}").strip().upper()
        except (EOFError, KeyboardInterrupt):
            print_error(_("eula_declined"))
            return 1
        if choice == "Y":
            Settings.EULA_ACCEPTED = True
            Settings.save()
            print_success(_("eula_accepted_message"))
        else:
            print_error(_("eula_declined"))
            return 1
    Settings.AUTO_YES = args.yes
    Settings.THREADS = max(1, min(8, args.threads))
    config = EncryptionConfig.load(args.config_file)
    enc = FileEncryptor(config=config, settings=Settings)
    if args.create_key:
        root = args.key_root or input(_("drive_root_prompt") + ": ").strip()
        if not root:
            print_error(_("error_invalid_choice"))
            return 1
        label = args.key_label or input(_("key_label_prompt") + ": ").strip() or "managed-key"
        pp = _get_key_pass_or_ask()
        if not pp:
            return 1
        rec = enc.create_managed_key(label, pp, root, allowed_targets=args.allow_target, notes=args.notes or "")
        print_success(_("key_created", rec.key_id))
        return 0
    if args.list_keys:
        records = enc.kv.list_records(args.key_root)
        if not records:
            print_warning(_("no_keys_found"))
        else:
            for root, rec, path in records:
                print(f"- {rec.key_id} | {rec.label} | root={root} | allowed={enc.kv.describe_targets(rec.allowed_targets)}")
        return 0
    if args.encrypt_with_key:
        path = args.encrypt_with_key
        if not args.key_id:
            print_error("Missing --key-id")
            return 1
        pp = _get_key_pass_or_ask()
        if not pp:
            return 1
        if os.path.isdir(path):
            ok, fail = enc.process_folder(path, "encrypt", SecureString(""), recursive=args.recursive,
                                          threads=Settings.THREADS, managed_key_id=args.key_id,
                                          managed_key_password=pp, managed_key_root=args.key_root)
            print_success(f"{_('encrypted_success')}: {ok}/{ok+fail}")
        else:
            if not enc.encrypt_file(path, SecureString(""), output=args.output, overwrite=args.yes,
                                    managed_key_id=args.key_id, managed_key_password=pp, managed_key_root=args.key_root):
                return 1
        return 0
    if args.decrypt_with_key:
        path = args.decrypt_with_key
        if not args.key_id:
            print_error("Missing --key-id")
            return 1
        pp = _get_key_pass_or_ask()
        if not pp:
            return 1
        if os.path.isdir(path):
            ok, fail = enc.process_folder(path, "decrypt", SecureString(""), recursive=args.recursive,
                                          threads=Settings.THREADS, managed_key_id=args.key_id,
                                          managed_key_password=pp, managed_key_root=args.key_root)
            print_success(f"{_('decrypted_success')}: {ok}/{ok+fail}")
        else:
            if not enc.decrypt_file(path, SecureString(""), overwrite=args.yes, output=args.output,
                                    managed_key_id=args.key_id, managed_key_password=pp, managed_key_root=args.key_root):
                return 1
        return 0
    if args.encrypt:
        path = args.encrypt
        pwd = _get_pwd_or_ask(_("enter_password") + ": ", confirm=True)
        if not pwd:
            return 1
        valid, msg = enc.validate_password(pwd.get())
        if not valid:
            print_error(msg)
            return 1
        if os.path.isdir(path):
            ok, fail = enc.process_folder(path, "encrypt", pwd, recursive=args.recursive, threads=Settings.THREADS)
            print_success(f"{_('encrypted_success')}: {ok}/{ok+fail}")
        else:
            if not enc.encrypt_file(path, pwd, output=args.output, overwrite=args.yes):
                return 1
        return 0
    if args.decrypt:
        path = args.decrypt
        pwd = _get_pwd_or_ask(_("enter_password") + ": ")
        if not pwd:
            return 1
        if os.path.isdir(path):
            ok, fail = enc.process_folder(path, "decrypt", pwd, recursive=args.recursive, threads=Settings.THREADS)
            print_success(f"{_('decrypted_success')}: {ok}/{ok+fail}")
        else:
            if not enc.decrypt_file(path, pwd, overwrite=args.yes, output=args.output):
                return 1
        return 0
    if args.change_password:
        path = args.change_password
        old_pwd = _get_pwd_or_ask(_("current_password") + ": ")
        if not old_pwd:
            return 1
        new_pwd = get_password_input(_("enter_new_password") + ": ", confirm=True)
        if not new_pwd:
            return 1
        if os.path.isdir(path):
            ok, fail = enc.process_folder(path, "change_password", old_pwd, new_pwd, recursive=args.recursive, threads=Settings.THREADS)
            print_success(f"{_('password_changed')}: {ok}/{ok+fail}")
        else:
            if not enc.change_password(path, old_pwd, new_pwd, overwrite=True):
                return 1
        return 0
    if args.verify:
        path = args.verify
        pwd = _get_pwd_or_ask(_("enter_password") + ": ")
        if not pwd:
            return 1
        if os.path.isdir(path):
            ok, fail = enc.process_folder(path, "verify", pwd, recursive=args.recursive, threads=Settings.THREADS)
            print_success(f"{_('verification_passed')}: {ok}/{ok+fail}")
        else:
            if not enc.verify_file(path, pwd):
                return 1
        return 0
    return 0


class UI:
    def __init__(self):
        self.enc = None
        setup_readline()

    def print_banner(self):
        print(f"""
{Colors.BOLD}{Colors.MAGENTA}
╔═══════════════════════════════════════════╗
║          {APP_FULL_NAME:<31}║
╚═══════════════════════════════════════════╝
{Colors.RESET}
""")

    def show_update_reminder(self):
        print(f"{Colors.GRAY}{_('update_reminder', GITHUB_MAIN)}{Colors.RESET}")

    def show_eula(self):
        if Settings.EULA_ACCEPTED:
            return True
        clear_screen()
        self.print_banner()
        print(f"{Colors.BOLD}{Colors.YELLOW}{_('eula_title')}{Colors.RESET}\n")
        print(_("eula_intro"))
        print()
        print(f"{Colors.CYAN}{_('eula_link')}{Colors.RESET} {EULA_URL}")
        print()
        while True:
            ans = input(f"{Colors.CYAN}{_('yes')}/{_('no')} (Y/N): {Colors.RESET}").strip().upper()
            if ans == "Y":
                Settings.EULA_ACCEPTED = True
                Settings.save()
                print_success(_("eula_accepted_message"))
                return True
            elif ans == "N":
                print_error(_("eula_declined"))
                return False
            print_error(_("error_invalid_choice"))

    def main_menu(self):
        self.enc = FileEncryptor()
        while True:
            if not Settings.EULA_ACCEPTED:
                if not self.show_eula():
                    sys.exit(0)
            clear_screen()
            self.print_banner()
            self.show_update_reminder()
            print(f"{Colors.BOLD}{Colors.CYAN}{_('main_menu')}{Colors.RESET}\n")
            print(f"1. {_('file_operations')}")
            print(f"2. {_('folder_operations')}")
            print(f"3. {_('encryption_settings')}")
            print(f"4. {_('security_settings')}")
            print(f"5. {_('language')}")
            print(f"6. {_('about')}")
            print(f"7. {_('key_vault')}")
            print(f"8. {_('exit')}\n")
            ch = input(f"{Colors.YELLOW}{_('choose_action')} (1-8): {Colors.RESET}").strip()
            if ch == "1":
                self.file_menu()
            elif ch == "2":
                self.folder_menu()
            elif ch == "3":
                self.settings_menu()
            elif ch == "4":
                self.security_settings()
            elif ch == "5":
                self.language_menu()
            elif ch == "6":
                self.about()
            elif ch == "7":
                self.key_vault_menu()
            elif ch == "8":
                print_success(_("exit"))
                return
            else:
                print_error(_("error_invalid_choice"))
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")

    def _encryptor(self):
        if self.enc is None:
            self.enc = FileEncryptor()
        return self.enc

    def file_menu(self):
        e = self._encryptor()
        while True:
            clear_screen()
            self.print_banner()
            print(f"{Colors.BOLD}{Colors.CYAN}{_('file_operations')}{Colors.RESET}\n")
            print(f"1. {_('encrypt_file')}")
            print(f"2. {_('decrypt_file')}")
            print(f"3. {_('change_password')}")
            print(f"4. {_('verify_file')}")
            print(f"5. {_('back')}\n")
            ch = input(f"{Colors.YELLOW}{_('choose_action')} (1-5): {Colors.RESET}").strip()
            if ch == "1":
                path = input(f"{Colors.CYAN}{_('file_path')}: {Colors.RESET}").strip()
                if not os.path.exists(path):
                    print_error(_("file_not_found"))
                else:
                    pwd = get_password_input(f"{Colors.CYAN}{_('enter_password')}: ", confirm=True)
                    if pwd:
                        valid, msg = e.validate_password(pwd.get())
                        if not valid:
                            print_error(msg)
                        else:
                            e.encrypt_file(path, pwd)
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")
            elif ch == "2":
                path = input(f"{Colors.CYAN}{_('encrypted_file_path')}: {Colors.RESET}").strip()
                if not os.path.exists(path):
                    print_error(_("file_not_found"))
                else:
                    pwd = get_password_input(f"{Colors.CYAN}{_('enter_password')}: ")
                    if pwd:
                        e.decrypt_file(path, pwd)
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")
            elif ch == "3":
                path = input(f"{Colors.CYAN}{_('encrypted_file_path')}: {Colors.RESET}").strip()
                if not os.path.exists(path):
                    print_error(_("file_not_found"))
                else:
                    old = get_password_input(f"{Colors.CYAN}{_('current_password')}: ")
                    if old:
                        new = get_password_input(f"{Colors.CYAN}{_('enter_new_password')}: ", confirm=True)
                        if new:
                            valid, msg = e.validate_password(new.get())
                            if not valid:
                                print_error(msg)
                            else:
                                e.change_password(path, old, new)
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")
            elif ch == "4":
                path = input(f"{Colors.CYAN}{_('encrypted_file_path')}: {Colors.RESET}").strip()
                if not os.path.exists(path):
                    print_error(_("file_not_found"))
                else:
                    pwd = get_password_input(f"{Colors.CYAN}{_('enter_password')}: ")
                    if pwd:
                        e.verify_file(path, pwd)
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")
            elif ch == "5":
                return
            else:
                print_error(_("error_invalid_choice"))
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")

    def folder_menu(self):
        e = self._encryptor()
        while True:
            clear_screen()
            self.print_banner()
            print(f"{Colors.BOLD}{Colors.CYAN}{_('folder_operations')}{Colors.RESET}\n")
            print(f"1. {_('encrypt_folder')}")
            print(f"2. {_('decrypt_folder')}")
            print(f"3. {_('change_password_folder')}")
            print(f"4. {_('verify_folder')}")
            print(f"5. {_('back')}\n")
            ch = input(f"{Colors.YELLOW}{_('choose_action')} (1-5): {Colors.RESET}").strip()
            if ch == "1":
                fld = input(f"{Colors.CYAN}{_('folder_path')}: {Colors.RESET}").strip()
                if not os.path.isdir(fld):
                    print_error(_("folder_not_found"))
                else:
                    rec = input(f"{Colors.CYAN}{_('processing_recursively')}: {Colors.RESET}").strip().lower() == "y"
                    try:
                        t = input(f"{Colors.CYAN}{_('threads_prompt')} [{Settings.THREADS}]: {Colors.RESET}").strip()
                        th = int(t) if t else Settings.THREADS
                        th = max(1, min(8, th))
                    except Exception:
                        th = Settings.THREADS
                    pwd = get_password_input(f"{Colors.CYAN}{_('enter_password')}: ", confirm=True)
                    if pwd:
                        valid, msg = e.validate_password(pwd.get())
                        if not valid:
                            print_error(msg)
                        else:
                            ok, fail = e.process_folder(fld, "encrypt", pwd, recursive=rec, threads=th)
                            print_success(f"{_('encrypted_success')}: {ok}/{ok+fail}")
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")
            elif ch == "2":
                fld = input(f"{Colors.CYAN}{_('folder_path')}: {Colors.RESET}").strip()
                if not os.path.isdir(fld):
                    print_error(_("folder_not_found"))
                else:
                    rec = input(f"{Colors.CYAN}{_('processing_recursively')}: {Colors.RESET}").strip().lower() == "y"
                    try:
                        t = input(f"{Colors.CYAN}{_('threads_prompt')} [{Settings.THREADS}]: {Colors.RESET}").strip()
                        th = int(t) if t else Settings.THREADS
                        th = max(1, min(8, th))
                    except Exception:
                        th = Settings.THREADS
                    pwd = get_password_input(f"{Colors.CYAN}{_('enter_password')}: ")
                    if pwd:
                        ok, fail = e.process_folder(fld, "decrypt", pwd, recursive=rec, threads=th)
                        print_success(f"{_('decrypted_success')}: {ok}/{ok+fail}")
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")
            elif ch == "3":
                fld = input(f"{Colors.CYAN}{_('folder_path')}: {Colors.RESET}").strip()
                if not os.path.isdir(fld):
                    print_error(_("folder_not_found"))
                else:
                    rec = input(f"{Colors.CYAN}{_('processing_recursively')}: {Colors.RESET}").strip().lower() == "y"
                    try:
                        t = input(f"{Colors.CYAN}{_('threads_prompt')} [{Settings.THREADS}]: {Colors.RESET}").strip()
                        th = int(t) if t else Settings.THREADS
                        th = max(1, min(8, th))
                    except Exception:
                        th = Settings.THREADS
                    old = get_password_input(f"{Colors.CYAN}{_('current_password')}: ")
                    if old:
                        new = get_password_input(f"{Colors.CYAN}{_('enter_new_password')}: ", confirm=True)
                        if new:
                            valid, msg = e.validate_password(new.get())
                            if not valid:
                                print_error(msg)
                            else:
                                ok, fail = e.process_folder(fld, "change_password", old, new, recursive=rec, threads=th)
                                print_success(f"{_('password_changed')}: {ok}/{ok+fail}")
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")
            elif ch == "4":
                fld = input(f"{Colors.CYAN}{_('folder_path')}: {Colors.RESET}").strip()
                if not os.path.isdir(fld):
                    print_error(_("folder_not_found"))
                else:
                    rec = input(f"{Colors.CYAN}{_('processing_recursively')}: {Colors.RESET}").strip().lower() == "y"
                    try:
                        t = input(f"{Colors.CYAN}{_('threads_prompt')} [{Settings.THREADS}]: {Colors.RESET}").strip()
                        th = int(t) if t else Settings.THREADS
                        th = max(1, min(8, th))
                    except Exception:
                        th = Settings.THREADS
                    pwd = get_password_input(f"{Colors.CYAN}{_('enter_password')}: ")
                    if pwd:
                        ok, fail = e.process_folder(fld, "verify", pwd, recursive=rec, threads=th)
                        print_success(f"{_('verification_passed')}: {ok}/{ok+fail}")
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")
            elif ch == "5":
                return
            else:
                print_error(_("error_invalid_choice"))
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")

    def settings_menu(self):
        e = self._encryptor()
        clear_screen()
        self.print_banner()
        print(f"{Colors.BOLD}{Colors.CYAN}{_('encryption_settings')}{Colors.RESET}\n")
        print(f"{Colors.BOLD}{_('current_settings')}:{Colors.RESET}")
        print(f"  • {_('algorithm')}: {e.config.algorithm}")
        print(f"  • {_('iterations')}: {e.config.iterations:,}")
        print(f"  • {_('min_password_length')}: {e.config.min_password_length}")
        print(f"  • {_('max_file_size')}: {e.config.max_file_size_gb} GB")
        print(f"  • {_('key_size')}: {e.config.key_size} bytes")
        print(f"  • {_('salt_size')}: {e.config.salt_size} bytes")
        print(f"  • {_('nonce_size')}: {e.config.nonce_size} bytes\n")
        print(f"1. {_('min_password_length')}")
        print(f"2. {_('iterations')}")
        print(f"3. {_('max_file_size')}")
        print(f"4. {_('threads')}")
        print(f"5. {_('save_settings')}")
        print(f"6. {_('reset_settings')}")
        print(f"7. {_('back')}\n")
        ch = input(f"{Colors.YELLOW}{_('choose_action')} (1-7): {Colors.RESET}").strip()
        try:
            if ch == "1":
                v = int(input(f"{Colors.CYAN}{_('min_password_length')} (8-32): {Colors.RESET}").strip())
                if 8 <= v <= 32:
                    e.config.min_password_length = v
                    e.config.save()
                    print_success(_("saved"))
                else:
                    print_error(_("error_invalid_number"))
            elif ch == "2":
                v = int(input(f"{Colors.CYAN}{_('iterations')} (100000-2000000): {Colors.RESET}").strip())
                if 100000 <= v <= 2000000:
                    e.config.iterations = v
                    e.config.save()
                    print_success(_("saved"))
                else:
                    print_error(_("error_invalid_number"))
            elif ch == "3":
                v = int(input(f"{Colors.CYAN}{_('max_file_size')} (1-100): {Colors.RESET}").strip())
                if 1 <= v <= 100:
                    e.config.max_file_size_gb = v
                    e.config.save()
                    print_success(_("saved"))
                else:
                    print_error(_("error_invalid_number"))
            elif ch == "4":
                v = int(input(f"{Colors.CYAN}{_('threads_prompt')} (1-8): {Colors.RESET}").strip())
                if 1 <= v <= 8:
                    Settings.THREADS = v
                    Settings.save()
                    print_success(_("saved"))
                else:
                    print_error(_("error_invalid_number"))
            elif ch == "5":
                e.config.save()
                print_success(_("save_settings"))
            elif ch == "6":
                e.config = EncryptionConfig()
                e.config.save()
                print_success(_("reset_settings"))
            elif ch == "7":
                return
            else:
                print_error(_("error_invalid_choice"))
        except Exception as ex:
            print_error(f"{_('error')}: {ex}")
        input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")

    def security_settings(self):
        while True:
            clear_screen()
            self.print_banner()
            print(f"{Colors.BOLD}{Colors.CYAN}{_('security_settings')}{Colors.RESET}\n")
            print(f"{Colors.BOLD}{_('current_settings')}:{Colors.RESET}")
            logs = f"{Colors.GREEN}{_('logging_enabled')}{Colors.RESET}" if Settings.ENABLE_LOGGING else f"{Colors.RED}{_('logging_disabled')}{Colors.RESET}"
            tmp = f"{Colors.GREEN}{_('temp_enabled')}{Colors.RESET}" if Settings.KEEP_TEMP_FILES else f"{Colors.RED}{_('temp_disabled')}{Colors.RESET}"
            eula = f"{Colors.GREEN}{_('eula_accepted')}{Colors.RESET}" if Settings.EULA_ACCEPTED else f"{Colors.RED}{_('eula_not_accepted')}{Colors.RESET}"
            pmode = (f"{Colors.GREEN}{_('password_visible')}{Colors.RESET}" if Settings.SHOW_PASSWORD
                     else f"{Colors.YELLOW}{_('password_stars')}{Colors.RESET}" if Settings.SHOW_PASSWORD_STARS
                     else f"{Colors.RED}{_('password_hidden')}{Colors.RESET}")
            ccnt = f"{Colors.GREEN}{_('char_counter_enabled')}{Colors.RESET}" if Settings.SHOW_CHAR_COUNT else f"{Colors.RED}{_('char_counter_disabled')}{Colors.RESET}"
            print(f"  1. {_('logging')}: {logs}")
            print(f"  2. {_('temp_files')}: {tmp}")
            print(f"  3. {_('password_mode')}: {pmode}")
            print(f"  4. {_('char_counter')}: {ccnt}")
            print(f"  5. {_('eula')}: {eula}")
            print(f"  6. {_('security_info')}")
            print(f"  7. {_('reset_settings')}")
            print(f"  8. {_('back')}\n")
            ch = input(f"{Colors.YELLOW}{_('choose_action')} (1-8): {Colors.RESET}").strip()
            if ch == "1":
                Settings.ENABLE_LOGGING = not Settings.ENABLE_LOGGING
                Settings.save()
                self.enc = FileEncryptor(self._encryptor().config)
                print_success(_("logging_enabled") if Settings.ENABLE_LOGGING else _("logging_disabled"))
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")
            elif ch == "2":
                Settings.KEEP_TEMP_FILES = not Settings.KEEP_TEMP_FILES
                if Settings.KEEP_TEMP_FILES:
                    os.makedirs(Settings.TEMP_FILES_DIR, exist_ok=True)
                Settings.save()
                print_success(_("temp_enabled") if Settings.KEEP_TEMP_FILES else _("temp_disabled"))
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")
            elif ch == "3":
                print()
                print(f"1. {_('password_visible')}")
                print(f"2. {_('password_stars')}")
                print(f"3. {_('password_hidden')}")
                m = input(f"\n{Colors.CYAN}{_('choose_action')} (1-3): {Colors.RESET}").strip()
                if m == "1":
                    Settings.SHOW_PASSWORD, Settings.SHOW_PASSWORD_STARS = True, False
                elif m == "2":
                    Settings.SHOW_PASSWORD, Settings.SHOW_PASSWORD_STARS = False, True
                elif m == "3":
                    Settings.SHOW_PASSWORD, Settings.SHOW_PASSWORD_STARS = False, False
                else:
                    print_error(_("error_invalid_choice"))
                Settings.save()
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")
            elif ch == "4":
                Settings.SHOW_CHAR_COUNT = not Settings.SHOW_CHAR_COUNT
                Settings.save()
                print_success(_("char_counter_enabled") if Settings.SHOW_CHAR_COUNT else _("char_counter_disabled"))
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")
            elif ch == "5":
                if Settings.EULA_ACCEPTED:
                    ans = input(f"{Colors.YELLOW}{_('reset_eula_prompt')}{Colors.RESET}").strip().lower()
                    if ans == "y":
                        Settings.EULA_ACCEPTED = False
                        Settings.save()
                        print_success(_("eula_not_accepted"))
                        if not self.show_eula():
                            pass
                else:
                    self.show_eula()
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")
            elif ch == "6":
                self.security_info()
            elif ch == "7":
                ans = input(f"{Colors.RED}{_('reset_all_settings')}{Colors.RESET}").strip().lower()
                if ans == "y":
                    Settings.SHOW_PASSWORD = False
                    Settings.SHOW_PASSWORD_STARS = True
                    Settings.SHOW_CHAR_COUNT = True
                    Settings.KEEP_TEMP_FILES = False
                    Settings.ENABLE_LOGGING = False
                    Settings.THREADS = 4
                    Settings.AUTO_YES = False
                    Settings.EULA_ACCEPTED = False
                    Settings.save()
                    print_success(_("reset_settings"))
                    if not self.show_eula():
                        pass
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")
            elif ch == "8":
                return
            else:
                print_error(_("error_invalid_choice"))
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")

    def security_info(self):
        clear_screen()
        self.print_banner()
        print(f"\n{Colors.BOLD}{Colors.GREEN}{_('security_info')}{Colors.RESET}\n")
        print("Логирование:")
        print("  • Логи хранятся локально")
        print("  • Конфиденциальные данные не логируются")
        print("\nВременные файлы:")
        print("  • Удаляются после операции")
        print("  • Можно оставить для отладки")
        print("\nРежим ввода пароля:")
        print("  • Видимый, скрытый звёздочками или полностью невидимый")
        print("  • Счётчик символов работает в любом режиме")
        print("\nШифрование:")
        print("  • AES-256-GCM, PBKDF2-HMAC-SHA256")
        input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")

    def about(self):
        clear_screen()
        self.print_banner()
        print(f"\n{Colors.BOLD}{Colors.CYAN}{_('about')}{Colors.RESET}\n")
        print(f"{Colors.BOLD}{APP_FULL_NAME}{Colors.RESET}")
        print(f"Developer: {DEVELOPER}")
        print("\nВозможности:")
        print("• Шифрование/расшифрование файлов и папок")
        print("• Смена пароля зашифрованных файлов")
        print("• Проверка целостности")
        print("• Многопоточность")
        print("• Потоковая обработка больших файлов")
        print("• Интерфейс на русском и английском")
        print(f"\nАлгоритм: AES-256-GCM, PBKDF2 итераций: {self._encryptor().config.iterations:,}")
        print("\n" + "=" * 50)
        print(f"{Colors.BOLD}{Colors.GREEN}Open Source Project{Colors.RESET}")
        print(f"{Colors.CYAN}GitHub:{Colors.RESET}         {GITHUB_MAIN}")
        print(f"{Colors.CYAN}Repository:{Colors.RESET}    {GITHUB_REPO}")
        print(f"{Colors.CYAN}Website:{Colors.RESET}       {OFFICIAL_WEBSITE}")
        print("=" * 50)
        input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")

    def language_menu(self):
        clear_screen()
        self.print_banner()
        print(f"{Colors.BOLD}{Colors.CYAN}{_('language')}{Colors.RESET}\n")
        cur = I18N().get_language()
        display = (_("language_auto") if cur == Language.AUTO
                   else _("language_en") if cur == Language.ENGLISH else _("language_ru"))
        print(f"{_('current_settings')}: {display}\n")
        print(f"1. {_('language_auto')}")
        print(f"2. {_('language_en')}")
        print(f"3. {_('language_ru')}")
        print(f"4. {_('back')}\n")
        ch = input(f"{Colors.YELLOW}{_('language_prompt')} (1-4): {Colors.RESET}").strip()
        if ch == "1":
            I18N().set_language(Language.AUTO)
            Settings.LANGUAGE = Language.AUTO.value
            Settings.save()
            print_success(_("language_changed", _("language_auto")))
        elif ch == "2":
            I18N().set_language(Language.ENGLISH)
            Settings.LANGUAGE = Language.ENGLISH.value
            Settings.save()
            print_success(_("language_changed", _("language_en")))
        elif ch == "3":
            I18N().set_language(Language.RUSSIAN)
            Settings.LANGUAGE = Language.RUSSIAN.value
            Settings.save()
            print_success(_("language_changed", _("language_ru")))
        elif ch == "4":
            return
        else:
            print_error(_("error_invalid_choice"))
        if not Settings.AUTO_YES:
            ans = input(f"\n{Colors.CYAN}{_('language_restart')}{Colors.RESET}").strip().lower()
            if ans == "y":
                os.execv(sys.executable, [sys.executable] + sys.argv)
        input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")

    def key_vault_menu(self):
        e = self._encryptor()
        while True:
            clear_screen()
            self.print_banner()
            print(f"{Colors.BOLD}{Colors.CYAN}{_('key_vault_menu')}{Colors.RESET}\n")
            print(f"1. {_('create_managed_key')}")
            print(f"2. {_('list_managed_keys')}")
            print(f"3. {_('encrypt_with_managed_key')}")
            print(f"4. {_('decrypt_with_managed_key')}")
            print(f"5. {_('back')}\n")
            ch = input(f"{Colors.YELLOW}{_('choose_action')} (1-5): {Colors.RESET}").strip()
            if ch == "1":
                root = input(f"{Colors.CYAN}{_('drive_root_prompt')}: {Colors.RESET}").strip()
                if not root:
                    print_error(_("error_invalid_choice"))
                else:
                    label = input(f"{Colors.CYAN}{_('key_label_prompt')}: {Colors.RESET}").strip() or "managed-key"
                    pp = get_password_input(f"{Colors.CYAN}{_('key_passphrase_prompt')}: ", confirm=True)
                    if pp:
                        targets_raw = input(f"{Colors.CYAN}{_('allowed_targets_prompt')}: {Colors.RESET}").strip()
                        targets = [t.strip() for t in targets_raw.split(",") if t.strip()] if targets_raw else []
                        notes = input(f"{Colors.CYAN}{_('notes_prompt')}: {Colors.RESET}").strip()
                        rec = e.create_managed_key(label, pp, root, allowed_targets=targets, notes=notes)
                        print_success(_("key_created", rec.key_id))
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")
            elif ch == "2":
                hint = input(f"{Colors.CYAN}{_('scan_root_prompt')}: {Colors.RESET}").strip() or None
                records = e.kv.list_records(hint)
                if not records:
                    print_warning(_("no_keys_found"))
                else:
                    for root, rec, path in records:
                        print(f"- id={rec.key_id}")
                        print(f"  label={rec.label}")
                        print(f"  root={root}")
                        print(f"  allowed={e.kv.describe_targets(rec.allowed_targets)}")
                        print(f"  file={path}")
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")
            elif ch == "3":
                path = input(f"{Colors.CYAN}{_('path_to_encrypt')}: {Colors.RESET}").strip()
                kid = input(f"{Colors.CYAN}{_('key_id')}: {Colors.RESET}").strip()
                kroot = input(f"{Colors.CYAN}{_('drive_root_optional')}: {Colors.RESET}").strip() or None
                kpp = get_password_input(f"{Colors.CYAN}{_('key_passphrase_prompt')}: ", confirm=False)
                if not (path and kid and kpp):
                    print_error(_("error_invalid_choice"))
                else:
                    if os.path.isdir(path):
                        ok, fail = e.process_folder(path, "encrypt", SecureString(""),
                                                    recursive=True, threads=Settings.THREADS,
                                                    managed_key_id=kid, managed_key_password=kpp,
                                                    managed_key_root=kroot)
                        print_success(f"{_('encrypted_success')}: {ok}/{ok+fail}")
                    else:
                        e.encrypt_file(path, SecureString(""),
                                       managed_key_id=kid, managed_key_password=kpp, managed_key_root=kroot)
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")
            elif ch == "4":
                path = input(f"{Colors.CYAN}{_('path_to_decrypt')}: {Colors.RESET}").strip()
                kid = input(f"{Colors.CYAN}{_('key_id')}: {Colors.RESET}").strip()
                kroot = input(f"{Colors.CYAN}{_('drive_root_optional')}: {Colors.RESET}").strip() or None
                kpp = get_password_input(f"{Colors.CYAN}{_('key_passphrase_prompt')}: ", confirm=False)
                if not (path and kid and kpp):
                    print_error(_("error_invalid_choice"))
                else:
                    if os.path.isdir(path):
                        ok, fail = e.process_folder(path, "decrypt", SecureString(""),
                                                    recursive=True, threads=Settings.THREADS,
                                                    managed_key_id=kid, managed_key_password=kpp,
                                                    managed_key_root=kroot)
                        print_success(f"{_('decrypted_success')}: {ok}/{ok+fail}")
                    else:
                        e.decrypt_file(path, SecureString(""),
                                       managed_key_id=kid, managed_key_password=kpp, managed_key_root=kroot)
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")
            elif ch == "5":
                return
            else:
                print_error(_("error_invalid_choice"))
                input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")


def check_deps():
    try:
        import cryptography
        return True
    except ImportError:
        print_error(_("error_missing_dependency", "cryptography"))
        print(_("error_install_crypto"))
        return False


def main():
    try:
        Settings.load()
        if not check_deps():
            sys.exit(1)

        Settings.LAUNCH_COUNT += 1
        Settings.save()

        if Settings.LAUNCH_COUNT == 10:
            msg = _("launch_10_message", app=APP_NAME, url=GITHUB_MAIN)
            print(f"\n{Colors.BOLD}{Colors.YELLOW}{msg}{Colors.RESET}\n")
            if sys.stdin.isatty() and not sys.argv[1:]:
                input(_("launch_10_prompt") or "Press Enter to continue...")
            else:
                time.sleep(0.5)

        args = sys.argv[1:]
        if args:
            code = cli_main()
            sys.exit(code)
        ui = UI()
        if not Settings.EULA_ACCEPTED and not ui.show_eula():
            sys.exit(0)
        ui.main_menu()
    except KeyboardInterrupt:
        print()
        print_warning(_("error_interrupted"))
    except Exception as e:
        print_error(_("error_critical", str(e)))
        try:
            input(f"\n{Colors.CYAN}{_('continue')}...{Colors.RESET}")
        except Exception:
            pass


if __name__ == "__main__":
    main()
