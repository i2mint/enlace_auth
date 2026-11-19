"""The passkey screens' copy and notification mails, in English and French.

Same shape as :mod:`enlace_auth.signup.texts`: ``t(lang, key, **fields)``, with
English as the fallback for a missing language or key.
"""

from __future__ import annotations

_TEXTS: dict[str, dict[str, str]] = {
    "en": {
        "card_title": "Passkeys",
        "card_body": (
            "A passkey signs you in, and confirms sensitive actions, with Face ID, "
            "Touch ID or your device's screen lock. It works on every app of this "
            "site. Your email stays the way back in if you lose your devices."
        ),
        "none_yet": "No passkey yet.",
        "name_label": "Name for a new passkey",
        "add": "Add a passkey on this device",
        "adding": "Waiting for your device…",
        "added": "Passkey added.",
        "remove": "Remove",
        "removed": "Passkey removed. Your other sessions were signed out.",
        "confirm_remove": "Remove the passkey “{name}”?",
        "reauth": "Sign in again",
        "cancelled": "Cancelled.",
        "unsupported": "This browser cannot use passkeys.",
        "required_note": (
            "This account must sign in with a passkey once it has {n} of them."
        ),
        "enforced_note": "This account signs in with a passkey only.",
        "created": "added",
        "last_used": "last used",
        "never_used": "never used",
        "synced": "synced",
        "signin": "Sign in with a passkey",
        "mail_added_subject": "A passkey was added to your account",
        "mail_added_body": (
            "A passkey named “{name}” was just added to your account {email} on "
            "{site}.\n\nIf this was not you, sign in, remove it from {site}/auth/"
            "account and change your password."
        ),
        "mail_removed_subject": "A passkey was removed from your account",
        "mail_removed_body": (
            "The passkey named “{name}” was just removed from your account {email} "
            "on {site}. Your other sessions were signed out.\n\nIf this was not "
            "you, sign in and change your password."
        ),
    },
    "fr": {
        "card_title": "Clés d'accès",
        "card_body": (
            "Une clé d'accès vous connecte, et confirme les actions sensibles, avec "
            "Face ID, Touch ID ou le verrouillage de votre appareil. Elle vaut pour "
            "toutes les applications de ce site. Votre adresse e-mail reste le "
            "moyen de revenir si vous perdez vos appareils."
        ),
        "none_yet": "Aucune clé d'accès pour l'instant.",
        "name_label": "Nom de la nouvelle clé",
        "add": "Ajouter une clé d'accès sur cet appareil",
        "adding": "En attente de votre appareil…",
        "added": "Clé d'accès ajoutée.",
        "remove": "Supprimer",
        "removed": "Clé supprimée. Vos autres sessions ont été fermées.",
        "confirm_remove": "Supprimer la clé « {name} » ?",
        "reauth": "Se reconnecter",
        "cancelled": "Annulé.",
        "unsupported": "Ce navigateur ne gère pas les clés d'accès.",
        "required_note": (
            "Ce compte devra se connecter par clé d'accès dès qu'il en aura {n}."
        ),
        "enforced_note": "Ce compte se connecte uniquement par clé d'accès.",
        "created": "ajoutée",
        "last_used": "dernière utilisation",
        "never_used": "jamais utilisée",
        "synced": "synchronisée",
        "signin": "Se connecter avec une clé d'accès",
        "mail_added_subject": "Une clé d'accès a été ajoutée à votre compte",
        "mail_added_body": (
            "Une clé d'accès nommée « {name} » vient d'être ajoutée à votre compte "
            "{email} sur {site}.\n\nSi ce n'est pas vous, connectez-vous, "
            "supprimez-la depuis {site}/auth/account et changez votre mot de passe."
        ),
        "mail_removed_subject": "Une clé d'accès a été supprimée de votre compte",
        "mail_removed_body": (
            "La clé d'accès nommée « {name} » vient d'être supprimée de votre "
            "compte {email} sur {site}. Vos autres sessions ont été fermées.\n\n"
            "Si ce n'est pas vous, connectez-vous et changez votre mot de passe."
        ),
    },
}


def t(lang: str, key: str, **fields) -> str:
    """The text *key* in *lang* (English when missing), with *fields* filled in.

    >>> t("fr", "remove"), t("de", "remove")
    ('Supprimer', 'Remove')
    """
    text = _TEXTS.get(lang, {}).get(key) or _TEXTS["en"][key]
    return text.format(**fields) if fields else text


def texts_for(lang: str, keys) -> dict[str, str]:
    """``{key: text}`` for the client script of a page."""
    return {k: t(lang, k) for k in keys}
