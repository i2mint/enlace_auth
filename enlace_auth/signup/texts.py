"""What the sign-up flow says, in English and French: page text and emails.

Plain dictionaries, one per language, so a translation is a reviewable diff and
a missing key falls back to English rather than raising. :func:`pick_lang`
chooses from the request's ``Accept-Language`` (or an explicit ``lang``).

>>> pick_lang("fr-FR,fr;q=0.9,en;q=0.8"), pick_lang("de, en;q=0.5"), pick_lang(None)
('fr', 'en', 'en')
>>> t("fr", "continue")
'Continuer avec mon e-mail'
"""

from __future__ import annotations

from typing import Optional

LANGS = ("en", "fr")

_EN = {
    "continue": "Continue with email",
    "email": "Email",
    "code": "6-digit code",
    "code_sent": "If this address can sign in here, we sent it a 6-digit code. It works for {minutes} minutes.",
    "verify": "Sign in",
    "other_address": "Use another address",
    "or_password": "Sign in with a password instead",
    "sending": "Sending…",
    "checking": "Checking…",
    "wrong_code": "That code is wrong or has expired. Check the latest email, or ask for a new code.",
    "too_many": "Too many attempts. Wait a while, then try again.",
    "signup_closed": "Sign-up is closed here. Ask the platform admin for an account.",
    "note_open": "New here? Enter your email to create an account. For people aged 15 and over.",
    "note_invite": "New here? Sign-up here is by invitation.",
    "note_closed": "No account? Accounts are created by the platform admin.",
    "accept": "By continuing you accept the {terms} and the {privacy}.",
    "accept_terms": "By continuing you accept the {terms}.",
    "accept_privacy": "See the {privacy}.",
    "terms": "terms of use",
    "privacy": "privacy notice",
    "provider": "Continue with {name}",
    "link_title": "Finish signing in",
    "link_body": "Press the button to finish signing in in this browser.",
    "link_bad": "This link is invalid, has expired, or was opened in another browser than the one that asked for it. Open it there, or type the code there.",
    "back": "Back to sign in",
    "delete_title": "Delete my account",
    "delete_body": "This deletes your account, your saved data in every app, and every share you are part of. It cannot be undone.",
    "delete_send": "Email me a confirmation code",
    "delete_confirm": "Delete my account for good",
    "delete_sent": "We sent a 6-digit code to {email}. Enter it to confirm.",
    "deleted": "Your account is deleted.",
    # emails
    "mail_code_subject": "{code} is your sign-in code",
    "mail_code_body": (
        "Your code to sign in to {site}:\n\n    {code}\n\n"
        "It works for {minutes} minutes, in the browser where you asked for "
        "it. You can also open this link in that browser:\n\n    {link}\n\n"
        "If you did not ask for this, ignore this email: nothing happens "
        "without the code."
    ),
    "mail_refused_subject": "About your sign-in request",
    "mail_refused_body": (
        "Someone asked to sign in to {site} with this address. There is no "
        "account for it, and sign-up there is by invitation only.\n\n"
        "If you expected an account, ask the person who runs the site. If you "
        "did not ask for this, ignore this email."
    ),
    "mail_delete_subject": "{code} confirms deleting your account",
    "mail_delete_body": (
        "Someone signed in to your account on {site} asked to delete it. Enter "
        "this code to confirm:\n\n    {code}\n\n"
        "It works for {minutes} minutes. If this was not you, ignore this "
        "email and change your password: your account stays as it is."
    ),
}

_FR = {
    "continue": "Continuer avec mon e-mail",
    "email": "E-mail",
    "code": "Code à 6 chiffres",
    "code_sent": "Si cette adresse peut se connecter ici, nous lui avons envoyé un code à 6 chiffres. Il est valable {minutes} minutes.",
    "verify": "Se connecter",
    "other_address": "Utiliser une autre adresse",
    "or_password": "Se connecter avec un mot de passe",
    "sending": "Envoi…",
    "checking": "Vérification…",
    "wrong_code": "Ce code est faux ou a expiré. Vérifiez le dernier e-mail reçu, ou demandez un nouveau code.",
    "too_many": "Trop de tentatives. Patientez un moment, puis réessayez.",
    "signup_closed": "Les inscriptions sont fermées ici. Demandez un compte à l'administrateur.",
    "note_open": "Nouveau ? Saisissez votre e-mail pour créer un compte. Réservé aux personnes de 15 ans et plus.",
    "note_invite": "Nouveau ? L'inscription se fait ici sur invitation.",
    "note_closed": "Pas de compte ? Les comptes sont créés par l'administrateur.",
    "accept": "En continuant, vous acceptez les {terms} et la {privacy}.",
    "accept_terms": "En continuant, vous acceptez les {terms}.",
    "accept_privacy": "Voir la {privacy}.",
    "terms": "conditions d'utilisation",
    "privacy": "politique de confidentialité",
    "provider": "Continuer avec {name}",
    "link_title": "Terminer la connexion",
    "link_body": "Appuyez sur le bouton pour terminer la connexion dans ce navigateur.",
    "link_bad": "Ce lien est invalide, a expiré, ou a été ouvert dans un autre navigateur que celui qui l'a demandé. Ouvrez-le dans ce navigateur, ou saisissez-y le code.",
    "back": "Retour à la connexion",
    "delete_title": "Supprimer mon compte",
    "delete_body": "Cela supprime votre compte, vos données enregistrées dans chaque application et tous les partages dont vous faites partie. C'est définitif.",
    "delete_send": "M'envoyer un code de confirmation",
    "delete_confirm": "Supprimer définitivement mon compte",
    "delete_sent": "Nous avons envoyé un code à 6 chiffres à {email}. Saisissez-le pour confirmer.",
    "deleted": "Votre compte est supprimé.",
    "mail_code_subject": "{code} est votre code de connexion",
    "mail_code_body": (
        "Votre code pour vous connecter à {site} :\n\n    {code}\n\n"
        "Il est valable {minutes} minutes, dans le navigateur où vous l'avez "
        "demandé. Vous pouvez aussi ouvrir ce lien dans ce navigateur :\n\n"
        "    {link}\n\n"
        "Si vous n'avez rien demandé, ignorez cet e-mail : rien ne se passe "
        "sans le code."
    ),
    "mail_refused_subject": "Votre demande de connexion",
    "mail_refused_body": (
        "Quelqu'un a demandé à se connecter à {site} avec cette adresse. Il "
        "n'existe pas de compte pour elle, et l'inscription s'y fait "
        "uniquement sur invitation.\n\n"
        "Si vous attendiez un compte, adressez-vous à la personne qui gère le "
        "site. Si vous n'avez rien demandé, ignorez cet e-mail."
    ),
    "mail_delete_subject": "{code} confirme la suppression de votre compte",
    "mail_delete_body": (
        "Une personne connectée à votre compte sur {site} a demandé sa "
        "suppression. Saisissez ce code pour confirmer :\n\n    {code}\n\n"
        "Il est valable {minutes} minutes. Si ce n'était pas vous, ignorez cet "
        "e-mail et changez votre mot de passe : votre compte reste intact."
    ),
}

_STRINGS = {"en": _EN, "fr": _FR}


def pick_lang(accept_language: Optional[str], *, explicit: Optional[str] = None) -> str:
    """The first supported language in *explicit*, else in ``Accept-Language``."""
    if explicit and explicit[:2].lower() in LANGS:
        return explicit[:2].lower()
    for part in (accept_language or "").split(","):
        tag = part.split(";", 1)[0].strip()[:2].lower()
        if tag in LANGS:
            return tag
    return "en"


def t(lang: str, key: str, **values: object) -> str:
    """The *key* string in *lang* (English when missing), formatted with *values*."""
    text = _STRINGS.get(lang, _EN).get(key) or _EN[key]
    return text.format(**values) if values else text


def code_email(
    lang: str, *, code: str, link: str, site: str, minutes: int
) -> tuple[str, str]:
    """``(subject, body)`` of the mail carrying a sign-in code."""
    v = dict(code=code, link=link, site=site, minutes=minutes)
    return t(lang, "mail_code_subject", **v), t(lang, "mail_code_body", **v)


def refused_email(lang: str, *, site: str) -> tuple[str, str]:
    """``(subject, body)`` of the mail to an address the policy does not admit."""
    return t(lang, "mail_refused_subject"), t(lang, "mail_refused_body", site=site)


def delete_email(lang: str, *, code: str, site: str, minutes: int) -> tuple[str, str]:
    """``(subject, body)`` of the mail confirming an account deletion."""
    v = dict(code=code, site=site, minutes=minutes)
    return t(lang, "mail_delete_subject", **v), t(lang, "mail_delete_body", **v)
