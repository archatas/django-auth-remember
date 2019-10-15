# -*- coding: UTF-8 -*-
from __future__ import unicode_literals
from datetime import timedelta
from django.utils.timezone import now as timezone_now
from django.utils.translation import ugettext_lazy as _
from django.db import models
from django.conf import settings as django_settings
from django.utils.encoding import python_2_unicode_compatible

from auth_remember import settings
from auth_remember.auth_utils import check_password


class RememberTokenManager(models.Manager):

    def get_by_string(self, token_string):
        """Return the token for the given token_string"""
        try:
            user_id, token_hash = token_string.split(':')
        except ValueError:
            return

        max_age = timezone_now() - timedelta(seconds=settings.COOKIE_AGE)
        try:
            for token in self.filter(created_initial__gte=max_age, user__pk=user_id):
                if check_password(token_hash, token.token_hash):
                    return token
        except ValueError:
            return

    def clean_remember_tokens(self):
        max_age = timezone_now() - timedelta(seconds=settings.COOKIE_AGE)
        return self.filter(created_initial__lte=max_age).delete()


@python_2_unicode_compatible
class RememberToken(models.Model):
    token_hash = models.CharField(_("Token Hash"), max_length=60, blank=False, primary_key=True)

    created = models.DateTimeField(_("Created"), editable=False, default=timezone_now)

    created_initial = models.DateTimeField(_("Created Initially"), editable=False, blank=False)

    user = models.ForeignKey(django_settings.AUTH_USER_MODEL, verbose_name=_("User"), related_name="remember_me_tokens")

    objects = RememberTokenManager()

    class Meta:
        verbose_name = _("Remember Token")
        verbose_name_plural = _("Remember Tokens")
        ordering = ("-created",)

    def __str__(self):
        return "{} - {:%Y-%m-%d %H:%M}".format(self.user, self.created)
