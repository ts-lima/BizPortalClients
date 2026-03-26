import getpass
import os
import sys

from django.contrib.auth.management import get_default_username
from django.contrib.auth.management.commands.createsuperuser import PASSWORD_FIELD, NotRunningInTTYException, Command as DjangoCreateSuperuserCommand
from django.contrib.auth.password_validation import validate_password
from django.core import exceptions
from django.core.management.base import CommandError
from django.db import IntegrityError, transaction
from django.utils.text import capfirst

from django_bizportal_client.settings import get_oidc_identity_model, get_setting


class Command(DjangoCreateSuperuserCommand):
    help = 'Used to create a superuser and its OIDC identity.'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.OIDCIdentity = get_oidc_identity_model()
        if self.OIDCIdentity is None:
            raise CommandError('OIDC identity model is not configured. Please set OIDC_IDENTITY_MODEL in your settings.')

    def add_arguments(self, parser):
        super().add_arguments(parser)
        parser.add_argument(
            '--issuer',
            help='Specifies the issuer for the superuser OIDC identity.',
        )
        parser.add_argument(
            '--subject',
            help='Specifies the subject for the superuser OIDC identity.',
        )

    def _get_default_issuer(self):
        issuer_url = get_setting('OIDC_ISSUER_URL', '')
        if not issuer_url:
            raise CommandError('OIDC issuer URL is not configured. Please set OIDC_ISSUER_URL in your settings or provide it interactively.')
        return f'{issuer_url}o'

    def _get_default_subject(self):
        return '1'

    def handle(self, *args, **options):
        username = options[self.UserModel.USERNAME_FIELD]
        database = options['database']
        user_data = {}
        verbose_field_name = self.username_field.verbose_name
        try:
            self.UserModel._meta.get_field(PASSWORD_FIELD)
        except exceptions.FieldDoesNotExist:
            pass
        else:
            user_data[PASSWORD_FIELD] = None

        try:
            if options['interactive']:
                fake_user_data = {}
                if hasattr(self.stdin, 'isatty') and not self.stdin.isatty():
                    raise NotRunningInTTYException
                default_username = get_default_username(database=database)
                if username:
                    error_msg = self._validate_username(
                        username, verbose_field_name, database
                    )
                    if error_msg:
                        self.stderr.write(error_msg)
                        username = None
                elif username == '':
                    raise CommandError(
                        '%s cannot be blank.' % capfirst(verbose_field_name)
                    )
                while username is None:
                    message = self._get_input_message(
                        self.username_field, default_username
                    )
                    username = self.get_input_data(
                        self.username_field, message, default_username
                    )
                    if username:
                        error_msg = self._validate_username(
                            username, verbose_field_name, database
                        )
                        if error_msg:
                            self.stderr.write(error_msg)
                            username = None
                            continue
                user_data[self.UserModel.USERNAME_FIELD] = username
                fake_user_data[self.UserModel.USERNAME_FIELD] = (
                    self.username_field.remote_field.model(username)
                    if self.username_field.remote_field
                    else username
                )

                for field_name in self.UserModel.REQUIRED_FIELDS:
                    field = self.UserModel._meta.get_field(field_name)
                    user_data[field_name] = options[field_name]
                    if user_data[field_name] is not None:
                        user_data[field_name] = field.clean(user_data[field_name], None)
                    while user_data[field_name] is None:
                        message = self._get_input_message(field)
                        input_value = self.get_input_data(field, message)
                        user_data[field_name] = input_value
                        if field.many_to_many and input_value:
                            if not input_value.strip():
                                user_data[field_name] = None
                                self.stderr.write('Error: This field cannot be blank.')
                                continue
                            user_data[field_name] = [
                                pk.strip() for pk in input_value.split(',')
                            ]

                    if not field.many_to_many:
                        fake_user_data[field_name] = user_data[field_name]
                    if field.many_to_one:
                        fake_user_data[field_name] = field.remote_field.model(
                            user_data[field_name]
                        )

                while PASSWORD_FIELD in user_data and user_data[PASSWORD_FIELD] is None:
                    password = getpass.getpass()
                    password2 = getpass.getpass('Password (again): ')
                    if password != password2:
                        self.stderr.write("Error: Your passwords didn't match.")
                        continue
                    if password.strip() == '':
                        self.stderr.write("Error: Blank passwords aren't allowed.")
                        continue
                    try:
                        validate_password(password2, self.UserModel(**fake_user_data))
                    except exceptions.ValidationError as err:
                        self.stderr.write('\n'.join(err.messages))
                        response = input(
                            'Bypass password validation and create user anyway? [y/N]: '
                        )
                        if response.lower() != 'y':
                            continue
                    user_data[PASSWORD_FIELD] = password

                issuer = self._get_interactive_oidc_value('issuer')
                subject = self._get_interactive_oidc_value('subject')
            else:
                if (
                    PASSWORD_FIELD in user_data
                    and 'DJANGO_SUPERUSER_PASSWORD' in os.environ
                ):
                    user_data[PASSWORD_FIELD] = os.environ['DJANGO_SUPERUSER_PASSWORD']
                if username is None:
                    username = os.environ.get(
                        'DJANGO_SUPERUSER_' + self.UserModel.USERNAME_FIELD.upper()
                    )
                if username is None:
                    raise CommandError(
                        'You must use --%s with --noinput.'
                        % self.UserModel.USERNAME_FIELD
                    )
                error_msg = self._validate_username(
                    username, verbose_field_name, database
                )
                if error_msg:
                    raise CommandError(error_msg)

                user_data[self.UserModel.USERNAME_FIELD] = username
                for field_name in self.UserModel.REQUIRED_FIELDS:
                    env_var = 'DJANGO_SUPERUSER_' + field_name.upper()
                    value = options[field_name] or os.environ.get(env_var)
                    field = self.UserModel._meta.get_field(field_name)
                    if not value:
                        if field.blank and (
                            options[field_name] == '' or os.environ.get(env_var) == ''
                        ):
                            continue
                        raise CommandError(
                            'You must use --%s with --noinput.' % field_name
                        )
                    user_data[field_name] = field.clean(value, None)
                    if field.many_to_many and isinstance(user_data[field_name], str):
                        user_data[field_name] = [
                            pk.strip() for pk in user_data[field_name].split(',')
                        ]

                issuer = self._get_non_interactive_oidc_value(options, 'issuer')
                subject = self._get_non_interactive_oidc_value(options, 'subject')

            self._validate_oidc_identity_uniqueness(
                issuer=issuer,
                subject=subject,
                database=database,
            )

            with transaction.atomic(using=database):
                user = self.UserModel._default_manager.db_manager(database).create_superuser(
                    **user_data
                )
                self.OIDCIdentity.objects.db_manager(database).create(
                    user=user,
                    issuer=issuer,
                    subject=subject,
                )

            if options['verbosity'] >= 1:
                self.stdout.write('Superuser created successfully.')
        except KeyboardInterrupt:
            self.stderr.write('\nOperation cancelled.')
            sys.exit(1)
        except exceptions.ValidationError as exc:
            raise CommandError('; '.join(exc.messages))
        except IntegrityError as exc:
            raise CommandError(str(exc)) from exc
        except NotRunningInTTYException:
            self.stdout.write(
                'Superuser creation skipped due to not running in a TTY. '
                'You can run `manage.py createsuperuser` in your project '
                'to create one manually.'
            )

    def _get_interactive_oidc_value(self, field_name):
        field = self.OIDCIdentity._meta.get_field(field_name)
        value = None
        while value is None:
            if field_name == 'issuer':
                default_value = self._get_default_issuer()
            elif field_name == 'subject':
                default_value = self._get_default_subject()
            else:
                default_value = None

            raw_value = input(self._get_oidc_input_message(field, default_value))
            if raw_value == '' and default_value is not None:
                raw_value = default_value
            value = self._clean_oidc_value(field_name, raw_value)
        return value

    def _get_non_interactive_oidc_value(self, options, field_name):
        env_var = f'DJANGO_SUPERUSER_{field_name.upper()}'
        value = options[field_name] or os.environ.get(env_var)
        if value is None:
            if field_name == 'issuer':
                value = self._get_default_issuer()
            elif field_name == 'subject':
                value = self._get_default_subject()
            else:
                raise CommandError(f'You must use --{field_name} with --noinput.')
        cleaned_value = self._clean_oidc_value(field_name, value)
        if cleaned_value is None:
            raise CommandError(f'{capfirst(field_name)} cannot be blank.')
        return cleaned_value

    def _clean_oidc_value(self, field_name, raw_value):
        field = self.OIDCIdentity._meta.get_field(field_name)
        if raw_value is None:
            return None
        value = raw_value.strip()
        if not value:
            self.stderr.write(f'Error: {capfirst(field_name)} cannot be blank.')
            return None
        try:
            return field.clean(value, None)
        except exceptions.ValidationError as exc:
            self.stderr.write('Error: %s' % '; '.join(exc.messages))
            return None

    def _get_oidc_input_message(self, field, default_value=None):
        if default_value is not None:
            return f'OIDC {capfirst(field.verbose_name)} [{default_value}]: '
        return f'OIDC {capfirst(field.verbose_name)}: '

    def _validate_oidc_identity_uniqueness(self, *, issuer, subject, database):
        exists = self.OIDCIdentity.objects.using(database).filter(
            issuer=issuer,
            subject=subject,
        ).exists()
        if exists:
            raise CommandError('Error: That issuer and subject combination is already taken.')


