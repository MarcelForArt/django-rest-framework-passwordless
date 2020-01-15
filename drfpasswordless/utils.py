import logging
import os
import requests
import mandrill
import hashlib
from django.contrib.auth import get_user_model
from django.core.exceptions import PermissionDenied
from django.core.mail import send_mail
from django.template import loader
from django.utils import timezone
from drfpasswordless.models import CallbackToken
from drfpasswordless.settings import api_settings


logger = logging.getLogger(__name__)
User = get_user_model()


def _send_mandrill_email_msg(recip, callback_token, user, template_name):
    """
    Create the template in Mailchimp then export to Mandrill. Ensure
    to add {{callback_token}} and {{first_name}} variables in the template
    and check after the export to Mailchimp that it hasn't corrupted these

    :param recip:
    :param callback_token:
    :param user:
    :param template_name:
    :return:
    """
    mandrill_client = mandrill.Mandrill(api_settings.PASSWORDLESS_MANDRILL_API_KEY)
    # Prepare message to send w/ dynamic content
    message = {'to': [{'email': recip, 'type': 'to'}], 'track_opens': True, 'track_clicks': True,
               'global_merge_vars': [{'content': callback_token, 'name': 'callback_token'},
                                     {'content': user.first_name, 'name': 'first_name'},
                                     {'content': api_settings.PASSWORDLESS_MARCEL_HOST, 'name': 'marcel_host'},
                                     {'content': api_settings.PASSWORDLESS_MAILCHIMP_UNSUB_LINK, 'name': 'redirect_unsub'},
                                     ]
               }
    result = mandrill_client.messages.send_template(template_name=template_name, template_content=[],
                                                    message=message, async=False, ip_pool='Main Pool')
    logger.info(result)


def _update_mailchimp_merge_fields(user, merge_field_dict):
    """
    Update the merge fields for this user on Mailchimp - we want to set the custom merge field
    MAGICTOKEN with the token we generated before we fire the campaign to that user, so the magic link
    will be generated correctly using ?token=*|MAGICTOKEN|*

    :param user:
    :param merge_field_dict:
    :return:
    """
    md5_email = hashlib.md5(user.email.encode('utf-8')).hexdigest()
    member_url = f'{api_settings.PASSWORDLESS_MAILCHIMP_BASE_URL}/lists/{api_settings.PASSWORDLESS_MAILCHIMP_SUBSCRIBE_LIST_ID}/members/{md5_email}'
    r = requests.put(member_url, json=merge_field_dict, auth=('anystring', api_settings.PASSWORDLESS_MAILCHIMP_API_KEY))
    r.raise_for_status()


def _send_mailchimp_email_msg(user, callback_token, campaign_trigger_url):
    """
    Set the MAGICTOKEN merge variable for this user on mailchimp.
    Trigger the automation

    :param user:
    :param callback_token:
    :param campaign_trigger_url: the mailchimp API 3.0 trigger url for automation of campaign
                                (send this email to specific user when that url endpoint is hit)
    :return:
    """
    # Update the merge field MAGICTOKEN on this Mailchimp user first
    _update_mailchimp_merge_fields(user, {"merge_fields": {"MAGICTOKEN": callback_token}})

    # Trigger the campaign by the automation API 3.0 endpoint for this user email
    response = requests.post(campaign_trigger_url,
                             json={'email_address': user.email},
                             auth=('anystring', api_settings.PASSWORDLESS_MAILCHIMP_API_KEY))
    response.raise_for_status()

    logger.info(response)


def authenticate_by_token(callback_token):
    try:
        token = CallbackToken.objects.get(key=callback_token, is_active=True)

        # Returning a user designates a successful authentication.
        token.user = User.objects.get(pk=token.user.pk)
        token.is_active = False  # Mark this token as used.
        token.save()

        return token.user

    except CallbackToken.DoesNotExist:
        logger.debug("drfpasswordless: Challenged with a callback token that doesn't exist.")
    except User.DoesNotExist:
        logger.debug("drfpasswordless: Authenticated user somehow doesn't exist.")
    except PermissionDenied:
        logger.debug("drfpasswordless: Permission denied while authenticating.")

    return None


def create_callback_token_for_user(user, token_type):

    token = None
    token_type = token_type.upper()

    if token_type == 'EMAIL':
        token = CallbackToken.objects.create(user=user,
                                             to_alias_type=token_type,
                                             to_alias=getattr(user, api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME))

    elif token_type == 'MOBILE':
        token = CallbackToken.objects.create(user=user,
                                             to_alias_type=token_type,
                                             to_alias=getattr(user, api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME))

    if token is not None:
        return token

    return None


def validate_token_age(callback_token):
    """
    Returns True if a given token is within the age expiration limit.
    """
    try:
        token = CallbackToken.objects.get(key=callback_token, is_active=True)
        seconds = (timezone.now() - token.created_at).total_seconds()
        token_expiry_time = api_settings.PASSWORDLESS_TOKEN_EXPIRE_TIME

        if seconds <= token_expiry_time:
            return True
        else:
            # Invalidate our token.
            token.is_active = False
            token.save()
            return False

    except CallbackToken.DoesNotExist:
        # No valid token.
        return False


def verify_user_alias(user, token):
    """
    Marks a user's contact point as verified depending on accepted token type.
    """
    if token.to_alias_type == 'EMAIL':
        if token.to_alias == getattr(user, api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME):
            setattr(user, api_settings.PASSWORDLESS_USER_EMAIL_VERIFIED_FIELD_NAME, True)
    elif token.to_alias_type == 'MOBILE':
        if token.to_alias == getattr(user, api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME):
            setattr(user, api_settings.PASSWORDLESS_USER_MOBILE_VERIFIED_FIELD_NAME, True)
    else:
        return False
    user.save()
    return True


def inject_template_context(context):
    """
    Injects additional context into email template.
    """
    for processor in api_settings.PASSWORDLESS_CONTEXT_PROCESSORS:
        context.update(processor())
    return context


def send_email_with_callback_token(user, email_token, **kwargs):
    """
    Sends a Email to user.email.

    Passes silently without sending in test environment
    """
    try:
        if api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS:
            # Make sure we have a sending address before sending.
            if api_settings.PASSWORDLESS_MANDRILL_API_KEY:
                # Go via Mandrill
                template_name = kwargs.get('template')
                if template_name:
                    _send_mandrill_email_msg(getattr(user, api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME),
                                             email_token.key, user, template_name)
                else:
                    raise Exception('Ensure PASSWORDLESS_TEMPLATE_CHOICES has been set')
            elif (api_settings.PASSWORDLESS_MAILCHIMP_API_KEY and api_settings.PASSWORDLESS_MAILCHIMP_BASE_URL and
                  api_settings.PASSWORDLESS_MAILCHIMP_SUBSCRIBE_LIST_ID):
                # Go via Mailchimp campaign
                campaign_trigger_url = kwargs.get('campaign_trigger_url')
                if campaign_trigger_url:
                    _send_mailchimp_email_msg(user, email_token.key, campaign_trigger_url)
                else:
                    raise Exception('Ensure to pass the campaign_trigger_url as kwarg')
            else:
                # Get email subject and message
                email_subject = kwargs.get('email_subject',
                                           api_settings.PASSWORDLESS_EMAIL_SUBJECT)
                email_plaintext = kwargs.get('email_plaintext',
                                             api_settings.PASSWORDLESS_EMAIL_PLAINTEXT_MESSAGE)
                email_html = kwargs.get('email_html',
                                        api_settings.PASSWORDLESS_EMAIL_TOKEN_HTML_TEMPLATE_NAME)

                # Inject context if user specifies.
                context = inject_template_context({'callback_token': email_token.key, })
                html_message = loader.render_to_string(email_html, context,)
                send_mail(
                    email_subject,
                    email_plaintext % email_token.key,
                    api_settings.PASSWORDLESS_EMAIL_NOREPLY_ADDRESS,
                    [getattr(user, api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME)],
                    fail_silently=False,
                    html_message=html_message,)

        else:
            logger.debug("Failed to send token email. Missing PASSWORDLESS_EMAIL_NOREPLY_ADDRESS.")
            return False
        return True

    except Exception as e:
        logger.debug("Failed to send token email to user: %d."
                     "Possibly no email on user object. Email entered was %s" %
                    (user.id, getattr(user, api_settings.PASSWORDLESS_USER_EMAIL_FIELD_NAME)))
        logger.debug(e)
        return False


def send_sms_with_callback_token(user, mobile_token, **kwargs):
    """
    Sends a SMS to user.mobile via Twilio.

    Passes silently without sending in test environment.
    """
    base_string = kwargs.get('mobile_message', api_settings.PASSWORDLESS_MOBILE_MESSAGE)

    try:

        if api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER:
            # We need a sending number to send properly
            if api_settings.PASSWORDLESS_TEST_SUPPRESSION is True:
                # we assume success to prevent spamming SMS during testing.
                return True

            from twilio.rest import Client
            twilio_client = Client(os.environ['TWILIO_ACCOUNT_SID'], os.environ['TWILIO_AUTH_TOKEN'])
            twilio_client.messages.create(
                body=base_string % mobile_token.key,
                to=getattr(user, api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME),
                from_=api_settings.PASSWORDLESS_MOBILE_NOREPLY_NUMBER
            )
            return True
        else:
            logger.debug("Failed to send token sms. Missing PASSWORDLESS_MOBILE_NOREPLY_NUMBER.")
            return False
    except ImportError:
        logger.debug("Couldn't import Twilio client. Is twilio installed?")
        return False
    except KeyError:
        logger.debug("Couldn't send SMS."
                  "Did you set your Twilio account tokens and specify a PASSWORDLESS_MOBILE_NOREPLY_NUMBER?")
    except Exception as e:
        logger.debug("Failed to send token SMS to user: {}. "
                  "Possibly no mobile number on user object or the twilio package isn't set up yet. "
                  "Number entered was {}".format(user.id, getattr(user, api_settings.PASSWORDLESS_USER_MOBILE_FIELD_NAME)))
        logger.debug(e)
        return False
