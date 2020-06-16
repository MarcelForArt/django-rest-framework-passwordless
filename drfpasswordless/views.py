import logging
from allauth.account.utils import perform_login
from django.conf import settings
from rest_framework import parsers, renderers, status
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated 
from rest_framework.views import APIView
from rest_framework.exceptions import ValidationError
from django.shortcuts import render

from drfpasswordless.settings import api_settings
from drfpasswordless.serializers import (
    EmailAuthSerializer,
    MobileAuthSerializer,
    CallbackTokenAuthSerializer,
    CallbackTokenVerificationSerializer,
    EmailVerificationSerializer,
    MobileVerificationSerializer,
)
from drfpasswordless.services import TokenService

logger = logging.getLogger(__name__)


class AbstractBaseObtainCallbackToken(APIView):
    """
    This returns a 6-digit callback token we can trade for a user's Auth Token.
    """
    # Differing from original: demand auth users
    permission_classes = (IsAuthenticated,)

    success_response = "A login token has been sent to you."
    failure_response = "Unable to send you a login code. Try again later."

    message_payload = {}

    @property
    def serializer_class(self):
        # Our serializer depending on type
        raise NotImplementedError

    @property
    def alias_type(self):
        # Alias Type
        raise NotImplementedError

    def post(self, request, *args, **kwargs):
        if self.alias_type.upper() not in api_settings.PASSWORDLESS_AUTH_TYPES:
            # Only allow auth types allowed in settings.
            return Response(status=status.HTTP_404_NOT_FOUND)

        serializer = self.serializer_class(data=request.data, context={'request': request})
        if serializer.is_valid(raise_exception=True):
            # Validate -
            user = serializer.validated_data['user']
            template_name = None
            if api_settings.PASSWORDLESS_TEMPLATE_CHOICES:
                # Differing from original lib: we allow optional template and pass this to send_token
                template_idx = serializer.validated_data.get('template')  # default 1
                template_name = [choice for choice in api_settings.PASSWORDLESS_TEMPLATE_CHOICES if choice[0]
                                 == template_idx][0][1]
            # Create and send callback token
            success = TokenService.send_token(user, self.alias_type, template=template_name, **self.message_payload)

            # Respond With Success Or Failure of Sent
            if success:
                status_code = status.HTTP_200_OK
                response_detail = self.success_response
            else:
                status_code = status.HTTP_400_BAD_REQUEST
                response_detail = self.failure_response
            return Response({'detail': response_detail}, status=status_code)
        else:
            return Response(serializer.error_messages, status=status.HTTP_400_BAD_REQUEST)


class ObtainEmailCallbackToken(AbstractBaseObtainCallbackToken):
    # We only allow authenticated users to request magic link
    serializer_class = EmailAuthSerializer
    success_response = "A login token has been sent to your email."
    failure_response = "Unable to email you a login code. Try again later."

    alias_type = 'email'

    email_subject = api_settings.PASSWORDLESS_EMAIL_SUBJECT
    email_plaintext = api_settings.PASSWORDLESS_EMAIL_PLAINTEXT_MESSAGE
    email_html = api_settings.PASSWORDLESS_EMAIL_TOKEN_HTML_TEMPLATE_NAME
    message_payload = {'email_subject': email_subject,
                       'email_plaintext': email_plaintext,
                       'email_html': email_html}


class ObtainMobileCallbackToken(AbstractBaseObtainCallbackToken):
    serializer_class = MobileAuthSerializer
    success_response = "We texted you a login code."
    failure_response = "Unable to send you a login code. Try again later."

    alias_type = 'mobile'

    mobile_message = api_settings.PASSWORDLESS_MOBILE_MESSAGE
    message_payload = {'mobile_message': mobile_message}


class ObtainEmailVerificationCallbackToken(AbstractBaseObtainCallbackToken):
    permission_classes = (IsAuthenticated,)
    serializer_class = EmailVerificationSerializer
    success_response = "A verification token has been sent to your email."
    failure_response = "Unable to email you a verification code. Try again later."

    alias_type = 'email'

    email_subject = api_settings.PASSWORDLESS_EMAIL_VERIFICATION_SUBJECT
    email_plaintext = api_settings.PASSWORDLESS_EMAIL_VERIFICATION_PLAINTEXT_MESSAGE
    email_html = api_settings.PASSWORDLESS_EMAIL_VERIFICATION_TOKEN_HTML_TEMPLATE_NAME
    message_payload = {
        'email_subject': email_subject,
        'email_plaintext': email_plaintext,
        'email_html': email_html
    }


class ObtainMobileVerificationCallbackToken(AbstractBaseObtainCallbackToken):
    permission_classes = (IsAuthenticated,)
    serializer_class = MobileVerificationSerializer
    success_response = "We texted you a verification code."
    failure_response = "Unable to send you a verification code. Try again later."

    alias_type = 'mobile'

    mobile_message = api_settings.PASSWORDLESS_MOBILE_MESSAGE
    message_payload = {'mobile_message': mobile_message}


class AbstractBaseObtainAuthToken(APIView):
    """
    This is a duplicate of rest_framework's own ObtainAuthToken method.
    Instead, this returns an Auth Token based on our 6 digit callback token and source.
    """
    serializer_class = None

    def _process_request(self, data):
        serializer = self.serializer_class(data=data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.validated_data['user']
            token = Token.objects.get_or_create(user=user)[0]

            if token:
                return token, user
        else:
            logger.error("Couldn't log in unknown user. Errors on serializer: {}".format(serializer.error_messages))
        return None

    def get(self, request, *args, **kwargs):
        redirect_url = request.query_params.get('redirect_url')
        token = request.query_params.get('token')
        if token is None:
            return Response({'detail': 'Missing token.'}, status=status.HTTP_400_BAD_REQUEST)

        data = {'token': token}

        try:
            token, user = self._process_request(data)
        except ValidationError as exc:
            msg = 'Unknown error. Contact an admin.'
            if 'token' in exc.detail:
                msg = str(exc.detail['token'][0])
            else:
                # If it's not the standard token invalid error log as error to see on sentry etc
                logger.error(exc)

            return render(request, 'token_error.html', {'error_message': msg})

        # Get an authenticated web session and do a redirect
        ret = perform_login(request, user, email_verification=settings.ACCOUNT_EMAIL_VERIFICATION,
                            redirect_url=redirect_url)
        request.session.set_expiry(settings.SESSION_COOKIE_AGE)
        return ret

    def post(self, request, *args, **kwargs):
        token, user = self._process_request(request.data)
        if token:
            # Return our key for consumption.
            return Response({'token': token.key}, status=status.HTTP_200_OK)

        return Response({'detail': 'Couldn\'t log you in. Try again later.'}, status=status.HTTP_400_BAD_REQUEST)


class ObtainAuthTokenFromCallbackToken(AbstractBaseObtainAuthToken):
    """
    This is a duplicate of rest_framework's own ObtainAuthToken method.
    Instead, this returns an Auth Token based on our callback token and source.
    """
    permission_classes = (AllowAny,)
    serializer_class = CallbackTokenAuthSerializer


class VerifyAliasFromCallbackToken(APIView):
    """
    This verifies an alias on correct callback token entry using the same logic as auth.
    Should be refactored at some point.
    """
    serializer_class = CallbackTokenVerificationSerializer

    def post(self, request, *args, **kwargs):
        serializer = self.serializer_class(data=request.data, context={'user_id': self.request.user.id})
        if serializer.is_valid(raise_exception=True):
            return Response({'detail': 'Alias verified.'}, status=status.HTTP_200_OK)
        else:
            logger.error("Couldn't verify unknown user. Errors on serializer: {}".format(serializer.error_messages))

        return Response({'detail': 'We couldn\'t verify this alias. Try again later.'}, status.HTTP_400_BAD_REQUEST)
