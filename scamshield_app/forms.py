from django import forms
from .models import ScamReport
from .models import UserSubmission
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User


# ============================================================
# SCAM REPORT FORM
# ============================================================

class ScamReportForm(forms.ModelForm):

    class Meta:

        model = ScamReport

        fields = [
            'title',
            'description',
            'scam_type',
            'method',
            'impact',
            'indicators',
            'action_taken',
            'reported_by'
        ]


# ============================================================
# USER SUBMISSION FORM
# ============================================================

class UserSubmissionForm(forms.ModelForm):

    class Meta:

        model = UserSubmission

        fields = [
            'sms',
            'email',
            'link'
        ]


# ============================================================
# SMS CHECK FORM
# ============================================================

class SMSCheckForm(forms.Form):

    sms = forms.CharField(
        label="Suspicious SMS",
        required=True,
        widget=forms.Textarea(
            attrs={
                "rows": 7,
                "placeholder": (
                    "Paste the suspicious SMS here..."
                ),
                "class": "dark-input"
            }
        )
    )


# ============================================================
# URL CHECK FORM
# ============================================================

class URLCheckForm(forms.Form):

    url = forms.CharField(
        label="Suspicious URL",
        required=True,
        widget=forms.URLInput(
            attrs={
                "placeholder": (
                    "https://example.com/..."
                ),
                "class": "dark-input"
            }
        )
    )


# ============================================================
# EMAIL CHECK FORM
# ============================================================

class EmailCheckForm(forms.Form):

    email_file = forms.FileField(
        label="Upload Email",
        required=True,
        widget=forms.ClearableFileInput(
            attrs={
                "accept": ".eml",
                "class": "dark-input"
            }
        )
    )

    def clean_email_file(self):

        file = self.cleaned_data.get(
            "email_file"
        )

        if file:

            if not file.name.lower().endswith(
                ".eml"
            ):

                raise forms.ValidationError(
                    "Please upload a valid .eml file."
                )

        return file


# ============================================================
# USER CREATION FORM
# ============================================================

class CustomUserCreationForm(
    UserCreationForm
):

    terms_agreement = forms.BooleanField(
        required=True,
        label=(
            "I agree to the Terms and Conditions of ScamShield AI."
        )
    )

    privacy_agreement = forms.BooleanField(
        required=True,
        label=(
            "I consent to ScamShield AI collecting, processing, and storing the information I submit for scam detection and prevention. My information will only be used for providing and improving the service and will not be intentionally misused or sold for unrelated purposes. I understand that I should not submit passwords, OTPs, banking details, or other highly sensitive information."
        )
    )

    class Meta:

        model = User

        fields = (
            "username",
            "email",
            "password1",
            "password2"
        )

    def __init__(
        self,
        *args,
        **kwargs
    ):

        super().__init__(
            *args,
            **kwargs
        )

        self.fields[
            'username'
        ].help_text = ""

        self.fields[
            'email'
        ].help_text = ""

        self.fields[
            'password1'
        ].help_text = ""

        self.fields[
            'password2'
        ].help_text = ""

        # Make email required
        self.fields[
            'email'
        ].required = True

    def clean_email(self):

        email = self.cleaned_data.get(
            'email'
        )

        if email:

            if User.objects.filter(
                email__iexact=email
            ).exists():

                raise forms.ValidationError(
                    "An account with this email address already exists."
                )

        return email