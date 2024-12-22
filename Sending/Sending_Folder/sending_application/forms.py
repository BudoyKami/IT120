from django import forms
from django.core.exceptions import ValidationError
from django.core.validators import RegexValidator
from django.contrib.auth.password_validation import validate_password

class RegistrationForm(forms.Form):
    username = forms.CharField(
        max_length=25,
        required=True,
        label="Username",
        help_text="Username must be 25 characters or fewer.",
        validators=[
            RegexValidator(
                regex=r'^[a-zA-Z0-9_]*$',
                message="Username can only contain letters, numbers, and underscores."
            )
        ],
        widget=forms.TextInput(attrs={
            'placeholder': 'Enter your username',
            'title': 'Choose a unique username (max 25 characters).'
        })
    )
    password1 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'placeholder': 'Enter your password',
            'title': 'Password must be at least 8 characters long and include uppercase letters, numbers, and special characters.'
        }),
        label="Password",
        required=True
    )
    password2 = forms.CharField(
        widget=forms.PasswordInput(attrs={
            'placeholder': 'Confirm your password',
            'title': 'Re-enter the same password for confirmation.'
        }),
        label="Confirm Password",
        required=True
    )

    def clean_username(self):
        username = self.cleaned_data.get("username")
        if len(username) > 25:
            raise ValidationError("Username must be 25 characters or fewer.")
        return username
    
    def clean_password1(self):
        password1 = self.cleaned_data.get("password1")
        validate_password(password1) 
        return password1

    def clean(self):
        cleaned_data = super().clean()
        password1 = cleaned_data.get("password1")
        password2 = cleaned_data.get("password2")

        if password1 and password2 and password1 != password2:
            self.add_error("password2", "Passwords do not match.")
        return cleaned_data
