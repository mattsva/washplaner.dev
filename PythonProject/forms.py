from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField, SelectField
from wtforms.validators import DataRequired, Length, EqualTo


class LoginForm(FlaskForm):
    """Form for user login"""
    username = StringField(
        "Username",
        validators=[DataRequired(), Length(min=2, max=64)]
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=4, max=128)]
    )
    remember = BooleanField("Remember Me")
    submit = SubmitField("Login")


class RegistrationForm(FlaskForm):
    """Form for new user registration"""
    username = StringField(
        "Username",
        validators=[DataRequired(), Length(min=2, max=64)]
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(), Length(min=6, max=128)]
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[DataRequired(), EqualTo("password", message="Passwords must match.")]
    )
    house = SelectField(
        "House",
        coerce=int  # ensures selected house_id is stored as int
    )
    submit = SubmitField("Register")


class ChangePasswordForm(FlaskForm):
    """Form for changing own password"""
    old_password = PasswordField(
        "Current Password",
        validators=[DataRequired()]
    )
    new_password = PasswordField(
        "New Password",
        validators=[DataRequired(), Length(min=6, max=128)]
    )
    confirm_password = PasswordField(
        "Confirm New Password",
        validators=[DataRequired(), EqualTo("new_password", message="Passwords must match.")]
    )
    submit = SubmitField("Change Password")
