from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, EmailField, PasswordField, TelField, TextAreaField
from wtforms.validators import DataRequired, URL, Email
from flask_ckeditor import CKEditorField


class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    img_url = StringField("Blog Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Blog Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    name = StringField("Name", validators=[DataRequired()])
    submit = SubmitField("Sign me up!")


class LoginForm(FlaskForm):
    email = EmailField("Email", validators=[DataRequired(), Email()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Let me in!")


class CommentForm(FlaskForm):
    comment = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField("Submit Comment")


class ContactForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()], render_kw={"placeholder": "Enter your name..."})
    email = EmailField("Email Address", validators=[DataRequired(), Email()], render_kw={"placeholder": "Enter your email..."})
    phone = TelField("Phone Number", validators=[DataRequired()], render_kw={"placeholder": "Enter your phone number..."})
    message = TextAreaField("Message", validators=[DataRequired()], render_kw={"placeholder": "Enter your message here...", "style": "height: 12rem"})
    submit = SubmitField("Send", render_kw={"class": "btn btn-primary text-uppercase"})
