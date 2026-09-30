from django.urls import path
from django.contrib.auth import views as auth_views
from . import views


urlpatterns = [

    path("chatbot/api/", views.chatbot_api, name="chatbot_api"),
    path("chatbot/", views.chatbot_page, name="chatbot_page"),

    # ============================================================
    # HOME
    # ============================================================

    path(
        '',
        views.home,
        name='home'
    ),


    # ============================================================
    # SCAM CHECKING
    # ============================================================

    path(
        'check/sms/',
        views.check_sms,
        name='check_sms'
    ),

    path(
        'check/email/',
        views.check_email,
        name='check_email'
    ),

    path(
        'check/url/',
        views.check_url,
        name='check_url'
    ),

    path(
    'api/check-url/',
    views.extension_check_url,
    name='extension_check_url'
    ),


    # ============================================================
    # SUBMIT REPORT
    # ============================================================

    path(
        'submit/',
        views.submit_report,
        name='submit_report'
    ),


    # ============================================================
    # REPORTS
    # ============================================================

    path(
        'reports/',
        views.report_list,
        name='report_list'
    ),

    path(
        'reports/<int:report_id>/',
        views.report_detail,
        name='report_detail'
    ),

    path(
        'reports/<int:report_id>/download/',
        views.download_report,
        name='download_report'
    ),


    # ============================================================
    # AUTHENTICATION
    # ============================================================

    path(
        'login/',
        views.CustomLoginView.as_view(),
        name='login'
    ),

    path(
        'logout/',
        views.logout_view,
        name='logout'
    ),

    path(
        'signup/',
        views.signup,
        name='signup'
    ),

    path(
    'verify-email/<uidb64>/<token>/',
    views.verify_email,
    name='verify_email'
    ),


    # ============================================================
    # PASSWORD RESET
    # ============================================================

    path(
        'password_reset/',
        auth_views.PasswordResetView.as_view(
            template_name='scamshield_app/password_reset.html',

            # Plain-text email version
            email_template_name='scamshield_app/password_reset_email.txt',

            # HTML email version
            html_email_template_name='scamshield_app/password_reset_email.html',

            # Email subject
            subject_template_name='scamshield_app/password_reset_subject.txt',
        ),
        name='password_reset'
    ),

    path(
        'password_reset/done/',
        auth_views.PasswordResetDoneView.as_view(
            template_name='scamshield_app/password_reset_done.html'
        ),
        name='password_reset_done'
    ),

    path(
        'reset/<uidb64>/<token>/',
        auth_views.PasswordResetConfirmView.as_view(
            template_name='scamshield_app/password_reset_confirm.html'
        ),
        name='password_reset_confirm'
    ),

    path(
        'reset/done/',
        auth_views.PasswordResetCompleteView.as_view(
            template_name='scamshield_app/password_reset_complete.html'
        ),
        name='password_reset_complete'
    ),

]