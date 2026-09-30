import os

import tempfile

from django.shortcuts import (
    render,
    redirect,
    get_object_or_404
)

from django.conf import settings

from django.http import JsonResponse

from django.views.decorators.http import require_POST

from .chatbot_engine import get_answer
from .mongodb import save_scam_log
from .mongodb import scam_logs

from django.http import HttpResponse

from django.contrib.auth import logout

from django.contrib.auth.views import LoginView

from django.contrib.auth.decorators import (
    login_required
)

from django.views.decorators.csrf import csrf_exempt

from django.contrib.auth.models import User

from django.contrib.auth.tokens import default_token_generator

from django.core.mail import send_mail

from django.db import transaction

from django.template.loader import render_to_string

from django.urls import reverse

from django.utils.encoding import force_bytes, force_str

from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode

from django.contrib.auth.urls import *

from django.urls import reverse_lazy

from reportlab.lib.pagesizes import A4

from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer
)

from reportlab.lib.styles import (
    getSampleStyleSheet
)

from .models import (
    ScamReport,
    SiteStats
)

from .forms import (
    ScamReportForm,
    UserSubmissionForm,
    SMSCheckForm,
    URLCheckForm,
    EmailCheckForm,
    CustomUserCreationForm
)




# ============================================================
# HOME PAGE
# ============================================================

def home(request):

    # --------------------------------------------------------
    # 1. Reports Submitted
    #    Stored in Django database
    # --------------------------------------------------------
    reports_count = ScamReport.objects.count()

    # --------------------------------------------------------
    # 2. Inputs Analyzed
    #    Includes website + browser extension detections
    # --------------------------------------------------------
    inputs_analyzed_count = scam_logs.count_documents({})

    # --------------------------------------------------------
    # 3. Users Protected
    #    Unique website users who have performed
    #    at least one detection.
    #
    #    Browser extension is excluded because it uses
    #    "browser_extension" as its user_id.
    # --------------------------------------------------------
    protected_user_ids = scam_logs.distinct(
        "user_id",
        {
            "user_id": {
                "$ne": "browser_extension"
            }
        }
    )

    users_protected_count = len(protected_user_ids)

    return render(
        request,
        'scamshield_app/home.html',
        {
            'reports_count': reports_count,
            'inputs_analyzed_count': inputs_analyzed_count,
            'users_protected_count': users_protected_count,
        }
    )


# ============================================================
# SMS CHECK PAGE
# ============================================================

@login_required
def check_sms(request):

    context = {
        "result": None,
        "message": "",
    }

    if request.method == "POST":

        message = request.POST.get(
            "message",
            ""
        ).strip()

        context["message"] = message

        if message:

            try:

                # ------------------------------------------------
                # Import SMS prediction model
                # ------------------------------------------------

                from ML.sms.predict import predict_sms


                # ------------------------------------------------
                # Run SMS prediction
                # ------------------------------------------------

                result = predict_sms(
                    message
                )
                print("SMS MODEL RESULT:", result)


                # ------------------------------------------------
                # Prepare MongoDB detection reasons
                # ------------------------------------------------

                detection_reasons = []


                if result.get(
                    "matched_keywords"
                ):

                    detection_reasons.append(
                        "Suspicious keywords detected"
                    )


                if result.get(
                    "matched_rules"
                ):

                    detection_reasons.append(
                        "Suspicious scam rules detected"
                    )


                if result.get(
                    "urgency_score",
                    0
                ) > 0:

                    detection_reasons.append(
                        "Urgency language detected"
                    )


                if result.get(
                    "threat_score",
                    0
                ) > 0:

                    detection_reasons.append(
                        "Threatening language detected"
                    )


                if result.get(
                    "financial_score",
                    0
                ) > 0:

                    detection_reasons.append(
                        "Financial scam indicators detected"
                    )


                if result.get(
                    "government_score",
                    0
                ) > 0:

                    detection_reasons.append(
                        "Government-related scam indicators detected"
                    )


                # ------------------------------------------------
                # If no suspicious indicators were detected
                # ------------------------------------------------

                if not detection_reasons:

                    detection_reasons.append(
                        "No major suspicious indicators detected"
                    )


                # ------------------------------------------------
                # Save SMS result to MongoDB
                # ------------------------------------------------

                try:

                    save_scam_log(

                        user_id=str(
                            request.user.id
                        ),

                        input_type="SMS",

                        input_data=message,

                        result=result.get(
                            "label",
                            "UNKNOWN"
                        ),

                        risk_score=result.get(
                            "confidence",
                            0
                        ),

                        detection_reasons=detection_reasons

                    )

                    print(
                        "SMS LOG SAVED TO MONGODB"
                    )


                except Exception as e:

                    print(
                        "MONGODB SMS LOG ERROR:",
                        repr(e)
                    )


                # ------------------------------------------------
                # Send result to template
                # ------------------------------------------------

                context["result"] = result


            except Exception as e:

                print(
                    "SMS MODEL ERROR:",
                    repr(e)
                )

                raise


    return render(

        request,

        "scamshield_app/check_sms.html",

        context

    )

# ============================================================
# EMAIL CHECK PAGE
# ============================================================

@login_required
def check_email(request):

    result = None

    form = EmailCheckForm(
        request.POST or None,
        request.FILES or None
    )

    if request.method == "POST":

        if form.is_valid():

            email_file = form.cleaned_data[
                "email_file"
            ]

            temp_path = None

            try:

                # ------------------------------------------------
                # Import Email ML model
                # ------------------------------------------------

                from ML.email_model.predict import predict_email


                # ------------------------------------------------
                # Save uploaded email temporarily
                # ------------------------------------------------

                with tempfile.NamedTemporaryFile(
                    delete=False,
                    suffix=".eml"
                ) as temp_file:

                    for chunk in email_file.chunks():

                        temp_file.write(
                            chunk
                        )

                    temp_path = temp_file.name


                # ------------------------------------------------
                # Run Email ML prediction
                # ------------------------------------------------

                model_result = predict_email(
                    temp_path
                )


                # ------------------------------------------------
                # Prepare result
                # ------------------------------------------------

                result = {

                    "type":
                        "email",

                    "label":
                        model_result.get(
                            "label",
                            "UNKNOWN"
                        ),

                    "confidence":
                        model_result.get(
                            "confidence",
                            0
                        ),

                    "risk":
                        model_result.get(
                            "risk",
                            "UNKNOWN"
                        ),

                    "filename":
                        email_file.name,

                    "message":
                        "Email analysis completed successfully."

                }


                # ------------------------------------------------
                # Prepare MongoDB detection reasons
                # ------------------------------------------------

                detection_reasons = []


                if result["label"].upper() == "SCAM":

                    detection_reasons.append(
                        "Email classified as suspicious"
                    )


                if result["risk"]:

                    detection_reasons.append(
                        f"Risk level: {result['risk']}"
                    )


                # ------------------------------------------------
                # If no specific reason was found
                # ------------------------------------------------

                if not detection_reasons:

                    detection_reasons.append(
                        "No major suspicious indicators detected"
                    )


                # ------------------------------------------------
                # Save Email result to MongoDB
                # ------------------------------------------------

                try:

                    save_scam_log(

                        user_id=str(
                            request.user.id
                        ),

                        input_type="EMAIL",

                        input_data=email_file.name,

                        result=result.get(
                            "label",
                            "UNKNOWN"
                        ),

                        risk_score=result.get(
                            "confidence",
                            0
                        ),

                        detection_reasons=detection_reasons

                    )

                    print(
                        "EMAIL LOG SAVED TO MONGODB"
                    )


                except Exception as e:

                    print(
                        "MONGODB EMAIL LOG ERROR:",
                        repr(e)
                    )


            except Exception as e:

                print(
                    "EMAIL MODEL ERROR:",
                    repr(e)
                )

                result = {

                    "type":
                        "email",

                    "label":
                        "ANALYSIS ERROR",

                    "confidence":
                        0,

                    "risk":
                        "ERROR",

                    "filename":
                        email_file.name,

                    "message":
                        str(e)

                }


            finally:

                # ------------------------------------------------
                # Delete temporary email file
                # ------------------------------------------------

                if temp_path:

                    try:

                        os.remove(
                            temp_path
                        )

                    except OSError:

                        pass


    return render(

        request,

        "scamshield_app/check_email.html",

        {

            "form":
                form,

            "result":
                result

        }

    )


# ============================================================
# URL CHECK PAGE
# ============================================================

@login_required
def check_url(request):

    result = None

    form = URLCheckForm(
        request.POST or None
    )

    if request.method == "POST":

        if form.is_valid():

            url = form.cleaned_data["url"]

            try:

                # ------------------------------------------------
                # Import the trained URL model
                # ------------------------------------------------

                from ML.url.predict import predict_url


                # ------------------------------------------------
                # Run URL ML prediction
                # ------------------------------------------------

                model_result = predict_url(url)


                # ------------------------------------------------
                # Prepare result for Django
                # ------------------------------------------------

                result = {

                    "type":
                        "url",

                    "url":
                        model_result.get(
                            "url",
                            url
                        ),

                    "label":
                        model_result.get(
                            "prediction",
                            "UNKNOWN"
                        ),

                    "confidence":
                        model_result.get(
                            "confidence",
                            0
                        ),

                    "risk":
                        model_result.get(
                            "risk",
                            "UNKNOWN"
                        ),

                    "trusted_domain":
                        model_result.get(
                            "trusted_domain",
                            False
                        ),

                    "matched_keywords":
                        model_result.get(
                            "matched_keywords",
                            []
                        ),

                    "matched_tld":
                        model_result.get(
                            "matched_tld",
                            False
                        ),

                    "message":
                        "URL analysis completed successfully."

                }


                # ------------------------------------------------
                # Prepare MongoDB detection reasons
                # ------------------------------------------------

                detection_reasons = []


                if result["matched_keywords"]:

                    detection_reasons.append(
                        "Suspicious keywords detected"
                    )


                if result["matched_tld"]:

                    detection_reasons.append(
                        "Suspicious TLD detected"
                    )


                if not result["trusted_domain"]:

                    detection_reasons.append(
                        "Domain is not recognized as trusted"
                    )


                # If no specific reason was found

                if not detection_reasons:

                    detection_reasons.append(
                        "No major suspicious indicators detected"
                    )


                # ------------------------------------------------
                # Save URL detection result to MongoDB
                # ------------------------------------------------

                try:

                    save_scam_log(

                        user_id=request.user.id,

                        input_type="URL",

                        input_data=url,

                        result=result["label"],

                        risk_score=result["confidence"],

                        detection_reasons=detection_reasons

                    )

                except Exception as e:

                    print(
                        "MONGODB URL LOG ERROR:",
                        repr(e)
                    )


            except Exception as e:

                print(
                    "URL MODEL ERROR:",
                    repr(e)
                )

                result = {

                    "type":
                        "url",

                    "url":
                        url,

                    "label":
                        "ANALYSIS ERROR",

                    "confidence":
                        0,

                    "risk":
                        "ERROR",

                    "message":
                        str(e)

                }


    return render(

        request,

        "scamshield_app/check_url.html",

        {

            "form":
                form,

            "result":
                result

        }

    )

# ============================================================
# BROWSER EXTENSION URL API
# ============================================================

@csrf_exempt
def extension_check_url(request):

    # --------------------------------------------------------
    # Only allow POST requests
    # --------------------------------------------------------

    if request.method != "POST":

        return JsonResponse(
            {
                "success": False,
                "message": "Only POST requests are allowed."
            },
            status=405
        )


    # --------------------------------------------------------
    # Read JSON request
    # --------------------------------------------------------

    try:

        import json

        data = json.loads(request.body)

        url = data.get("url", "").strip()

    except Exception:

        return JsonResponse(
            {
                "success": False,
                "message": "Invalid JSON request."
            },
            status=400
        )


    # --------------------------------------------------------
    # Validate URL
    # --------------------------------------------------------

    if not url:

        return JsonResponse(
            {
                "success": False,
                "message": "URL is required."
            },
            status=400
        )


    # --------------------------------------------------------
    # Run URL ML prediction
    # --------------------------------------------------------

    try:

        from ML.url.predict import predict_url

        model_result = predict_url(url)


        # ----------------------------------------------------
        # Prepare result
        # ----------------------------------------------------

        label = model_result.get(
            "prediction",
            "UNKNOWN"
        )

        confidence = model_result.get(
            "confidence",
            0
        )

        risk = model_result.get(
            "risk",
            "UNKNOWN"
        )

        trusted_domain = model_result.get(
            "trusted_domain",
            False
        )

        matched_keywords = model_result.get(
            "matched_keywords",
            []
        )

        matched_tld = model_result.get(
            "matched_tld",
            False
        )


        # ----------------------------------------------------
        # Detection reasons
        # ----------------------------------------------------

        detection_reasons = []


        if matched_keywords:

            detection_reasons.append(
                "Suspicious keywords detected"
            )


        if matched_tld:

            detection_reasons.append(
                "Suspicious TLD detected"
            )


        if not trusted_domain:

            detection_reasons.append(
                "Domain is not recognized as trusted"
            )


        if not detection_reasons:

            detection_reasons.append(
                "No major suspicious indicators detected"
            )


        # ----------------------------------------------------
        # Save log to MongoDB
        # ----------------------------------------------------

        try:

            # Browser extension currently has no Django
            # authenticated user.

            save_scam_log(

                user_id="browser_extension",

                input_type="URL",

                input_data=url,

                result=label,

                risk_score=confidence,

                detection_reasons=detection_reasons

            )

        except Exception as e:

            print(
                "MONGODB EXTENSION LOG ERROR:",
                repr(e)
            )


        # ----------------------------------------------------
        # Return JSON to browser extension
        # ----------------------------------------------------

        return JsonResponse(

            {
                "success": True,

                "type": "url",

                "url": model_result.get(
                    "url",
                    url
                ),

                "label": label,

                "confidence": confidence,

                "risk": risk,

                "trusted_domain": trusted_domain,

                "matched_keywords": matched_keywords,

                "matched_tld": matched_tld,

                "detection_reasons": detection_reasons,

                "message":
                    "URL analysis completed successfully."
            }

        )


    # --------------------------------------------------------
    # Handle model errors
    # --------------------------------------------------------

    except Exception as e:

        print(
            "EXTENSION URL MODEL ERROR:",
            repr(e)
        )

        return JsonResponse(

            {
                "success": False,

                "type": "url",

                "url": url,

                "label": "ANALYSIS ERROR",

                "confidence": 0,

                "risk": "ERROR",

                "message": str(e)
            },

            status=500
        )
    
# ============================================================
# SIGNUP
# ============================================================

def signup(request):

    if request.method == "POST":

        form = CustomUserCreationForm(
            request.POST
        )

        if form.is_valid():

            try:

                with transaction.atomic():

                    user = form.save(
                        commit=False
                    )

                    # Account remains inactive
                    # until email is verified
                    user.is_active = False

                    user.save()

                    # Create verification token
                    uid = urlsafe_base64_encode(
                        force_bytes(user.pk)
                    )

                    token = default_token_generator.make_token(
                        user
                    )

                    # Create verification URL
                    verification_url = (
                        settings.SITE_URL.rstrip("/")
                        + reverse(
                            'verify_email',
                            kwargs={
                                'uidb64': uid,
                                'token': token
                            }
                        )
                    )

                    # Plain text email
                    message = f"""
Hello {user.username},

Thank you for creating an account with ScamShield AI.

Please verify your email address by clicking the link below:

{verification_url}

After verification, you will be able to log in to your ScamShield AI account.

If you did not create this account, you can safely ignore this email.

Regards,
ScamShield AI
"""

                    # HTML email
                    html_message = render_to_string(
                        'scamshield_app/email_verification.html',
                        {
                            'username': user.username,
                            'verification_url': verification_url
                        }
                    )

                    send_mail(
                        subject='Verify your ScamShield AI account',
                        message=message,
                        from_email=None,
                        recipient_list=[
                            user.email
                        ],
                        html_message=html_message,
                        fail_silently=False
                    )

                return render(
                    request,
                    'scamshield_app/verification_sent.html',
                    {
                        'email': user.email
                    }
                )

            except Exception as e:

                print("SIGNUP ERROR:", e)
                raise

    else:

        form = CustomUserCreationForm()

    return render(
        request,
        'scamshield_app/signup.html',
        {
            'form': form
        }
    )

# ============================================================
# EMAIL VERIFICATION
# ============================================================

def verify_email(request, uidb64, token):

    try:

        uid = force_str(
            urlsafe_base64_decode(uidb64)
        )

        user = User.objects.get(
            pk=uid
        )

    except (
        TypeError,
        ValueError,
        OverflowError,
        User.DoesNotExist
    ):

        user = None

    if user is not None:

        if (
            not user.is_active
            and default_token_generator.check_token(
                user,
                token
            )
        ):

            user.is_active = True
            user.save(
                update_fields=[
                    'is_active'
                ]
            )

            # Update Users Protected
            stats, created = (
                SiteStats.objects.get_or_create(
                    id=1
                )
            )

            stats.users_protected += 1
            stats.save()

            return render(
                request,
                'scamshield_app/email_verified.html',
                {
                    'user': user
                }
            )

    return render(
        request,
        'scamshield_app/email_verification_failed.html'
    )

# ============================================================
# LOGIN
# ============================================================

class CustomLoginView(
    LoginView
):

    template_name = (
        'scamshield_app/login.html'
    )

    def get_success_url(self):

        return reverse_lazy(
            'home'
        )


# ============================================================
# LOGOUT
# ============================================================

def logout_view(request):

    logout(request)

    return redirect(
        'login'
    )


# ============================================================
# REPORT LIST
# ============================================================

@login_required
def report_list(request):

    reports = (
        ScamReport.objects
        .all()
        .order_by(
            '-date_reported'
        )
    )

    return render(
        request,
        'scamshield_app/report_list.html',
        {
            'reports': reports
        }
    )


# ============================================================
# REPORT DETAIL
# ============================================================

@login_required
def report_detail(
    request,
    report_id
):

    report = get_object_or_404(
        ScamReport,
        id=report_id
    )

    return render(
        request,
        'scamshield_app/report_detail.html',
        {
            'report': report
        }
    )


# ============================================================
# DOWNLOAD REPORT
# ============================================================

@login_required
def download_report(
    request,
    report_id
):

    report = get_object_or_404(
        ScamReport,
        id=report_id
    )

    response = HttpResponse(
        content_type='application/pdf'
    )

    response[
        'Content-Disposition'
    ] = (
        f'attachment; '
        f'filename=report_{report.id}.pdf'
    )

    doc = SimpleDocTemplate(
        response,
        pagesize=A4
    )

    styles = getSampleStyleSheet()

    story = []

    story.append(
        Paragraph(
            f"<b>Scam Report #{report.id}</b>",
            styles['Title']
        )
    )

    story.append(
        Spacer(
            1,
            12
        )
    )

    fields = [

        (
            "Title",
            report.title
        ),

        (
            "Description",
            report.description
        ),

        (
            "Scam Type",
            report.scam_type
        ),

        (
            "Method",
            report.method
        ),

        (
            "Impact",
            report.impact
        ),

        (
            "Indicators",
            report.indicators
        ),

        (
            "Action Taken",
            report.action_taken
        ),

        (
            "Reported By",
            str(
                report.reported_by
            )
        ),

        (
            "Date Reported",
            report.date_reported.strftime(
                '%Y-%m-%d %H:%M'
            )
        ),
    ]

    for label, value in fields:

        story.append(
            Paragraph(
                f"<b>{label}:</b> {value}",
                styles['Normal']
            )
        )

        story.append(
            Spacer(
                1,
                8
            )
        )

    doc.build(
        story
    )

    return response


# ============================================================
# SUBMIT REPORT
# ============================================================

@login_required
def submit_report(request):

    if request.method == 'POST':

        form = ScamReportForm(
            request.POST,
            request.FILES
        )

        if form.is_valid():

            report = form.save(
                commit=False
            )

            report.reported_by = (
                request.user
            )

            report.save()

            stats, created = (
                SiteStats.objects.get_or_create(
                    id=1
                )
            )

            stats.reports_submitted += 1

            stats.save()

            return redirect(
                'report_list'
            )

    else:

        form = ScamReportForm()

    return render(
        request,
        'scamshield_app/submit_report.html',
        {
            'form': form
        }
    )



@login_required
@require_POST
def chatbot_api(request):
    message = request.POST.get("message", "").strip()

    answer = get_answer(message)

    return JsonResponse({
        "success": True,
        "answer": answer,
    })

@login_required
def chatbot_page(request):
    return render(request, "scamshield_app/chatbot.html")