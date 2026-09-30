from django.db import models

# Create your models here.
class ScamReport(models.Model):
    title = models.CharField(max_length=200)
    description = models.TextField()
    scam_type = models.CharField(max_length=100, blank=True, default="")
    method = models.TextField(blank=True, default="")
    impact = models.TextField(blank=True, default="")
    indicators = models.TextField(blank=True, default="")
    action_taken = models.TextField(blank=True, default="")
    reported_by = models.CharField(max_length=100)
    date_reported = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return self.title

class UserSubmission(models.Model):
    sms = models.TextField(blank=True, null=True)
    email = models.EmailField(blank=True, null=True)
    link = models.URLField(blank=True, null=True)
    submitted_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Submission {self.id} - {self.submitted_at}"

file = models.FileField(upload_to='reports/', blank=True, null=True)

class SiteStats(models.Model):
    reports_submitted = models.PositiveIntegerField(default=0)
    scams_blocked = models.PositiveIntegerField(default=0)
    users_protected = models.PositiveIntegerField(default=0)

    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"Stats (Reports: {self.reports_submitted}, Blocked: {self.scams_blocked}, Users: {self.users_protected})"
