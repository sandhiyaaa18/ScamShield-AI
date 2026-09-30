from django.contrib import admin
from .models import ScamReport
# Register your models here.
class ScamReportAdmin(admin.ModelAdmin):
    list_display = (
        'title',
        'description',   
        'scam_type',
        'method',
        'impact',
        'indicators',
        'action_taken',
        'reported_by',
        'date_reported'
    )
    search_fields = ('title', 'description', 'scam_type', 'reported_by')
    list_filter = ('scam_type', 'date_reported')
admin.site.register(ScamReport, ScamReportAdmin)